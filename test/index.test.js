import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {generateKeyPairSync} from 'node:crypto';
import {Resolver} from 'node:dns/promises';
import {writeFileSync} from 'node:fs';
import net from 'node:net';
import {once} from 'node:events';
import path from 'node:path';
import {Readable} from 'node:stream';
import {describe, it} from 'node:test';
import {dkimSign} from 'mailauth/lib/dkim/sign.js';
import SpamScanner, {
	Classifier, DEFAULTS, VERSION, getFeatures, loadModel,
} from '../src/index.js';
import {GTUBE} from '../src/is-arbitrary.js';
import {expandAttachments, parseMessage, parseWithin} from '../src/parse.js';
import {
	HAM, SPAM, dnsServer, eicar, fakeClamd, httpServer, message, temporaryDirectory, zip,
} from './helpers/index.js';
import {cpuTime} from './helpers/cpu-time.js';

const offline = {phishing: {cloudflare: false}};
const names = result => result.tests.map(test => test.name);

describe('SpamScanner with the bundled model', () => {
	it('passes ordinary mail in many languages and catches spam in many languages', async () => {
		const scanner = new SpamScanner(offline);
		const missed = [];
		const flagged = [];
		for (const [language, subject, text] of SPAM) {
			const result = await scanner.scan(message({subject, text}));
			if (result.results.classification.probability < 0.5) {
				missed.push(language);
			}
		}

		for (const [language, subject, text] of HAM) {
			const result = await scanner.scan(message({subject, text}));
			if (result.isSpam) {
				flagged.push(language);
			}
		}

		assert.deepEqual(flagged, [], 'no ham is spam');
		// The bundled model learned mostly English, Russian, German, Italian and
		// Spanish; other languages rely on training and the language model.
		assert.ok(missed.length <= 6, `missed ${missed.join(', ')}`);
		assert.equal(scanner.metrics.totalScans, SPAM.length + HAM.length);
	});

	it('explains a phishing message with several independent signals', async () => {
		const scanner = new SpamScanner(offline);
		const raw = message({
			from: '"PayPal Security" <service@paypa1-secure.top>',
			subject: 'Your account has been limited',
			html: '<p>Dear customer, we noticed unusual activity. Verify your account within 24 hours or it will be suspended.</p><a href="http://paypa1-secure.top/login">https://www.paypal.com/signin</a>',
		});
		const result = await scanner.scan(raw);
		assert.equal(result.isSpam, true);
		assert.equal(result.action, 'reject');
		for (const test of ['PHISHING_LOOKALIKE_DOMAIN', 'DECEPTIVE_LINK', 'FROM_NAME_BRAND']) {
			assert.ok(names(result).includes(test), test);
		}

		assert.match(result.message, /^Spam \(/);
		assert.equal(result.results.idnHomographAttack.detected, true);
		assert.equal(result.results.idnHomographAttack.domains[0].brand, 'paypal');
		assert.ok(result.links.includes('http://paypa1-secure.top/login'));
		assert.equal(result.language, 'en');
		assert.equal(result.version, VERSION);
		assert.ok(result.metrics.totalTime >= 0);
		assert.equal(String(result.results.phishing.find(item => item.type === 'deceptive_link')), 'A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top');
	});
});

describe('SpamScanner detectors', () => {
	function small() {
		const classifier = new Classifier();
		for (const [, subject, text] of SPAM) {
			classifier.learn(getFeatures({subject, text}).features, 'spam');
		}

		for (const [, subject, text] of HAM) {
			classifier.learn(getFeatures({subject, text}).features, 'ham');
		}

		return classifier;
	}

	it('uses a classifier object, a model object, a model file, or none', async () => {
		const classifier = small();
		const file = path.join(temporaryDirectory(), 'model.json');
		writeFileSync(file, JSON.stringify(classifier.toJSON()));
		const raw = message({subject: SPAM[0][1], text: SPAM[0][2]});
		for (const setting of [classifier, classifier.toJSON(), file]) {
			const result = await new SpamScanner({...offline, classifier: setting}).scan(raw);
			assert.equal(result.results.classification.category, 'spam');
		}

		const off = await new SpamScanner({...offline, classifier: false}).scan(raw);
		assert.equal(off.results.classification.category, 'disabled');
		assert.ok(!names(off).some(name => name.startsWith('BAYES')));
	});

	it('learns, unlearns and saves what it learned', async () => {
		const file = path.join(temporaryDirectory(), 'learned.json');
		const scanner = new SpamScanner({...offline, classifier: false});
		const spam = message({subject: 'Zorblax offer', text: 'zorblax quantum gizmo discount zorblax'});
		await scanner.learn(spam, 'spam');
		await scanner.learn(message({subject: 'Minutes', text: 'meeting minutes attached for review'}), 'ham');
		assert.equal(scanner.getClassifier().nspam, 1);
		await scanner.unlearn(spam, 'spam');
		assert.equal(scanner.getClassifier().nspam, 0);
		await scanner.learn(spam, 'spam');
		scanner.saveModel(file);
		assert.equal(loadModel(file).nspam, 1);
		await new SpamScanner({...offline, classifier: false}).unlearn(spam, 'spam');
		new SpamScanner({...offline, classifier: false}).saveModel(path.join(temporaryDirectory(), 'empty.json'));
		const fresh = new SpamScanner({...offline, classifier: small()});
		await fresh.learn(spam, 'ham');
		assert.equal(fresh.getClassifier().nham, HAM.length + 1);
	});

	it('accepts buffers, strings, typed arrays and streams, and scans files', async () => {
		const scanner = new SpamScanner({...offline, classifier: small()});
		const raw = message({subject: 'Lunch', text: 'See you at noon'});
		const results = await Promise.all([raw, Buffer.from(raw), new Uint8Array(Buffer.from(raw)), Readable.from([Buffer.from(raw.slice(0, 20)), raw.slice(20)])].map(source => scanner.scan(source)));
		assert.ok(results.every(result => result.mail.subject === 'Lunch'));
		const file = path.join(temporaryDirectory(), 'mail.eml');
		writeFileSync(file, raw);
		assert.equal((await scanner.scanFile(file)).mail.subject, 'Lunch');
		await assert.rejects(scanner.scan(42), /must be a Buffer/);
		// A file path given as a string is message text, never read from disk.
		assert.equal((await scanner.scan(file)).mail.subject, undefined);
	});

	it('keeps the tokens and parsing helpers of earlier versions', async () => {
		const scanner = new SpamScanner(offline);
		const {tokens, features, mail} = await scanner.getTokensAndMailFromSource(message({subject: 'Hi', text: 'Привет мир'}));
		assert.deepEqual(tokens, ['привет', 'мир']);
		assert.ok(features.includes('s:hi'));
		assert.equal(mail.subject, 'Hi');
		assert.deepEqual(scanner.getTokens('Hello, World', 'en'), ['hello', 'world']);
	});

	it('checks attachments, macros and archives', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const raw = message({
			subject: 'Invoice',
			text: 'See attached',
			attachments: [
				{filename: 'invoice.pdf.exe', content: Buffer.concat([Buffer.from('MZ'), Buffer.alloc(64)])},
				{filename: 'report.docm', content: zip([{name: 'word/vbaProject.bin', content: 'x'}])},
				{filename: 'files.zip', content: zip([{name: 'run.scr', content: 'x'}])},
			],
		});
		const result = await scanner.scan(raw);
		assert.deepEqual(result.results.executables.map(item => item.type).sort(), ['double_extension', 'executable', 'executable_in_archive']);
		assert.deepEqual(result.results.macros.map(item => item.type), ['macro']);
		assert.equal(result.action, 'reject');
		const noMacros = await new SpamScanner({...offline, classifier: false, enableMacroDetection: false}).scan(raw);
		assert.deepEqual(noMacros.results.macros, []);
		const none = await new SpamScanner({...offline, classifier: false, attachments: false}).scan(raw);
		assert.deepEqual(none.results.attachments, []);
	});

	it('scans attachments with clamd', async () => {
		const clamd = await fakeClamd();
		try {
			const raw = message({text: 'file', attachments: [{filename: 'test.txt', content: eicar()}, {filename: 'clean.txt', content: 'hello'}]});
			const result = await new SpamScanner({...offline, classifier: false, clamav: {port: clamd.port}}).scan(raw);
			assert.equal(result.results.viruses.length, 1);
			assert.equal(result.results.viruses[0].filename, 'test.txt');
			assert.ok(names(result).includes('VIRUS'));
			const legacy = await new SpamScanner({...offline, classifier: false, clamscan: {clamdscan: {host: '127.0.0.1', port: clamd.port}}}).scan(raw);
			assert.equal(legacy.results.viruses.length, 1);
			const top = await new SpamScanner({...offline, classifier: false, clamscan: {host: '127.0.0.1', port: clamd.port}}).scan(raw);
			assert.equal(top.results.viruses.length, 1);
			const unnamed = await new SpamScanner({...offline, classifier: false, clamav: {port: clamd.port}}).scan(message({text: 'x', attachments: [{filename: '', content: eicar()}]}));
			assert.match(unnamed.results.viruses[0].message, /unnamed attachment/);
		} finally {
			await clamd.close();
		}

		const down = await new SpamScanner({...offline, classifier: false, clamav: {port: 1}}).scan(message({text: 'x', attachments: [{filename: 'a.txt', content: 'x'}]}));
		assert.deepEqual(down.results.viruses, []);
		const defaults = await new SpamScanner({...offline, classifier: false, clamscan: true}).scan(message({text: 'x'}));
		assert.deepEqual(defaults.results.viruses, []);
	});

	it('runs the arbitrary rules, and reports only decisive ones in results.arbitrary', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const gtube = await scanner.scan(message({text: GTUBE}));
		assert.deepEqual(gtube.results.arbitrary.map(rule => rule.name), ['GTUBE']);
		assert.equal(String(gtube.results.arbitrary[0]), 'Contains the GTUBE spam test string');
		const minor = await scanner.scan(message({text: 'x', date: false}));
		assert.ok(names(minor).includes('MISSING_DATE'));
		assert.deepEqual(minor.results.arbitrary, []);
		const off = await new SpamScanner({...offline, classifier: false, enableArbitraryDetection: false}).scan(message({text: GTUBE}));
		assert.deepEqual(off.results.arbitrary, []);
	});

	it('scores obfuscation and unaccepted languages', async () => {
		const scanner = new SpamScanner({
			...offline, classifier: false, allowedLanguages: ['EN', 'de'],
		});
		const result = await scanner.scan(message({subject: 'Поздравляем', text: 'Поздравляем! Вы выигр\u{200B}али милл\u{200B}ион дол\u{200B}ларов. Нажмите здесь прямо сейчас, pаypаl аccount'}));
		for (const test of ['LANGUAGE_NOT_ALLOWED', 'INVISIBLE_CHARACTERS', 'MIXED_SCRIPT_WORDS']) {
			assert.ok(names(result).includes(test), test);
		}

		const english = await scanner.scan(message({subject: 'Hello', text: 'Hello Bob, how was your weekend at the lake with the family?'}));
		assert.equal(english.results.language.notAllowed, false);
		// (by any code for the language)
		for (const allowedLanguages of [['en-US'], ['eng'], ['ENG', 'deu']]) {
			const coded = await scanner.scan(message({subject: 'Hello', text: 'Hello Bob, how was your weekend at the lake with the family?'}), {allowedLanguages});
			assert.equal(coded.results.language.notAllowed, false, allowedLanguages.join(','));
		}

		const any = await scanner.scan(message({subject: 'Поздравляем', text: 'Поздравляем с днём рождения, желаем счастья!'}), {allowedLanguages: null});
		assert.equal(any.results.language.notAllowed, false);
	});

	it('checks links against Cloudflare\'s resolvers and a domain blocklist, and the client against an IP blocklist', async () => {
		const dns = await dnsServer({
			'malware.example A': ['0.0.0.0'],
			'adult.example A': ['0.0.0.0'],
			'listed.example.dbl.example A': ['127.0.1.2'],
			'1.2.0.192.zen.example A': ['127.0.0.2'],
		});
		const malwareOnly = await dnsServer({'malware.example A': ['0.0.0.0']});
		try {
			const scanner = new SpamScanner({
				classifier: false,
				dns: {servers: [dns.server], timeout: 500},
				dnsbl: {ip: ['zen.example'], domain: ['dbl.example']},
			});
			// Point the filtering resolvers at the test server.
			const original = scanner.dns.checkCloudflare.bind(scanner.dns);
			scanner.dns.checkCloudflare = (hosts, options) => original(hosts, {...options, malwareServers: [malwareOnly.server], familyServers: [dns.server]});
			const raw = message({text: 'Links: https://malware.example/a https://adult.example/b https://listed.example/c https://fine.example/d'});
			const result = await scanner.scan(raw, {session: {remoteAddress: '192.0.2.1'}});
			assert.deepEqual(result.results.phishing.map(item => item.type).sort(), ['adult_domain', 'malicious_domain', 'uribl']);
			assert.match(result.results.phishing.find(item => item.type === 'adult_domain').message, /adult-related content/);
			assert.deepEqual(result.results.dnsbl.map(item => item.zone), ['zen.example']);
			for (const test of ['MALICIOUS_DOMAIN', 'ADULT_DOMAIN', 'URIBL_DBL', 'RBL_ZEN']) {
				assert.ok(names(result).includes(test), test);
			}

			const noAdult = await scanner.scan(raw, {phishing: {adult: false}});
			assert.ok(!noAdult.results.phishing.some(item => item.type === 'adult_domain'));
			// (hosts beyond phishing.maxHosts are not looked up, and counted)
			assert.equal(result.results.uncheckedHosts, 0);
			const few = await scanner.scan(raw, {phishing: {maxHosts: 1}});
			assert.equal(few.results.uncheckedHosts, 3);
			assert.deepEqual(few.results.phishing.map(item => item.type), ['malicious_domain']);
		} finally {
			await dns.close();
			await malwareOnly.close();
		}
	});

	it('checks host names written without a link and email address domains for lookalikes only', async () => {
		const dns = await dnsServer({'bare-malware.com A': ['0.0.0.0'], 'mail-malware.net A': ['0.0.0.0'], 'link-malware.com A': ['0.0.0.0']});
		const empty = await dnsServer({});
		try {
			const scanner = new SpamScanner({classifier: false, dns: {servers: [dns.server], timeout: 500}});
			const original = scanner.dns.checkCloudflare.bind(scanner.dns);
			const asked = [];
			scanner.dns.checkCloudflare = (hosts, options) => {
				asked.push(...hosts);
				return original(hosts, {...options, malwareServers: [dns.server], familyServers: [empty.server]});
			};

			const result = await scanner.scan(message({text: 'Sign in at paypa1-secure.com today, see bare-malware.com, write to help@mail-malware.net, or https://link-malware.com/x'}));
			const lookalike = result.results.phishing.find(item => item.type === 'homograph');
			assert.equal(lookalike.domain, 'paypa1-secure.com');
			assert.equal(lookalike.source, 'text');
			assert.equal(lookalike.url, undefined);
			// (a quoted reply or a signature may name any site: only links are looked up)
			assert.deepEqual(asked, ['link-malware.com']);
			assert.deepEqual(result.results.phishing.filter(item => item.type === 'malicious_domain').map(item => item.domain), ['link-malware.com']);
		} finally {
			await dns.close();
			await empty.close();
		}
	});

	it('checks at most 1000 hosts of a message for lookalikes, links first, and links that show an address before them', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const homograph = result => result.results.phishing.some(item => item.type === 'homograph');
		const links = count => Array.from({length: count}, (_, i) => `https://site${i}.example/`).join(' ');
		assert.ok(!homograph(await scanner.scan(message({text: `${links(1000)} https://paypa1.com/login`}))));
		assert.ok(homograph(await scanner.scan(message({text: `https://paypa1.com/login ${links(1000)}`}))));
		assert.ok(homograph(await scanner.scan(message({html: `<p>${links(1000)}</p><a href="https://paypa1.com/login">https://www.paypal.com/</a>`}))));
		// (600 links and hosts in the text before it: still checked)
		const text = Array.from({length: 50}, (_, i) => `host${i}.example`).join(' ');
		assert.ok(homograph(await scanner.scan(message({text: `${text} ${links(600)} https://paypa1.com/login`}))));
	});

	it('counts hosts only named in the text when they are plainly imitations', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const homographs = async text => (await scanner.scan(message({text}))).results.phishing.filter(item => item.type === 'homograph').map(item => item.domain);
		// (a brand inside another name, or one letter away: as a link only)
		assert.deepEqual(await homographs('See paypal-help.com, rakutem.com, rnicrosoft.com and arnazon-help.com'), ['rnicrosoft.com', 'arnazon-help.com']);
		assert.deepEqual(await homographs('See https://paypal-help.example/'), ['paypal-help.example']);
		// (or a short brand one letter away: a company may be named so)
		assert.deepEqual(await homographs('See wlse.com, lrs.com and xn--pypal-4ve.com'), ['xn--pypal-4ve.com']);
		assert.deepEqual(await homographs('See https://wlse.com/'), ['wlse.com']);
	});

	it('scores SPF, DKIM, DMARC and ARC results the server already has', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const raw = message({from: 'billing@sender.example', subject: 'Invoice', text: 'Please see the invoice.'});
		// (as mailauth gives them: an unsigned message has one DKIM result "none")
		const failed = {
			spf: {status: {result: 'permerror'}}, dkim: {results: [{status: {result: 'none'}}]}, dmarc: {status: {result: 'fail'}, domain: 'sender.example'}, arc: {status: {result: 'none'}},
		};
		const result = await scanner.scan(raw, {authenticationResults: failed});
		assert.ok(names(result).includes('DMARC_FAIL'));
		assert.equal(result.results.authentication.score.score, 3.5);
		// (the caller's object is not changed)
		assert.equal(failed.score, undefined);

		const passed = await scanner.scan(raw, {
			authenticationResults: {
				spf: {status: {result: 'pass'}, domain: 'sender.example'}, dkim: {results: [{status: {result: 'pass', aligned: 'sender.example'}, signingDomain: 'sender.example'}]}, dmarc: {status: {result: 'pass'}}, arc: {status: {result: 'none'}},
			},
		});
		assert.deepEqual(passed.results.authentication.score.tests.map(test => test.name).sort(), ['DKIM_PASS', 'DMARC_PASS', 'SPF_PASS']);
		assert.ok(passed.score < result.score);
	});

	it('allowlists a subdomain sender signed by its organizational domain, as mailauth checks it', async () => {
		const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
		const dns = await dnsServer({
			's1._domainkey.bank.example TXT': [`v=DKIM1; k=rsa; p=${publicKey.export({type: 'spki', format: 'der'}).toString('base64')}`],
			'_dmarc.bank.example TXT': ['v=DMARC1; p=reject'],
		});
		try {
			const raw = message({from: 'alerts@notify.bank.example', subject: 'Statement', text: 'Your statement is ready.'});
			const signed = (await dkimSign(raw, {signatureData: [{signingDomain: 'bank.example', selector: 's1', privateKey: privateKey.export({type: 'pkcs1', format: 'pem'})}]})).signatures + raw;
			const scanner = new SpamScanner({
				...offline, classifier: false, allowlist: ['notify.bank.example'], authentication: {dnsServers: [dns.server], timeout: 2000},
			});
			const result = await scanner.scan(signed, {session: {remoteAddress: '203.0.113.9', helo: 'mx.bank.example', envelope: {mailFrom: {address: 'bounce@other.example'}}}});
			assert.equal(result.results.authentication.dmarc.domain, 'bank.example');
			assert.ok(names(result).includes('ALLOWLISTED'));
		} finally {
			await dns.close();
		}
	});

	it('does not trust a signature of a domain that is not a hostname, as mailauth checks it', async () => {
		const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
		const signer = 'bank.example/x.attacker.example';
		const dns = await dnsServer({
			[`s1._domainkey.${signer} TXT`]: [`v=DKIM1; k=rsa; p=${publicKey.export({type: 'spki', format: 'der'}).toString('base64')}`],
			'_dmarc.bank.example TXT': ['v=DMARC1; p=reject'],
		});
		try {
			const raw = message({from: 'CEO <ceo@bank.example>', subject: 'Wire', text: 'Please wire the money today.'});
			const signed = (await dkimSign(raw, {signatureData: [{signingDomain: signer, selector: 's1', privateKey: privateKey.export({type: 'pkcs1', format: 'pem'})}]})).signatures + raw;
			const scanner = new SpamScanner({
				...offline, classifier: false, allowlist: ['bank.example'], authentication: {dnsServers: [dns.server], timeout: 2000},
			});
			const result = await scanner.scan(signed, {session: {remoteAddress: '203.0.113.9', helo: 'mx.attacker.example', envelope: {mailFrom: {address: 'bounce@attacker.example'}}}});
			// (mailauth reads "bank.example" from it, and passes DMARC)
			assert.equal(result.results.authentication.dkim.aligned, null);
			assert.equal(result.results.authentication.dmarc.status.result, 'fail');
			assert.ok(!names(result).includes('ALLOWLISTED'));
			assert.ok(names(result).includes('DMARC_FAIL'));
		} finally {
			await dns.close();
		}
	});

	it('checks authentication, and flags spoofing of the recipient\'s own domain', async () => {
		const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
		const dns = await dnsServer({
			'example.org TXT': ['v=spf1 ip4:192.0.2.10 -all'],
			's1._domainkey.example.org TXT': [`v=DKIM1; k=rsa; p=${publicKey.export({type: 'spki', format: 'der'}).toString('base64')}`],
			'_dmarc.example.org TXT': ['v=DMARC1; p=reject'],
		});
		try {
			const raw = message({
				from: 'alice@example.org', to: 'bob@example.org', subject: 'Report', text: 'The quarterly report is attached.',
			});
			const signed = (await dkimSign(raw, {signatureData: [{signingDomain: 'example.org', selector: 's1', privateKey: privateKey.export({type: 'pkcs1', format: 'pem'})}]})).signatures + raw;
			const scanner = new SpamScanner({
				...offline, classifier: false, authentication: {dnsServers: [dns.server], timeout: 2000, weights: {dmarcPass: -3}},
			});
			const good = await scanner.scan(signed, {session: {remoteAddress: '192.0.2.10', envelope: {mailFrom: {address: 'alice@example.org'}, rcptTo: [{address: 'bob@example.org'}]}}});
			assert.ok(names(good).includes('DMARC_PASS'));
			assert.equal(good.tests.find(test => test.name === 'DMARC_PASS').score, -3);
			const spoofed = await scanner.scan(raw, {session: {remoteAddress: '203.0.113.5', helo: 'evil.example', envelope: {mailFrom: {address: 'alice@example.org'}, rcptTo: [{address: 'bob@example.org'}]}}});
			for (const test of ['DMARC_FAIL', 'SELF_SPOOF']) {
				assert.ok(names(spoofed).includes(test), test);
			}

			assert.equal(spoofed.results.authentication.spf.status.result, 'fail');

			// Options of earlier versions: enableAuthentication with authOptions.
			const legacy = new SpamScanner({
				...offline, classifier: false, enableAuthentication: true, authOptions: {
					ip: '203.0.113.5', helo: 'evil.example', sender: 'alice@example.org', hostname: 'evil.example',
				},
			});
			legacy.config.authentication = {dnsServers: [dns.server]};
			const legacyResult = await legacy.scan(raw);
			assert.equal(legacyResult.results.authentication.spf.status.result, 'fail');
			assert.ok(names(legacyResult).includes('DMARC_FAIL'));
			assert.equal(legacy.config.session.resolvedClientHostname, 'evil.example');
			// (and a scan's own client replaces theirs: SPF is checked for the
			//  client that sent the message, and allowlists only it)
			const relay = new SpamScanner({
				...offline, classifier: false, allowlist: ['example.org'], enableAuthentication: true, authOptions: {
					ip: '192.0.2.10', sender: 'alice@example.org', dnsServers: [dns.server],
				},
			});
			assert.deepEqual(relay.config.authentication, {dnsServers: [dns.server]});
			const otherSession = {session: {remoteAddress: '203.0.113.5', helo: 'evil.example', envelope: {mailFrom: {address: 'alice@example.org'}, rcptTo: []}}};
			const other = await relay.scan(raw, otherSession);
			assert.equal(other.results.authentication.spf.status.result, 'fail');
			assert.ok(!names(other).includes('ALLOWLISTED'));
			const named = await scanner.scan(raw, {...otherSession, authentication: {dnsServers: [dns.server], ip: '192.0.2.10'}});
			assert.equal(named.results.authentication.spf.status.result, 'fail');
			const plain = await new SpamScanner({...offline, classifier: false, authentication: true}).scan(raw);
			assert.equal(plain.results.authentication, null);
			// Authentication: true uses a resolver with the system's servers (here
			// sent to the test server, so the test never asks real DNS).
			const {resolve} = Resolver.prototype;
			let system;
			Resolver.prototype.resolve = function (...query) {
				this.setServers([dns.server]);
				return resolve.apply(this, query);
			};

			try {
				dns.queries.length = 0;
				system = await new SpamScanner({
					...offline, classifier: false, authentication: true, timeout: 300,
				}).scan(raw, {session: {remoteAddress: '203.0.113.5'}});
			} finally {
				Resolver.prototype.resolve = resolve;
			}

			assert.equal(typeof system.results.authentication.score.score, 'number');
			assert.ok(dns.queries.includes('_dmarc.example.org TXT'));
			assert.deepEqual(new SpamScanner({authOptions: {}}).config.session, {});
			// The language model is told the authentication results.
			const prompts = [];
			const llm = await httpServer((request, body) => {
				prompts.push(body);
				return {message: {content: '{"verdict":"spam","confidence":0.9,"reasons":["spoofed"]}'}};
			});
			try {
				const asked = await scanner.scan(raw, {llm: {provider: 'ollama', baseUrl: llm.url, model: 'test'}, session: {remoteAddress: '203.0.113.5', envelope: {mailFrom: {address: 'alice@example.org'}, rcptTo: [{address: 'bob@example.org'}]}}});
				assert.equal(asked.results.llm.verdict, 'spam');
				assert.match(JSON.stringify(prompts[0]), /dmarc/i);
			} finally {
				await llm.close();
			}

			assert.equal(new SpamScanner({enableAuthentication: false}).config.authentication, false);
			assert.equal(new SpamScanner({enableAuthentication: true, authentication: false}).config.authentication, false);
		} finally {
			await dns.close();
		}
	});

	it('checks reputation lists and services', async () => {
		const service = await httpServer(request => (request.url.includes('truth.example') ? {isTruthSource: true} : {}));
		try {
			const scanner = new SpamScanner({
				...offline, classifier: false, allowlist: ['friend.example'], denylist: ['bad.example'],
			});
			assert.ok(names(await scanner.scan(message({from: 'x@bad.example', text: 'hi'}))).includes('DENYLISTED'));
			// (a From address allowlists a message only when authentication shows it is genuine)
			const dmarcPass = {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'friend.example'}}};
			assert.ok(names(await scanner.scan(message({from: 'x@friend.example', text: 'hi'}), dmarcPass)).includes('ALLOWLISTED'));
			const legacy = new SpamScanner({
				...offline, classifier: false, enableReputation: true, reputationOptions: {apiUrl: service.url, timeout: 1000},
			});
			assert.ok(names(await legacy.scan(message({from: 'x@truth.example', text: 'hi'}), {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'truth.example'}}})).includes('TRUTH_SOURCE'));
			assert.equal(new SpamScanner({enableReputation: true}).reputation, null);
			const combined = new SpamScanner({reputation: {apiUrl: service.url}, allowlist: ['a.example']});
			assert.deepEqual([...combined.reputation.allowlist], ['a.example']);
		} finally {
			await service.close();
		}
	});

	it('keeps the reputation service\'s answers, and its failures, for lists given for one message', async () => {
		const service = await httpServer(request => (request.url.includes('down.example') ? {status: 500, body: 'down'} : {}));
		const other = await httpServer(() => ({}));
		try {
			const scanner = new SpamScanner({...offline, classifier: false, reputation: {apiUrl: service.url}});
			const up = message({from: 'x@up.example', text: 'hi'});
			const down = message({from: 'x@down.example', text: 'hi'});
			await scanner.scan(up);
			await scanner.scan(down);
			const asked = service.requests.length;
			assert.ok(asked > 0);
			await scanner.scan(up, {denylist: ['bad.example']});
			await scanner.scan(down, {reputation: {allowlist: ['192.0.2.99']}});
			assert.equal(service.requests.length, asked);
			// (another service has its own answers)
			await scanner.scan(up, {reputation: {apiUrl: other.url}});
			assert.ok(other.requests.length > 0);
			// (a cacheSize for one message does not shrink the shared cache)
			await scanner.scan(message({from: 'x@third.example', text: 'hi'}), {reputation: {cacheSize: 1}});
			assert.ok(scanner.reputation.cache.size >= 3);
			await scanner.scan(up);
			assert.equal(service.requests.length, asked + 2);
			// (the answers of at most 100 services, or headers, are kept)
			for (let i = 0; i < 120; i++) {
				await scanner.scan(up, {reputation: {apiUrl: other.url, headers: {authorization: `Bearer ${i}`}}});
			}

			assert.equal(scanner.reputationCaches.size, 100);
			await scanner.scan(up);
			assert.equal(service.requests.length, asked + 2);
		} finally {
			await service.close();
			await other.close();
		}
	});

	it('asks a language model when the classifier is unsure or the score is close', async () => {
		const answers = [];
		const llm = await httpServer((request, body) => {
			answers.push(body);
			return {message: {content: JSON.stringify({verdict: 'phishing', confidence: 1, reasons: ['credential request']})}};
		});
		try {
			const settings = {provider: 'ollama', baseUrl: llm.url, model: 'test'};
			const scanner = new SpamScanner({...offline, classifier: false, llm: settings});
			const result = await scanner.scan(message({text: 'Please confirm your mailbox password at the link.'}));
			assert.equal(result.results.llm.verdict, 'phishing');
			assert.equal(answers[0].model, 'test');
			assert.ok(names(result).includes('LLM_PHISHING'));
			assert.equal(result.isSpam, true);
			// Far from the threshold and a confident classifier: not asked.
			const confident = new SpamScanner({...offline, classifier: small(), llm: settings});
			const ham = await confident.scan(message({subject: HAM[0][1], text: HAM[0][2]}));
			assert.equal(ham.results.llm, null);
			const always = await confident.scan(message({subject: HAM[0][1], text: HAM[0][2]}), {llm: {...settings, mode: 'always'}});
			assert.equal(always.results.llm.verdict, 'phishing');
			// A clear decision is not sent to the model either.
			const clear = await confident.scan(message({subject: SPAM[0][1], text: `${SPAM[0][2]} ${GTUBE}`}));
			assert.equal(clear.results.llm, null);
			const never = await scanner.scan(message({text: 'x'}), {llm: {...settings, mode: 'off'}});
			assert.equal(never.results.llm, null);
			const narrow = await scanner.scan(message({text: 'x'}), {llm: {...settings, minScore: 50, maxScore: 60}});
			assert.equal(narrow.results.llm.verdict, 'phishing');
		} finally {
			await llm.close();
		}

		const failing = new SpamScanner({...offline, classifier: false, llm: {provider: 'ollama', baseUrl: 'http://127.0.0.1:1', model: 'x'}});
		const result = await failing.scan(message({text: 'hello'}));
		assert.match(result.results.llm.error, /ECONNREFUSED/);
		assert.equal(result.results.llm.provider, 'ollama');
	});

	it('runs optional toxicity and image models supplied by the caller', async () => {
		const toxicity = {
			async classify([text]) {
				return [{label: 'insult', results: [{match: true, probabilities: [0.1, text.includes('idiot') ? 0.95 : 0.1]}]}, {label: 'threat', results: [{}]}];
			},
		};
		const nsfw = {
			classify(content) {
				if (content.includes('THROW')) {
					throw new Error('model failed');
				}

				return [{className: 'Porn', probability: content.includes('NSFW') ? 0.9 : 0.1}];
			},
		};
		const png = marker => Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47]), Buffer.from(marker)]);
		const scanner = new SpamScanner({
			...offline, classifier: false, toxicity: {model: toxicity}, nsfw: {model: nsfw, threshold: 0.5},
		});
		const result = await scanner.scan(message({
			subject: 'You idiot', text: 'You are an idiot and everyone knows it.', attachments: [{filename: 'a.png', content: png('NSFW')}, {filename: 'b.png', content: png('fine')}, {filename: 'c.png', content: png('THROW')}, {filename: '', content: png('NSFW')}, {filename: 'doc.txt', content: 'text'}],
		}));
		assert.deepEqual(result.results.toxicity.map(item => item.category), ['insult']);
		assert.deepEqual(result.results.nsfw.map(item => item.filename), ['a.png', 'unnamed image']);
		assert.ok(names(result).includes('TOXIC_CONTENT'));
		assert.ok(names(result).includes('NSFW_IMAGE'));
		const short = await scanner.scan(message({text: 'hi'}));
		assert.deepEqual(short.results.toxicity, []);
		// (the text the HTML shows counts, beside a short plain text part)
		const mixedParts = 'From: a@example.org\r\nSubject: note\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\nContent-Type: text/plain\r\n\r\nhi\r\n--m\r\nContent-Type: text/html\r\n\r\n<p>You are an idiot and everyone knows it.</p>\r\n--m--\r\n';
		assert.deepEqual((await scanner.scan(mixedParts)).results.toxicity.map(item => item.category), ['insult']);
		const broken = new SpamScanner({
			...offline,
			classifier: false,
			toxicity: {
				model: {
					classify() {
						throw new Error('broken');
					},
				},
			},
		});
		assert.deepEqual((await broken.scan(message({text: 'a long enough message to check'}))).results.toxicity, []);
		assert.throws(() => new SpamScanner({toxicity: true}), /toxicity check needs { model }/);
		assert.throws(() => new SpamScanner({nsfw: {}}), /nsfw check needs/);
	});

	it('times out slow network checks instead of waiting', async () => {
		const dns = await dnsServer({'slow.example A': 'timeout', '1.2.0.192.zen.example A': 'timeout'});
		try {
			const scanner = new SpamScanner({
				classifier: false, timeout: 200, dns: {servers: [dns.server], timeout: 5000}, dnsbl: {ip: ['zen.example'], domain: ['slow.example']},
			});
			scanner.dns.checkCloudflare = () => new Promise(() => {});
			const started = Date.now();
			const result = await scanner.scan(message({text: 'https://slow.example/'}), {session: {remoteAddress: '192.0.2.1'}});
			assert.ok(Date.now() - started < 3000);
			assert.deepEqual(result.results.dnsbl, []);
		} finally {
			await dns.close();
		}
	});

	it('exposes its defaults and a strict homograph mode', async () => {
		assert.equal(DEFAULTS.threshold, 5);
		const strict = new SpamScanner({strictIDNDetection: true});
		assert.equal(strict.homograph.options.strictMode, true);
		const combined = new SpamScanner({strictIDNDetection: true, phishing: {homograph: {allowlist: ['example.com']}}});
		assert.equal(combined.homograph.options.strictMode, true);
	});
});

describe('link hosts', () => {
	// A scanner whose lookups are answered here: hosts named "bad..." are
	// blocked as malware, "slow..." answers after `delay`, and each name asked
	// is kept.
	const withLookups = ({delay = 1000, ...options} = {}) => {
		const asked = new Set();
		const scanner = new SpamScanner({
			classifier: false,
			timeout: 300,
			...options,
			dns: {
				async resolve4(name) {
					asked.add(name);
					if (name.startsWith('slow')) {
						await new Promise(resolve => {
							setTimeout(resolve, delay);
						});
					}

					return name.startsWith('bad') ? ['0.0.0.0'] : ['192.0.2.1'];
				},
			},
		});
		return {scanner, asked};
	};

	const blocked = result => result.results.phishing.filter(item => item.type === 'malicious_domain').map(item => item.domain).sort();

	it('looks up a link a mail client shows though its anchor is never closed, or is around long markup', async () => {
		const {scanner} = withLookups();
		const result = await scanner.scan(message({
			text: 'Hello.',
			html: `<a href="https://bad1.example.org/x">open</p><a href="https://bad2.example.org/y"><span>${'x'.repeat(3000)}</span></a>`,
		}));
		assert.deepEqual(blocked(result), ['bad1.example.org', 'bad2.example.org']);
	});

	it('reads the href of a tag attribute by attribute, and character references in it', async () => {
		const {scanner} = withLookups();
		// (with a text part of its own: otherwise mailparser writes one, with
		//  the links in it)
		const result = await scanner.scan(message({
			text: 'Hello.',
			html: '<a title="x href=\'https://fake.example.org/\'" href="https://bad3.example.org/">a</a> <a href="https://fine.example.org&commat;bad4.example.org/">b</a>',
		}));
		assert.deepEqual(blocked(result), ['bad3.example.org', 'bad4.example.org']);
	});

	it('looks up the links of the whole message, not only what the classifier reads, and says when there is more', async () => {
		const {scanner} = withLookups();
		const long = await scanner.scan(message({text: `${'a '.repeat(300_000)}https://bad5.example.org/x`}));
		assert.deepEqual(blocked(long), ['bad5.example.org']);
		assert.equal(long.results.linksTruncated, false);
		const longer = await new SpamScanner({
			classifier: false, phishing: {cloudflare: false, maxLength: 1000},
		}).scan(message({text: 'a '.repeat(1000)}));
		assert.equal(longer.results.linksTruncated, true);
		// (unset, or not a length: the default)
		for (const maxLength of [undefined, Number.NaN, 0]) {
			const unset = await new SpamScanner({classifier: false, phishing: {cloudflare: false, maxLength}}).scan(message({text: `${'a '.repeat(1000)}https://link.example/`}));
			assert.equal(unset.results.linksTruncated, false);
			assert.deepEqual(unset.links, ['https://link.example/']);
		}
	});

	it('reports at most 50 deceptive links', async () => {
		const html = Array.from({length: 60}, (_, index) => `<a href="https://h${index}.example.net/">https://www.paypal.com/</a>`).join(' ');
		const result = await new SpamScanner({classifier: false, phishing: {cloudflare: false}}).scan(message({text: 'Hello.', html}));
		assert.equal(result.results.phishing.filter(item => item.type === 'deceptive_link').length, 50);
	});

	it('keeps what was found when the time limit is reached, and counts the hosts not answered', async () => {
		const {scanner} = withLookups();
		const result = await scanner.scan(message({html: '<a href="https://bad6.example.org/">a</a> <a href="https://slow.example.org/">b</a>'}));
		assert.deepEqual(blocked(result), ['bad6.example.org']);
		assert.equal(result.results.timedOutHosts, 1);
		assert.equal(result.results.uncheckedHosts, 0);
	});

	it('does not look up an address, nor take a word\'s end or a file name for a host', async () => {
		const {scanner, asked} = withLookups();
		const result = await scanner.scan(message({
			text: 'See straße.de/angebote, file.js/ or http://[2001:db8::1]/ and http://192.0.2.7/, and update.zip/download',
		}));
		assert.deepEqual(blocked(result), []);
		// (a real top-level domain that is also a file extension is a host)
		assert.deepEqual([...asked].sort(), ['update.zip']);
		assert.ok(result.links.includes('http://[2001:db8::1]/'));
	});
});

describe('allowlist and sender identities', () => {
	const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(0x3A), Buffer.from([0x40, 0, 0, 0]), Buffer.from('PE\0\0')]);
	const scanner = new SpamScanner({
		...offline, classifier: false, allowlist: ['mycompany.com', '192.0.2.10', 'relay.mycompany.com'], denylist: ['bad.example'],
	});
	const has = async (raw, options, test) => names(await scanner.scan(raw, options)).includes(test);

	it('does not allowlist a message by a forged Reply-To, From or envelope sender', async () => {
		const raw = message({
			from: 'attacker@evil.example', headers: {'Reply-To': 'ceo@mycompany.com'}, text: 'open the attachment', attachments: [{filename: 'invoice.pdf.exe', content: exe}],
		});
		const result = await scanner.scan(raw, {session: {remoteAddress: '203.0.113.9'}});
		assert.ok(!names(result).includes('ALLOWLISTED'));
		assert.equal(result.action, 'reject');
		assert.ok(!await has(message({from: 'ceo@mycompany.com', text: 'hi'}), {session: {remoteAddress: '203.0.113.9', envelope: {mailFrom: {address: 'ceo@mycompany.com'}}}}, 'ALLOWLISTED'));
		// (a pass for another domain proves nothing about this one)
		assert.ok(!await has(message({from: 'ceo@mycompany.com', text: 'hi'}), {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'evil.example'}, spf: {status: {result: 'pass'}, domain: 'evil.example'}}, session: {envelope: {mailFrom: {address: 'ceo@mycompany.com'}}}}, 'ALLOWLISTED'));
		// (the denylist still reads every value, Reply-To too)
		assert.ok(await has(message({from: 'a@example.org', headers: {'Reply-To': 'x@bad.example'}, text: 'hi'}), {}, 'DENYLISTED'));
	});

	it('allowlists by the client, and by sender addresses that authentication shows are genuine', async () => {
		const raw = message({from: 'ceo@mycompany.com', text: 'hi'});
		assert.ok(await has(raw, {session: {remoteAddress: '::ffff:192.0.2.10'}}, 'ALLOWLISTED'));
		assert.ok(await has(raw, {session: {remoteAddress: '203.0.113.9', resolvedClientHostname: 'relay.mycompany.com'}}, 'ALLOWLISTED'));
		assert.ok(await has(raw, {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'mycompany.com'}}}, 'ALLOWLISTED'));
		assert.ok(await has(raw, {authenticationResults: {dkim: {results: [{signingDomain: 'mycompany.com', status: {result: 'pass', aligned: 'mycompany.com'}}]}}}, 'ALLOWLISTED'));
		const envelope = {envelope: {mailFrom: {address: 'bounces@mycompany.com'}}};
		const other = message({from: 'news@other.example', text: 'hi'});
		assert.ok(await has(other, {session: envelope, authenticationResults: {spf: {status: {result: 'pass'}, domain: 'mycompany.com'}}}, 'ALLOWLISTED'));
		assert.ok(!await has(other, {session: envelope, authenticationResults: {spf: {status: {result: 'fail'}, domain: 'mycompany.com'}}}, 'ALLOWLISTED'));
		assert.ok(!await has(message({from: null, text: 'hi'}), {session: {envelope: {mailFrom: {address: ''}}}, authenticationResults: {spf: {status: {result: 'pass'}}}}, 'ALLOWLISTED'));
	});

	it('does not allowlist by a DMARC or SPF pass that does not name its domain', async () => {
		const raw = message({from: 'ceo@mycompany.com', text: 'hi'});
		assert.ok(!await has(raw, {authenticationResults: {dmarc: {status: {result: 'pass'}}}}, 'ALLOWLISTED'));
		assert.ok(!await has(raw, {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: ''}}}, 'ALLOWLISTED'));
		const other = message({from: 'news@other.example', text: 'hi'});
		assert.ok(!await has(other, {session: {envelope: {mailFrom: {address: 'bounces@mycompany.com'}}}, authenticationResults: {spf: {status: {result: 'pass'}}}}, 'ALLOWLISTED'));
	});

	it('allowlists by a DKIM signature in relaxed alignment, from a parent or a subdomain of the From domain', async () => {
		const signed = (from, domain) => [message({from, text: 'hi'}), {authenticationResults: {dkim: {results: [{signingDomain: domain, status: {result: 'pass', aligned: domain}}]}}}];
		assert.ok(await has(...signed('news@mail.mycompany.com', 'mycompany.com'), 'ALLOWLISTED'));
		assert.ok(await has(...signed('news@mycompany.com', 'mail.mycompany.com'), 'ALLOWLISTED'));
		assert.ok(!await has(...signed('news@mycompany.com', 'mycompany.com.example'), 'ALLOWLISTED'));
	});

	it('compares an international From domain with the punycode domain of authentication results', async () => {
		const scanner = new SpamScanner({...offline, classifier: false, allowlist: ['bücher.example']});
		const raw = 'From: info@bücher.example\r\nTo: a@example.org\r\nSubject: hi\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhi\r\n';
		for (const authenticationResults of [{dmarc: {status: {result: 'pass'}, domain: 'xn--bcher-kva.example'}}, {dkim: {results: [{signingDomain: 'xn--bcher-kva.example', status: {result: 'pass', aligned: 'xn--bcher-kva.example'}}]}}]) {
			assert.ok(names(await scanner.scan(Buffer.from(raw), {authenticationResults})).includes('ALLOWLISTED'));
		}

		// (a domain that is not a hostname proves nothing)
		const invalid = new SpamScanner({...offline, classifier: false, allowlist: ['a%b.example']});
		assert.ok(!names(await invalid.scan(message({from: 'info@a%b.example', text: 'hi'}), {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'a%b.example'}}})).includes('ALLOWLISTED'));
	});

	it('matches an allowlist entry in punycode with an international From domain, and the other way round', async () => {
		const dmarc = {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'xn--bcher-kva.example'}}};
		const unicode = Buffer.from('From: info@bücher.example\r\nTo: a@example.org\r\nSubject: hi\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhi\r\n');
		const punycode = message({from: 'info@xn--bcher-kva.example', text: 'hi'});
		for (const entry of ['xn--bcher-kva.example', 'BÜCHER.example', 'info@xn--bcher-kva.example']) {
			const scanner = new SpamScanner({...offline, classifier: false, allowlist: [entry]});
			assert.ok(names(await scanner.scan(unicode, dmarc)).includes('ALLOWLISTED'), entry);
			assert.ok(names(await scanner.scan(punycode, dmarc)).includes('ALLOWLISTED'), entry);
		}
	});

	it('does not allowlist by a signing domain or DMARC domain that is not a hostname', async () => {
		const scanner = new SpamScanner({...offline, classifier: false, allowlist: ['bank.com']});
		const raw = message({from: 'CEO <ceo@bank.com>', text: 'Please wire the money today.'});
		// (URL parsers, tldts and domainToASCII among them, read "bank.com" from all of these)
		for (const domain of ['bank.com/x.attacker.example', 'bank.com?x.attacker.example', 'bank.com#x.attacker.example', String.raw`bank.com\x.attacker.example`, 'bank.com\uFF0Fx.attacker.example', 'bank.com:25']) {
			const signed = {dkim: {results: [{signingDomain: domain, status: {result: 'pass', aligned: domain}}]}};
			const result = await scanner.scan(raw, {authenticationResults: signed});
			assert.ok(!names(result).includes('ALLOWLISTED'), domain);
			assert.equal(result.results.authentication.dkim.aligned, null);
			assert.ok(!names(await scanner.scan(raw, {authenticationResults: {dmarc: {status: {result: 'pass'}, domain}}})).includes('ALLOWLISTED'), domain);
		}

		// (nor by labels that are empty or too long)
		for (const domain of ['bank..com', `${'a'.repeat(64)}.bank.com`, `${'a.'.repeat(127)}bank.com`]) {
			assert.ok(!names(await scanner.scan(raw, {authenticationResults: {dkim: {results: [{signingDomain: domain, status: {result: 'pass', aligned: domain}}]}}})).includes('ALLOWLISTED'), domain);
		}
	});

	it('allowlists a subdomain by a DMARC pass for its organizational domain, as mailauth gives it', async () => {
		const pass = (dkim, spf) => ({authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'bank.example', alignment: {dkim: {result: dkim}, spf: {result: spf}}}}});
		const raw = message({from: 'alerts@notify.bank.example', text: 'Your statement is ready.'});
		for (const entry of ['notify.bank.example', 'alerts@notify.bank.example', 'bank.example']) {
			const scanner = new SpamScanner({...offline, classifier: false, allowlist: [entry]});
			assert.ok(names(await scanner.scan(raw, pass('bank.example', false))).includes('ALLOWLISTED'), entry);
			assert.ok(names(await scanner.scan(raw, pass(false, 'notify.bank.example'))).includes('ALLOWLISTED'), entry);
		}

		// (a sibling's signature does not vouch for another subdomain, nor does
		//  a DMARC pass for another organizational domain)
		const subdomain = new SpamScanner({...offline, classifier: false, allowlist: ['notify.bank.example']});
		assert.ok(!names(await subdomain.scan(raw, pass('evil.bank.example', false))).includes('ALLOWLISTED'));
		assert.ok(!names(await subdomain.scan(raw, {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'other.example', alignment: {dkim: {result: 'other.example'}}}}})).includes('ALLOWLISTED'));
		// (without alignment details, a pass for the organizational domain
		//  vouches for it only: which subdomain aligned is not known)
		const orgOnly = {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'bank.example'}}};
		assert.ok(!names(await subdomain.scan(raw, orgOnly)).includes('ALLOWLISTED'));
		assert.ok(names(await new SpamScanner({...offline, classifier: false, allowlist: ['bank.example']}).scan(raw, orgOnly)).includes('ALLOWLISTED'));
		// (nor does a public suffix vouch, or a domain of another organization)
		assert.ok(!names(await subdomain.scan(raw, pass('example', false))).includes('ALLOWLISTED'));
		const github = message({from: 'a@sub.user.github.io', text: 'hi'});
		const pages = new SpamScanner({...offline, classifier: false, allowlist: ['sub.user.github.io']});
		assert.ok(!names(await pages.scan(github, {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'user.github.io', alignment: {dkim: {result: 'github.io'}}}}})).includes('ALLOWLISTED'));
		const bank = new SpamScanner({...offline, classifier: false, allowlist: ['bank.example']});
		assert.ok(!names(await bank.scan(message({from: 'a@bank.example', text: 'hi'}), {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'bank.example', alignment: {dkim: {result: 'attacker.example'}}}}})).includes('ALLOWLISTED'));
	});

	it('vouches by every passing aligned signature, not only the first', async () => {
		const scanner = new SpamScanner({...offline, classifier: false, allowlist: ['notify.bank.example']});
		const raw = message({from: 'alerts@notify.bank.example', text: 'hi'});
		const results = [
			{signingDomain: 'other.bank.example', status: {result: 'pass', aligned: 'other.bank.example'}},
			{signingDomain: 'notify.bank.example', status: {result: 'pass', aligned: 'notify.bank.example'}},
			{signingDomain: 'x.bank.example', status: {result: 'fail', aligned: 'x.bank.example'}},
		];
		assert.ok(names(await scanner.scan(raw, {authenticationResults: {dkim: {results}}})).includes('ALLOWLISTED'));
		assert.ok(!names(await scanner.scan(raw, {authenticationResults: {dkim: {results: results.slice(0, 1)}}})).includes('ALLOWLISTED'));
	});

	it('lets a signature of another subdomain vouch only for an entry naming the registrable domain', async () => {
		const signed = (from, domain) => [message({from, text: 'hi'}), {authenticationResults: {dkim: {results: [{signingDomain: domain, status: {result: 'pass', aligned: domain}}]}}}];
		const subdomain = new SpamScanner({...offline, classifier: false, allowlist: ['trusted.example.com']});
		const allowlisted = async (scanner, args) => names(await scanner.scan(...args)).includes('ALLOWLISTED');
		assert.ok(!await allowlisted(subdomain, signed('ceo@trusted.example.com', 'evil.example.com')));
		// (a parent controls its subdomains' DNS)
		assert.ok(await allowlisted(subdomain, signed('ceo@trusted.example.com', 'example.com')));
		assert.ok(await allowlisted(subdomain, signed('ceo@trusted.example.com', 'trusted.example.com')));
		assert.ok(await allowlisted(subdomain, signed('ceo@trusted.example.com', 'mail.trusted.example.com')));
		assert.ok(await allowlisted(subdomain, signed('ceo@a.trusted.example.com', 'trusted.example.com')));
		const registrable = new SpamScanner({...offline, classifier: false, allowlist: ['example.com']});
		assert.ok(await allowlisted(registrable, signed('ceo@trusted.example.com', 'evil.example.com')));
		// (every passing aligned signature counts with a DMARC pass too)
		const results = [{signingDomain: 'evil.example.com', status: {result: 'pass', aligned: 'evil.example.com'}}, {signingDomain: 'trusted.example.com', status: {result: 'pass', aligned: 'trusted.example.com'}}];
		assert.ok(names(await subdomain.scan(message({from: 'ceo@trusted.example.com', text: 'hi'}), {authenticationResults: {dkim: {results}, dmarc: {status: {result: 'pass'}, domain: 'example.com', alignment: {dkim: {result: 'evil.example.com'}}}}})).includes('ALLOWLISTED'));
		// (a DMARC pass is the domain's own word for it)
		assert.ok(names(await subdomain.scan(message({from: 'ceo@trusted.example.com', text: 'hi'}), {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'trusted.example.com'}}})).includes('ALLOWLISTED'));
	});

	it('honours lists given for one message, keeping the scanner\'s others', async () => {
		const raw = message({from: 'x@one.example', text: 'hi'});
		assert.ok(await has(raw, {denylist: ['one.example']}, 'DENYLISTED'));
		// (a denylist for one message keeps the scanner's allowlist)
		assert.ok(await has(raw, {denylist: ['two.example'], session: {remoteAddress: '192.0.2.10'}}, 'ALLOWLISTED'));
		assert.ok(await has(raw, {reputation: {allowlist: ['192.0.2.99']}, session: {remoteAddress: '192.0.2.99'}}, 'ALLOWLISTED'));
		assert.equal((await scanner.scan(raw, {reputation: false})).results.reputation, null);
		assert.ok(await has(raw, {denylist: ['one.example']}, 'DENYLISTED'));
		assert.ok(names(await new SpamScanner({...offline, classifier: false}).scan(raw, {denylist: ['one.example']})).includes('DENYLISTED'));
	});
});

describe('attached messages', () => {
	const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(0x3A), Buffer.from([0x40, 0, 0, 0]), Buffer.from('PE\0\0')]);
	// A message carrying `inner` as an attached message.
	const forward = (inner, filename = 'fw.eml') => {
		const boundary = `o${filename.replaceAll('.', '')}`;
		return `From: c@example.org\r\nTo: d@example.org\r\nSubject: fw\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="${boundary}"\r\n\r\n--${boundary}\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--${boundary}\r\nContent-Type: message/rfc822${filename ? `\r\nContent-Disposition: attachment; filename="${filename}"` : ''}\r\n\r\n${inner}\r\n--${boundary}--\r\n`;
	};

	it('inspects and scans the attachments of attached messages', async () => {
		const inner = message({subject: 'inner', text: 'hi', attachments: [{filename: 'invoice.exe', content: exe}, {filename: '', content: eicar()}]});
		const clamd = await fakeClamd();
		try {
			const result = await new SpamScanner({...offline, classifier: false, clamav: {port: clamd.port}}).scan(forward(inner));
			assert.deepEqual(result.results.attachments.map(item => [item.type, item.filename]), [['executable', 'fw.eml/invoice.exe']]);
			assert.deepEqual(result.results.viruses.map(item => item.filename), ['fw.eml/unnamed attachment']);
		} finally {
			await clamd.close();
		}
	});

	it('reports a virus in an attachment of an attached message once', async () => {
		const virus = eicar().toString('latin1');
		// (not in base64: clamd finds the virus in the attached message too)
		const inner = `From: x@example.org\r\nSubject: inner\r\nContent-Type: multipart/mixed; boundary=c\r\n\r\n--c\r\nContent-Type: text/plain\r\n\r\nhi\r\n--c\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=v.com\r\n\r\n${virus}\r\n--c--\r\n`;
		const clamd = await fakeClamd();
		try {
			const scanner = new SpamScanner({...offline, classifier: false, clamav: {port: clamd.port}});
			const viruses = async raw => (await scanner.scan(raw)).results.viruses.map(item => item.filename);
			assert.deepEqual(await viruses(forward(inner)), ['fw.eml/v.com']);
			assert.deepEqual(await viruses(forward(forward(inner, 'b.eml'), 'a.eml')), ['a.eml/b.eml/v.com']);
			assert.deepEqual(await viruses(forward(inner, '')), ['attached message/v.com']);
			// (an attached message carrying the virus in its own text is reported)
			assert.deepEqual(await viruses(forward(`From: x@example.org\r\nSubject: inner\r\n\r\n${virus}\r\n`)), ['fw.eml']);
			// (and so is another attachment of the message with the same virus)
			const both = forward(inner).replace('--ofweml--', `--ofweml\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=w.com\r\n\r\n${virus}\r\n--ofweml--`);
			assert.deepEqual((await viruses(both)).sort(), ['fw.eml/v.com', 'w.com']);
		} finally {
			await clamd.close();
		}
	});

	it('opens attached messages three levels deep, and an unnamed one too', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const executables = async raw => (await scanner.scan(raw)).results.attachments.map(item => item.filename);
		const payload = message({text: 'x', attachments: [{filename: 'run.exe', content: exe}]});
		assert.deepEqual(await executables(forward(forward(forward(payload, 'c.eml'), 'b.eml'), 'a.eml')), ['a.eml/b.eml/c.eml/run.exe']);
		assert.deepEqual(await executables(forward(forward(forward(forward(payload, 'd.eml'), 'c.eml'), 'b.eml'), 'a.eml')), []);
		assert.deepEqual(await executables(forward(payload, '')), ['attached message/run.exe']);
	});

	it('reads at most 100 attachments of attached messages, and every attachment of the message', async () => {
		const many = message({text: 'x', attachments: Array.from({length: 120}, (_, i) => ({filename: `run${i}.exe`, content: exe}))});
		const scanner = new SpamScanner({...offline, classifier: false});
		assert.equal((await scanner.scan(forward(many))).results.attachments.length, 100);
		// (the message's own attachments are never dropped: the 121st is still found)
		const notes = Array.from({length: 120}, (_, i) => ({filename: `note${i}.txt`, content: `note ${i}`}));
		const result = await scanner.scan(message({text: 'x', attachments: [...notes, {filename: 'invoice.exe', content: exe}]}));
		assert.deepEqual(result.results.attachments.map(item => item.filename), ['invoice.exe']);
		assert.equal(result.mail.attachments.length, 121);
	});
});

describe('messages beyond the parser\'s limits', () => {
	// A message of `count` MIME parts, the last one `last`.
	const parts = (count, last = '%PDF-1.4') => {
		let raw = 'From: a@example.com\r\nTo: b@example.org\r\nSubject: many parts\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n';
		for (let i = 0; i < count; i++) {
			raw += `--b\r\nContent-Type: application/pdf; name="r${i}.pdf"\r\nContent-Disposition: attachment; filename="r${i}.pdf"\r\n\r\n${i === count - 1 ? last : '%PDF-1.4'}\r\n`;
		}

		return `${raw}--b--\r\n`;
	};

	it('reads the first parts of a message with more than 1000 parts, and marks it', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const result = await scanner.scan(parts(1001));
		assert.match(result.results.parseError, /child nodes/);
		assert.ok(names(result).includes('MIME_TOO_COMPLEX'));
		assert.equal(result.isSpam, true);
		assert.equal(result.mail.subject, 'many parts');
		assert.ok(result.mail.attachments.length > 900);
		const fine = await scanner.scan(parts(999));
		assert.equal(fine.results.parseError, null);
		assert.ok(!names(fine).includes('MIME_TOO_COMPLEX'));
	});

	it('parses, learns from and reads the words of such a message, and text with no header', async () => {
		const scanner = new SpamScanner({...offline, classifier: new Classifier()});
		const many = parts(1001);
		const parsed = await scanner.parse(many);
		assert.equal(parsed.mail.subject, 'many parts');
		assert.ok(parsed.mail.attachments.length > 900);
		assert.equal(parsed.raw.toString(), many);
		await scanner.learn(many, 'spam');
		await scanner.unlearn(many, 'spam');
		assert.ok((await scanner.getTokensAndMailFromSource(many)).features.length > 0);
		// (text whose first line is not a header field is the message's text)
		for (const text of ['just text, no header', 'Hello there,\r\nsee you at noon: bring the notes.\r\n', '\0\0\0']) {
			const plain = await scanner.parse(text);
			assert.equal(plain.mail.text, text.replaceAll('\r\n', '\n'));
			assert.equal(plain.raw.toString(), text);
		}

		// (and a header, an mbox "From " line or a blank line first are read as before)
		assert.deepEqual([(await scanner.parse('Subject: hi\r\n\r\nbody')).mail.subject, (await scanner.parse('Subject: hi\r\n\r\nbody')).mail.text], ['hi', 'body']);
		assert.equal((await scanner.parse('From sender@example.org Mon Jan  1 00:00:00 2024\r\nSubject: mbox\r\n\r\nbody')).mail.subject, 'mbox');
		assert.equal((await scanner.parse('\r\nbody after a blank line')).mail.text, 'body after a blank line');
		assert.equal((await scanner.parse('')).mail.text, '');
	});

	it('reads the text, links and attachments before a flood of parts, and gives no credit for the sender\'s authentication', async () => {
		const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(0x3A), Buffer.from([0x40, 0, 0, 0]), Buffer.from('PE\0\0')]);
		let raw = 'From: Accounts <billing@sender.example>\r\nTo: b@example.org\r\nSubject: Re: notes\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n';
		raw += '--b\r\nContent-Type: text/html\r\n\r\n<p>Your account is limited: <a href="http://paypa1-secure.top/login">https://www.paypal.com/signin</a></p>\r\n';
		raw += `--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="invoice.exe"\r\nContent-Transfer-Encoding: base64\r\n\r\n${exe.toString('base64')}\r\n`;
		raw += '--b\r\nContent-Type: text/plain\r\n\r\n.\r\n'.repeat(1000);
		raw += '--b--\r\n';
		const passed = {
			spf: {status: {result: 'pass'}, domain: 'sender.example'}, dkim: {results: [{signingDomain: 'sender.example', status: {result: 'pass', aligned: 'sender.example'}}]}, dmarc: {status: {result: 'pass'}, domain: 'sender.example'}, arc: {status: {result: 'pass'}},
		};
		const result = await new SpamScanner({...offline, classifier: false}).scan(raw, {authenticationResults: passed});
		for (const test of ['MIME_TOO_COMPLEX', 'DECEPTIVE_LINK', 'EXECUTABLE_ATTACHMENT']) {
			assert.ok(names(result).includes(test), test);
		}

		assert.ok(result.tests.every(test => test.score >= 0));
		// (the allowlist still counts: the receiver trusts it)
		const allowlisted = await new SpamScanner({...offline, classifier: false, allowlist: ['sender.example']}).scan(raw, {authenticationResults: passed});
		assert.ok(names(allowlisted).includes('ALLOWLISTED'));
	});

	it('reads HTML nested thousands of levels deep, quickly, and the words it shows', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		for (const depth of [2000, 50_000]) {
			const started = cpuTime();
			const raw = `From: a@example.com\r\nSubject: deep\r\nContent-Type: text/html\r\n\r\n${'<div>'.repeat(depth)}Sign in <a href="http://paypa1-secure.top/login">https://www.paypal.com/signin</a>${'</div>'.repeat(depth)}`;
			const result = await scanner.scan(raw);
			assert.equal(result.results.parseError, null);
			assert.ok(names(result).includes('DECEPTIVE_LINK'), String(depth));
			assert.ok(cpuTime() - started < 5000);
		}

		// (mailparser makes no text of HTML: the words are those it shows)
		const shown = await scanner.scan(message({html: '<h1>Hello</h1><p style="display:none">hidden words</p><p>world</p>'}));
		assert.equal(shown.mail.text || '', '');
		assert.ok(shown.tokens.includes('hello') && shown.tokens.includes('world'));
		assert.ok(!shown.tokens.includes('hidden'));
	});

	it('reads a message whose parts are attached messages inline, and never fails on an attached message', async () => {
		const scanner = new SpamScanner({...offline, classifier: false, denylist: ['sender.example']});
		let nested = 'Content-Type: text/plain\r\n\r\nhi\r\n';
		for (let i = 0; i < 1002; i++) {
			nested = `Content-Type: message/rfc822\r\nContent-Disposition: inline\r\n\r\n${nested}`;
		}

		const deep = await scanner.scan(`From: a@sender.example\r\nSubject: deep\r\n${nested}`);
		assert.match(deep.results.parseError, /child nodes/);
		assert.ok(names(deep).includes('DENYLISTED'));
		let parts = '';
		for (let i = 0; i < 500; i++) {
			parts += `--b\r\nContent-Type: message/rfc822\r\nContent-Disposition: inline\r\n\r\nContent-Type: text/plain\r\n\r\npart ${i}\r\n`;
		}

		const wide = await scanner.scan(`From: a@example.org\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n${parts}--b--\r\n`);
		assert.match(wide.results.parseError, /child nodes/);
		// (the same as an attached file, which earlier versions did not open)
		const thread = Buffer.from(`From: x@example.org\r\nSubject: fwd\r\n${nested}`).toString('base64').replaceAll(/.{76}/g, '$&\r\n');
		const attached = await scanner.scan(`From: alice@example.com\r\nSubject: Fwd: thread\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee attached thread.\r\n--b\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename=thread.eml\r\nContent-Transfer-Encoding: base64\r\n\r\n${thread}\r\n--b--\r\n`);
		assert.match(attached.results.parseError, /child nodes/);
		// (an attached message that fails the parser is listed, not thrown)
		const errors = [];
		const all = await expandAttachments([{filename: 'fw.eml', contentType: 'message/rfc822', content: Buffer.from('x')}], errors, async () => {
			throw new Error('broken');
		});
		assert.deepEqual([all.length, errors], [1, ['fw.eml: broken']]);
		await expandAttachments([{contentType: 'message/rfc822', content: Buffer.from('x')}], errors, async () => {
			throw new Error('broken');
		});
		assert.equal(errors[1], 'attached message: broken');
	});

	it('takes a brand\'s sign-in address shown through click tracking for a deceptive link, by who sent it', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const tracked = (from, text) => message({from, subject: 'Account notice', html: `<p>Please sign in: <a href="https://example.us1.list-manage.com/track/click?u=1&id=2">${text}</a></p>`});
		const deceptive = async raw => names(await scanner.scan(raw)).includes('DECEPTIVE_LINK');
		assert.ok(await deceptive(tracked('alerts@notice-center.example', 'https://www.paypal.com/signin')));
		assert.ok(await deceptive(tracked('alerts@notice-center.example', 'https://www.amazon.com/ap/sign-in')));
		// (not a newsletter's links, nor the brand's own)
		assert.ok(!await deceptive(tracked('news@shop.example', 'https://www.amazon.com/dp/B000')));
		assert.ok(!await deceptive(tracked('service@paypal.com', 'https://www.paypal.com/signin')));
	});

	it('leaves an attachment open at the end of a message as it was', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const result = await scanner.scan('From: a@example.org\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=a.txt\r\n\r\nhello');
		assert.equal(result.mail.attachments[0].content.toString(), 'hello');
		assert.equal(result.mail.attachments[0].size, 5);
		// (and one that is closed, or in base64, keeps every byte of its own)
		const ending = 'line one\r\nline two\r\n\r\n';
		for (const [encoding, body] of [['base64', Buffer.from(ending).toString('base64')], ['7bit', ending]]) {
			for (const end of ['\r\n--b--\r\n', '']) {
				if (encoding === '7bit' && end === '') {
					continue;
				}

				const kept = await scanner.scan(`From: a@example.org\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: ${encoding}\r\nContent-Disposition: attachment; filename=a.txt\r\n\r\n${body}${end}`);
				assert.equal(kept.mail.attachments[0].content.toString(), ending, `${encoding} ${end ? 'closed' : 'open'}`);
			}
		}

		// (nor one closed before an epilogue, or followed by a part left open;
		//  and one left open keeps a last line that looks like a boundary)
		const head = 'From: a@example.org\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n--b\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=a.txt\r\n\r\n';
		const content = async raw => {
			const {attachments} = (await scanner.scan(raw)).mail;
			assert.equal(attachments.at(-1).size, attachments.at(-1).content.length);
			return attachments.map(attachment => attachment.content.toString());
		};

		assert.deepEqual(await content(`${head}line\r\n\r\n\r\n--b--\r\nThis is the epilogue.\r\n`), ['line\r\n\r\n']);
		assert.deepEqual(await content(`${head}line\r\n\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nbody text, never closed\r\n`), ['line\r\n\r\n']);
		assert.deepEqual(await content(`${head}line\r\n----------\r\n`), ['line\r\n----------\r\n']);
		assert.deepEqual(await content(`${head}line\r\n--b--x\r\n`), ['line\r\n--b--x\r\n']);
	});

	it('checks a link through a security gateway by the address it goes on to', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const wrapped = `https://eur01.safelinks.protection.outlook.com/?url=${encodeURIComponent('https://paypa1.com/login')}&data=x`;
		const result = await scanner.scan(message({html: `<p>Please <a href="${wrapped}">sign in</a></p>`}));
		assert.ok(names(result).includes('PHISHING_LOOKALIKE_DOMAIN')); // (and a link with no address it can read, by its own host)
		const checked = await scanner.checkLinks([{url: 'http://[bad', host: 'paypa1.com', text: null}], scanner.config);
		assert.ok(checked.phishing.some(item => item.type === 'homograph' || /paypa1/.test(String(item))));
	});

	it('reads HTML with tags named like the properties of objects', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		for (const tag of ['constructor', 'Constructor', '__proto__', 'toString', 'hasOwnProperty']) {
			const result = await scanner.scan(message({html: `<p>Hello <${tag}>friend</${tag}></p>`}));
			assert.ok(result.tokens.includes('friend'), tag);
		}
	});

	it('finishes a message that ends in the header of an attached message', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const within = (promise, ms = 5000) => Promise.race([promise, new Promise((resolve, reject) => {
			setTimeout(() => reject(new Error('did not finish')), ms).unref();
		})]);
		for (const raw of [
			'From: a@example.org\r\nContent-Type: message/rfc822\r\nContent-Disposition: inline\r\n',
			'From: a@example.org\r\nContent-Type: message/rfc822\r\nContent-Disposition: inline',
			'From: a@example.org\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\nContent-Disposition: inline\r\n',
			// (its type folded, spaced, quoted, or only a file name)
			'From: a@example.org\r\nContent-Type:\r\n message/rfc822\r\nContent-Disposition: inline\r\n',
			'From: a@example.org\r\nContent-Type :message/rfc822\r\nContent-Disposition: inline\r\n',
			'From: a@example.org\r\nContent-Type\r\n : message/rfc822\r\nContent-Disposition: inline\r\n',
			'From: a@example.org\r\nContent-Type:\r\n \r\n message/rfc822\r\nContent-Disposition: inline\r\n',
			'From: a@example.org\r\nContent-Type: "message/rfc822"\r\nContent-Disposition: inline\r\n',
			'From: a@example.org\nSubject: hi\nContent-Disposition: inline; filename="fw.eml"\n',
		]) {
			const result = await within(scanner.scan(raw));
			assert.equal(result.mail.from.value[0].address, 'a@example.org');
		}

		// (a message ending otherwise is read as it is)
		assert.equal((await parseMessage('From: a@example.org\r\n\r\nshort')).text, 'short');
	});

	it('reads the sender of a message whose header is too large', async () => {
		const scanner = new SpamScanner({...offline, classifier: false, denylist: ['spammer.example']});
		const body = 'Subject: win\r\nContent-Type: text/plain\r\n\r\nverify your bank password now\r\n';
		for (const pad of [
			`X-Pad: ${'a'.repeat(1_100_000)}\r\n`,
			`X-Pad: ${Array.from({length: 20_000}, () => 'a'.repeat(60)).join('\r\n ')}\r\n`,
			Array.from({length: 30_000}, (_, i) => `X-Pad-${i}: ${'a'.repeat(40)}\r\n`).join(''),
		]) {
			const result = await scanner.scan(`${pad}From: bad@spammer.example\r\n${body}`);
			assert.match(result.results.parseError, /header size/);
			assert.ok(names(result).includes('DENYLISTED'));
			assert.equal(result.mail.subject, 'win');
		}

		// (and many fields that say how it came, the first 100 of each)
		const received = Array.from({length: 1500}, (_, i) => `Received: from host${i}.example.org ${'x'.repeat(950)}\r\n`).join('');
		const routed = await scanner.scan(`${received}From: bad@spammer.example\r\n${body}`);
		assert.match(routed.mail.text, /verify your bank password/);
		assert.ok(names(routed).includes('DENYLISTED'));

		// (and without a body)
		const headerOnly = await scanner.scan(`X-Pad: ${'a'.repeat(1_100_000)}\nFrom: bad@spammer.example`);
		assert.ok(names(headerOnly).includes('DENYLISTED'));
	});

	it('counts obfuscation in an HTML part beside a short plain text part, and once in an alternative message', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const html = '<p>P\u200BA\u200BY\u200BP\u200BA\u200BL account susp\u0435nded. Ver\u0456fy your p\u0430ssword immediately or lose access</p>';
		const encoded = Buffer.from(html).toString('base64');
		const head = 'From: shop@example.org\r\nSubject: hello\r\nMIME-Version: 1.0\r\n';
		const mixed = await scanner.scan(`${head}Content-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\nContent-Type: text/plain\r\n\r\nhi\r\n--m\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${encoded}\r\n--m--\r\n`);
		assert.ok(names(mixed).includes('MIXED_SCRIPT_WORDS'));
		assert.ok(names(mixed).includes('INVISIBLE_CHARACTERS'));
		const plain = Buffer.from('P\u200BA\u200BY\u200BP\u200BA\u200BL account susp\u0435nded. Ver\u0456fy your p\u0430ssword immediately or lose access').toString('base64');
		const alternative = await scanner.scan(`${head}Content-Type: multipart/alternative; boundary=a\r\n\r\n--a\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${plain}\r\n--a\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${encoded}\r\n--a--\r\n`);
		assert.deepEqual(alternative.results.obfuscation, mixed.results.obfuscation);
	});

	it('reads HTML that is not the root part as earlier versions did', async () => {
		const head = 'From: shop@example.org\r\nSubject: s\r\nMIME-Version: 1.0\r\n';
		const html = '<p>Click <a href="http://example.com/x">HERE</a> to claim your reward today.</p><img src="cid:i1">';
		const related = `${head}Content-Type: multipart/related; boundary=r\r\n\r\n--r\r\nContent-Type: text/html\r\n\r\n${html}\r\n--r\r\nContent-Type: image/png\r\nContent-ID: <i1>\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--r--\r\n`;
		const withPdf = `${head}Content-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\nContent-Type: text/html\r\n\r\n${html}\r\n--m\r\nContent-Type: application/pdf; name=r.pdf\r\nContent-Disposition: attachment; filename=r.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQKJSVFT0YK\r\n--m--\r\n`;
		for (const raw of [related, withPdf]) {
			const {features} = getFeatures(await parseMessage(Buffer.from(raw)));
			assert.ok(features.includes('html:only'));
			assert.ok(!features.includes('html:alternative'));
		}
	});

	it('throws on parser errors other than its limits, as earlier versions did', async () => {
		await assert.rejects(parseWithin(Buffer.from('x'), async () => {
			throw new Error('broken');
		}), /broken/);
		// (a limit that reading less cannot get under)
		const limit = Object.assign(new Error('Max allowed child nodes exceeded'), {code: 'EMAXLEN'});
		await assert.rejects(parseWithin(Buffer.from('no part lines'), async () => {
			throw limit;
		}), /child nodes/);
		await assert.rejects(parseWithin(Buffer.from('x'), async () => {
			throw Object.assign(new Error('other limit'), {code: 'EMAXLEN'});
		}), /other limit/);
	});

	it('reads what it can of a header over 1 MB', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const long = `From: a@example.com\r\nSubject: long\r\nX-Long: ${'a'.repeat(1_100_000)}\r\n\r\nhi\r\n`;
		const result = await scanner.scan(long);
		assert.match(result.results.parseError, /header size/);
		assert.equal(result.mail.subject, 'long');
		// (folded over many lines, and without a body)
		const folded = await scanner.scan(`From: a@example.com\r\nSubject: folded\r\nX-Long: ${Array.from({length: 20_000}, () => 'a'.repeat(60)).join('\r\n ')}\r\n`);
		assert.ok(names(folded).includes('MIME_TOO_COMPLEX'));
		assert.equal(folded.mail.subject, 'folded');
		assert.equal((await scanner.scan(`X-Long: ${'a'.repeat(1_100_000)}`)).results.parseError !== null, true);
		// (the parts before a part whose header is too large are read)
		const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(0x3A), Buffer.from([0x40, 0, 0, 0]), Buffer.from('PE\0\0')]);
		const later = `From: a@example.com\r\nSubject: later\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="run.exe"\r\nContent-Transfer-Encoding: base64\r\n\r\n${exe.toString('base64')}\r\n--b\r\nContent-Type: text/plain\r\nX-Long: ${'a'.repeat(1_100_000)}\r\n\r\nhi\r\n--b--\r\n`;
		const read = await scanner.scan(later);
		assert.match(read.results.parseError, /header size/);
		assert.ok(names(read).includes('EXECUTABLE_ATTACHMENT'));
	});

	it('marks an attached message beyond the limits, and has clamd read a message whole', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const forwarded = `From: c@example.org\r\nTo: d@example.org\r\nSubject: fw\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="o"\r\n\r\n--o\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--o\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment; filename="fw.eml"\r\n\r\n${parts(1001)}\r\n--o--\r\n`;
		const result = await scanner.scan(forwarded);
		assert.match(result.results.parseError, /child nodes/);
		assert.ok(names(result).includes('MIME_TOO_COMPLEX'));
		const clamd = await fakeClamd();
		try {
			const scanned = await new SpamScanner({...offline, classifier: false, clamav: {port: clamd.port}}).scan(parts(1001, eicar().toString('latin1')));
			assert.deepEqual(scanned.results.viruses.map(item => item.filename), ['message.eml']);
		} finally {
			await clamd.close();
		}
	});
});

describe('time limits and failures', () => {
	it('does not count an attachment larger than clamd accepts as a failed scan, and lists it as skipped', async () => {
		const raw = message({text: 'see attached', attachments: [{filename: 'report.pdf', content: Buffer.from('%PDF-1.4\n')}]});
		const large = await fakeClamd({reply: 'INSTREAM size limit exceeded. ERROR\0'});
		try {
			const result = await new SpamScanner({...offline, classifier: false, clamav: {port: large.port}}).scan(raw);
			assert.deepEqual(result.results.virusScanErrors, []);
			assert.deepEqual(result.results.virusScanSkipped, [{filename: 'report.pdf', reason: 'INSTREAM size limit exceeded. ERROR'}]);
		} finally {
			await large.close();
		}

		// (its scan limits, which an archive bomb reaches, and running out of
		//  memory are failures, tried again later)
		for (const reply of ['stream: Exceeded max scan size ERROR\0', 'stream: Exceeded max scan files ERROR\0', 'stream: Exceeded max recursion depth ERROR\0', 'stream: Exceeded time limit ERROR\0', 'stream: Can\'t allocate memory ERROR\0']) {
			const clamd = await fakeClamd({reply});
			try {
				const result = await new SpamScanner({...offline, classifier: false, clamav: {port: clamd.port}}).scan(raw);
				assert.equal(result.results.virusScanErrors.length, 1, reply);
				assert.deepEqual(result.results.virusScanSkipped, []);
			} finally {
				await clamd.close();
			}
		}

		assert.deepEqual((await new SpamScanner({...offline, classifier: false}).scan(raw)).results.virusScanSkipped, []);
	});

	it('gives ClamAV its own time limit, not the network checks\'', async () => {
		const answerLater = socket => setTimeout(() => socket.end('stream: OK\0'), 300);
		const slow = net.createServer({allowHalfOpen: true}, socket => {
			socket.on('error', () => {});
			socket.resume();
			socket.on('end', () => answerLater(socket));
		});
		slow.listen(0, '127.0.0.1');
		await once(slow, 'listening');
		try {
			const attachments = Array.from({length: 8}, (_, i) => ({filename: `f${i}.txt`, content: 'x'}));
			const result = await new SpamScanner({
				...offline, classifier: false, timeout: 100, clamav: {port: slow.address().port},
			}).scan(message({text: 'x', attachments}));
			assert.deepEqual(result.results.virusScanErrors, []);
		} finally {
			slow.close();
		}
	});

	it('reports attachments clamd could not scan, scanning a few at a time within the time limit', async () => {
		let active = 0;
		let most = 0;
		const slow = net.createServer({allowHalfOpen: true}, socket => {
			active++;
			most = Math.max(most, active);
			socket.on('error', () => {});
			socket.resume();
			// (a connection the client gives up on is done too)
			let done = false;
			const finish = () => {
				if (!done) {
					done = true;
					active--;
				}
			};

			socket.on('close', finish);
			socket.on('end', () => setTimeout(() => {
				finish();
				socket.end('stream: OK\0');
			}, 100));
		});
		slow.listen(0, '127.0.0.1');
		await once(slow, 'listening');
		try {
			const attachments = Array.from({length: 20}, (_, i) => ({filename: `f${i}.txt`, content: 'x'}));
			const result = await new SpamScanner({
				...offline, classifier: false, clamav: {port: slow.address().port, timeout: 250},
			}).scan(message({text: 'x', attachments}));
			assert.equal(most, 4);
			assert.ok(result.results.virusScanErrors.length >= 4);
			assert.ok(result.results.virusScanErrors.some(item => /not scanned within 250 ms/.test(item.error)));
		} finally {
			slow.close();
		}

		const down = await new SpamScanner({...offline, classifier: false, clamav: {port: 1}}).scan(message({text: 'x', attachments: [{filename: 'a.txt', content: 'x'}, {filename: '', content: 'y'}]}));
		assert.deepEqual(down.results.virusScanErrors.map(item => item.filename), ['a.txt', 'unnamed attachment']);
		assert.match(down.results.virusScanErrors[0].error, /ECONNREFUSED/);
		const refused = await new SpamScanner({
			...offline, classifier: false, clamav: {port: 1}, timeout: 1,
		}).scan(message({text: 'x', attachments: [{filename: 'a.txt', content: 'x'}]}));
		assert.equal(refused.results.virusScanErrors.length, 1);
	});

	it('bounds authentication by the time limit', async () => {
		const resolver = async () => new Promise(resolve => {
			setTimeout(() => resolve([]), 2000);
		});
		const started = Date.now();
		const result = await new SpamScanner({
			...offline, classifier: false, timeout: 200, authentication: {resolver},
		}).scan(message({text: 'hi'}), {session: {remoteAddress: '192.0.2.1', envelope: {mailFrom: {address: 'a@example.org'}}}});
		assert.ok(Date.now() - started < 1500);
		assert.equal(result.results.authentication, null);
	});

	it('classifies at most 10 images, all within one time limit', async () => {
		let asked = 0;
		const model = {
			async classify() {
				asked++;
				return [{className: 'Neutral', probability: 1}];
			},
		};
		const png = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0, 0, 0, 0]);
		const raw = message({text: 'x', attachments: Array.from({length: 15}, (_, i) => ({filename: `i${i}.png`, content: png}))});
		await new SpamScanner({...offline, classifier: false, nsfw: {model}}).scan(raw);
		assert.equal(asked, 10);
		asked = 0;
		const slow = {
			async classify() {
				asked++;
				await new Promise(resolve => {
					setTimeout(resolve, 120);
				});
				return [];
			},
		};
		const started = Date.now();
		await new SpamScanner({
			...offline, classifier: false, timeout: 200, nsfw: {model: slow},
		}).scan(raw);
		// (asked one image after another, not all ten of 120 ms each within
		//  200 ms; how many depends on how busy the machine is)
		assert.ok(Date.now() - started < 1000);
		assert.ok(asked >= 1 && asked < 10, `asked ${asked}`);
	});

	it('looks up a link that other links of one domain would push past phishing.maxHosts', async () => {
		const scanner = new SpamScanner({classifier: false, dns: {resolve4: async name => (name.startsWith('bad') ? ['0.0.0.0'] : ['192.0.2.1'])}});
		const padding = Array.from({length: 25}, (_, i) => `<a href="https://n${i}.attacker.example/"></a>`).join('');
		const result = await scanner.scan(message({text: 'Hello.', html: `${padding}<a href="https://bad.example.org/login">Sign in</a>`}));
		assert.ok(names(result).includes('MALICIOUS_DOMAIN'));
		assert.equal(result.results.uncheckedHosts, 1);
	});

	it('counts link hosts whose lookups got no answer', async () => {
		const scanner = new SpamScanner({classifier: false, timeout: 1000, dns: {timeout: 100, resolve4: () => new Promise(() => {})}});
		const result = await scanner.scan(message({text: 'https://a.example.org/ https://b.example.org/'}));
		assert.equal(result.results.timedOutHosts, 2);
	});

	it('keeps defaults for options passed as undefined', async () => {
		const scanner = new SpamScanner({
			classifier: false, timeout: undefined, phishing: {cloudflare: false, maxHosts: undefined}, session: undefined, dnsbl: null,
		});
		assert.equal(scanner.config.timeout, DEFAULTS.timeout);
		assert.equal(scanner.config.phishing.maxHosts, DEFAULTS.phishing.maxHosts);
		const many = Array.from({length: 30}, (_, i) => `https://h${i}.example${i}.net/`).join(' ');
		const result = await scanner.scan(message({text: many}), {timeout: undefined, phishing: {maxHosts: undefined}, threshold: undefined});
		assert.equal(result.results.uncheckedHosts, 5);
		assert.equal(result.threshold, DEFAULTS.threshold);
	});

	it('reads as much text for the classifier as maxLength for one message says', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const raw = message({text: 'word '.repeat(5000)});
		assert.ok((await scanner.scan(raw)).tokens.length > (await scanner.scan(raw, {maxLength: 100})).tokens.length);
	});

	it('fails at once on a classifier model that cannot be read', () => {
		assert.throws(() => new SpamScanner({classifier: path.join(temporaryDirectory(), 'missing.json')}), /ENOENT/);
		assert.throws(() => new SpamScanner({classifier: {type: 'spamscanner-classifier', version: 2, nspam: 'x'}}), /Corrupt classifier model/);
	});
});

describe('SpamScanner on links split by tags, gateways, scripts and capitals', () => {
	const scanner = new SpamScanner(offline);

	it('finds a lookalike host in HTML text split by inline tags, with or without a harmless plain text part', async () => {
		for (const html of ['<p>Sign in: https://www.pay<b></b>pa1.com/login</p>', '<b>https://www.</b>paypa1<b>.com/login</b>', '<p>Sign in: https://www.pay<span>pa1</span>.com/login</p>', '<p>Sign in: https://www.pay<wbr>pa1.com/login</p>']) {
			for (const text of [undefined, 'Hello, your monthly statement is ready.']) {
				const result = await scanner.scan(message({subject: 'Account', html, text}));
				assert.ok(names(result).includes('PHISHING_LOOKALIKE_DOMAIN'), `${html} ${text}`);
			}
		}
	});

	it('takes no zero width space between Thai or Khmer words for an invisible character', async () => {
		for (const text of ['เรียน\u200Bคุณ\u200Bสมชาย ขอบคุณ\u200Bสำหรับ\u200Bการ\u200Bสั่งซื้อ\u200Bของ\u200Bคุณ', 'សូម\u200Bអរគុណ\u200Bសម្រាប់\u200Bការ\u200Bបញ្ជាទិញ\u200Bរបស់\u200Bអ្នក។']) {
			assert.ok(!names(await scanner.scan(message({text}))).includes('INVISIBLE_CHARACTERS'), text);
		}
	});

	it('counts joiners between Latin letters as invisible characters', async () => {
		assert.ok(names(await scanner.scan(message({text: 'Buy v\u200Ci\u200Cagra and c\u200Dialis now'}))).includes('INVISIBLE_CHARACTERS'));
	});

	it('takes no newsletter link through click tracking, nor a forwarded link through a security gateway, for a deceptive one', async () => {
		const newsletter = message({
			from: 'Jane Writer <jane@janewriter.example>', subject: 'My newsletter', text: 'New post this week.', html: '<p>Hello friends, this week I wrote about gardens.</p><p><a href="https://click.convertkit-mail2.com/abc123/def456">www.janewriter.example</a> | <a href="https://click.convertkit-mail2.com/abc123/x">Unsubscribe</a></p>',
		});
		const forwarded = message({
			subject: 'Fwd: Agenda', text: 'See below.', html: '<p>Forwarded message</p><p>Agenda: <a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.example.org%2Fagenda&amp;data=05%7C02&amp;reserved=0">https://www.example.org/agenda</a></p><p>Slides: <a href="https://urldefense.com/v3/__https://www.example.net/slides__;!!AbC!dEf$">https://www.example.net/slides</a>, notes: <a href="https://protect-us.mimecast.com/s/AbCd?domain=example.com">https://www.example.com/notes</a></p>',
		});
		for (const raw of [newsletter, forwarded]) {
			assert.ok(!names(await scanner.scan(raw)).includes('DECEPTIVE_LINK'));
		}

		// (but a gateway's link that goes on to another site than it shows)
		const phishing = message({subject: 'Fwd: Invoice', text: 'See below.', html: '<p><a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.net%2Flogin&amp;data=05">https://www.paypal.com/</a></p>'});
		assert.ok(names(await scanner.scan(phishing)).includes('DECEPTIVE_LINK'));
	});

	it('takes no Russian case ending after a brand name for a word mixing scripts', async () => {
		const text = 'Привет! Купил два iPhone\'а и думаю про MacBook’и. У Windows’а свои плюсы, а у iPad\'а экран больше.';
		assert.ok(!names(await scanner.scan(message({subject: 'Ноутбук', text}))).includes('MIXED_SCRIPT_WORDS'));
	});

	it('takes no negative squared letters, emoji such as parking, for styled ones', async () => {
		const text = 'The offsite is on Friday at 10am. \u{1F17F}\uFE0F Free parking behind the building, groups \u{1F170}\uFE0F and \u{1F171}\uFE0F.';
		assert.ok(!names(await scanner.scan(message({text}))).includes('STYLED_LETTERS'));
	});

	it('finds a lookalike host written in capitals', async () => {
		assert.ok(names(await scanner.scan(message({subject: 'Account', text: 'Your account is locked. Log in at PAYPA1.COM to restore it.'}))).includes('PHISHING_LOOKALIKE_DOMAIN'));
	});
});
