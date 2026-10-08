import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {generateKeyPairSync} from 'node:crypto';
import {writeFileSync} from 'node:fs';
import path from 'node:path';
import {Readable} from 'node:stream';
import {describe, it} from 'node:test';
import {dkimSign} from 'mailauth/lib/dkim/sign.js';
import SpamScanner, {
	Classifier, DEFAULTS, VERSION, getFeatures, loadModel,
} from '../src/index.js';
import {GTUBE} from '../src/is-arbitrary.js';
import {
	HAM, SPAM, dnsServer, eicar, fakeClamd, httpServer, message, temporaryDirectory, zip,
} from './helpers/index.js';

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
		} finally {
			await dns.close();
			await malwareOnly.close();
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
			for (const test of ['SPF_FAIL', 'DMARC_FAIL', 'SELF_SPOOF']) {
				assert.ok(names(spoofed).includes(test), test);
			}

			// Options of earlier versions: enableAuthentication with authOptions.
			const legacy = new SpamScanner({
				...offline, classifier: false, enableAuthentication: true, authOptions: {
					ip: '203.0.113.5', helo: 'evil.example', sender: 'alice@example.org', hostname: 'evil.example',
				},
			});
			legacy.config.authentication = {dnsServers: [dns.server]};
			const legacyResult = await legacy.scan(raw);
			assert.ok(names(legacyResult).includes('SPF_FAIL'));
			assert.equal(legacy.config.session.resolvedClientHostname, 'evil.example');
			const plain = await new SpamScanner({...offline, classifier: false, authentication: true}).scan(raw);
			assert.equal(plain.results.authentication, null);
			// Authentication: true uses the system's resolver; the timeout keeps it short.
			const system = await new SpamScanner({
				...offline, classifier: false, authentication: true, timeout: 300,
			}).scan(raw, {session: {remoteAddress: '203.0.113.5'}});
			assert.equal(typeof system.results.authentication.score.score, 'number');
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
			assert.ok(names(await scanner.scan(message({from: 'x@friend.example', text: 'hi'}))).includes('ALLOWLISTED'));
			const legacy = new SpamScanner({
				...offline, classifier: false, enableReputation: true, reputationOptions: {apiUrl: service.url, timeout: 1000},
			});
			assert.ok(names(await legacy.scan(message({from: 'x@truth.example', text: 'hi'}))).includes('TRUTH_SOURCE'));
			assert.equal(new SpamScanner({enableReputation: true}).reputation, null);
			const combined = new SpamScanner({reputation: {apiUrl: service.url}, allowlist: ['a.example']});
			assert.deepEqual([...combined.reputation.allowlist], ['a.example']);
		} finally {
			await service.close();
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
