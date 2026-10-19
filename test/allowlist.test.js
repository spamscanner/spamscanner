import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {generateKeyPairSync} from 'node:crypto';
import {describe, it} from 'node:test';
import {sealMessage} from 'mailauth/lib/arc/index.js';
import {dkimSign} from 'mailauth/lib/dkim/sign.js';
import {
	authenticate, calculateAuthScore, normalizeAuthOutput, summarizeDkim,
} from '../src/auth.js';
import {normalizeIp} from '../src/dnsbl.js';
import SpamScanner from '../src/index.js';
import {ReputationChecker, matchList, trustedReputationValues} from '../src/reputation.js';
import {cpuTime} from './helpers/cpu-time.js';

// Domains with their own DKIM keys, published by a resolver for mailauth.
function domains() {
	const keys = {};
	const txt = {};
	const add = (domain, records = {}) => {
		const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
		keys[domain] = privateKey.export({type: 'pkcs1', format: 'pem'});
		txt[`s1._domainkey.${domain}`] = `v=DKIM1; k=rsa; p=${publicKey.export({type: 'spki', format: 'der'}).toString('base64')}`;
		if (records.dmarc) {
			txt[`_dmarc.${domain}`] = records.dmarc;
		}

		if (records.spf) {
			txt[domain] = records.spf;
		}
	};

	const resolver = async (name, type) => {
		const record = type === 'TXT' && txt[name.toLowerCase()];
		if (record) {
			return [[record]];
		}

		const error = new Error(`ENOTFOUND ${name}`);
		error.code = 'ENOTFOUND';
		throw error;
	};

	const sign = async (raw, domain, extra = {}) => (await dkimSign(raw, {
		canonicalization: 'relaxed/relaxed', signatureData: [{
			signingDomain: domain, selector: 's1', privateKey: keys[domain], ...extra,
		}],
	})).signatures + raw;

	return {
		add, resolver, sign, keys,
	};
}

const mail = (from, body) => `From: ${from}\r\nTo: bob@recipient.example\r\nSubject: Meeting\r\nDate: Sat, 17 Oct 2026 10:00:00 +0000\r\nMessage-ID: <${Math.random().toString(36).slice(2)}@trusted.example>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}`;
const names = result => result.tests.map(test => test.name);
const offline = {phishing: {cloudflare: false}, classifier: false};
const session = (remoteAddress, sender) => ({remoteAddress, helo: 'mx.test', envelope: {mailFrom: {address: sender}, rcptTo: []}});

describe('DKIM signatures of part of the body (l=)', () => {
	it('does not allowlist a message its domain signed only the start of', async () => {
		const dns = domains();
		dns.add('trusted.example', {dmarc: 'v=DMARC1; p=reject', spf: 'v=spf1 ip4:192.0.2.10 -all'});
		dns.add('attacker.example', {spf: 'v=spf1 ip4:198.51.100.7 -all'});
		const scanner = new SpamScanner({...offline, allowlist: ['trusted.example'], authentication: {resolver: dns.resolver}});
		// (a real message of trusted.example, signed with a body length)
		const signed = await dns.sign(mail('Alice <alice@trusted.example>', 'Short legit body.\r\n'), 'trusted.example', {maxBodyLength: 19});
		const genuine = await scanner.scan(signed, {session: session('192.0.2.10', 'alice@trusted.example')});
		assert.ok(names(genuine).includes('ALLOWLISTED'));

		// (replayed with more text after it, from the attacker's own server)
		const replayed = `${signed}Click http://login.attacker.example/ to verify your account now!\r\n`;
		const result = await scanner.scan(replayed, {session: session('198.51.100.7', 'bounce@attacker.example')});
		const {authentication} = result.results;
		// (mailauth passes the signature and DMARC, noting the bytes unsigned)
		assert.equal(authentication.dkim.status.result, 'pass');
		assert.ok(authentication.dkim.results[0].status.underSized > 0);
		assert.equal(authentication.dmarc.status.result, 'pass');
		assert.ok(authentication.dmarc.alignment.dkim.underSized > 0);
		assert.equal(authentication.dkim.aligned, null);
		assert.equal(result.results.reputation.isAllowlisted, false);
		assert.ok(!names(result).includes('ALLOWLISTED'));
	});

	it('aligns no signature of part of the body, and trusts a DMARC pass that rests on SPF', () => {
		assert.equal(summarizeDkim({results: [{signingDomain: 'trusted.example', status: {result: 'pass', aligned: 'trusted.example', underSized: 40}}]}).aligned, null);
		assert.equal(summarizeDkim({results: [{signingDomain: 'trusted.example', status: {result: 'pass', aligned: 'trusted.example', underSized: 40}}, {signingDomain: 'trusted.example', status: {result: 'pass', aligned: 'trusted.example', underSized: 0}}]}).aligned, 'trusted.example');
		const from = {from: {value: [{address: 'alice@trusted.example'}]}};
		const underSized = {
			dkim: {results: [{status: {result: 'pass', aligned: 'trusted.example', underSized: 40}}]},
			dmarc: {status: {result: 'pass'}, domain: 'trusted.example', alignment: {dkim: {result: 'trusted.example', underSized: 40}, spf: {result: false}}},
		};
		assert.deepEqual(trustedReputationValues(from, {}, underSized), []);
		const withSpf = {...underSized, dmarc: {...underSized.dmarc, alignment: {dkim: {result: 'trusted.example', underSized: 40}, spf: {result: 'trusted.example'}}}};
		assert.deepEqual(trustedReputationValues(from, {}, withSpf).map(item => item.value), ['alice@trusted.example', 'trusted.example']);
		assert.deepEqual(trustedReputationValues(from, {}, withSpf)[0].signers, ['trusted.example']);
	});
});

describe('strict DKIM alignment', () => {
	it('aligns under adkim=s, in any case and spacing, only a signature of the From domain itself', async () => {
		for (const record of ['v=DMARC1; p=reject; adkim=s', 'v=DMARC1; p=reject; adkim=S', 'v=DMARC1; p=reject; adkim= s ']) {
			const dns = domains();
			dns.add('trusted.example', {dmarc: record});
			dns.add('news.trusted.example');
			const scanner = new SpamScanner({...offline, allowlist: ['trusted.example'], authentication: {resolver: dns.resolver}});
			const other = await dns.sign(mail('<alice@trusted.example>', 'Hello, see you tomorrow.\r\n'), 'news.trusted.example');
			const result = await scanner.scan(other, {session: session('203.0.113.5', 'bounce@esp.example')});
			// (mailauth passes DMARC relaxed whatever the mode)
			assert.equal(result.results.authentication.dmarc.alignment.dkim.strict, true, record);
			assert.equal(result.results.authentication.dmarc.alignment.dkim.result, false, record);
			assert.equal(result.results.authentication.dmarc.status.result, 'fail', record);
			assert.ok(names(result).includes('DMARC_FAIL'), record);
			assert.ok(!names(result).includes('DMARC_PASS'), record);
			assert.equal(result.results.reputation.isAllowlisted, false, record);
			const own = await dns.sign(mail('<alice@trusted.example>', 'Hello, see you tomorrow.\r\n'), 'trusted.example');
			const passed = await scanner.scan(own, {session: session('203.0.113.5', 'bounce@esp.example')});
			assert.equal(passed.results.authentication.dmarc.status.result, 'pass', record);
			assert.equal(passed.results.reputation.isAllowlisted, true, record);
		}
	});

	it('aligns under aspf=s only an SPF pass of the From domain itself', () => {
		const output = spf => ({
			dkim: {headerFrom: ['alice@trusted.example'], results: []},
			dmarc: {
				status: {result: 'pass', header: {d: 'trusted.example'}}, domain: 'trusted.example', policy: 'reject', rr: 'v=DMARC1; p=reject; aspf=S', alignment: {spf: {result: spf, strict: false}, dkim: {result: false, strict: false}},
			},
		});
		const other = normalizeAuthOutput(output('bounce.trusted.example'));
		assert.deepEqual([other.dmarc.status.result, other.dmarc.alignment.spf], ['fail', {result: false, strict: true}]);
		const own = normalizeAuthOutput(output('trusted.example'));
		assert.deepEqual([own.dmarc.status.result, own.dmarc.alignment.spf], ['pass', {result: 'trusted.example', strict: true}]);
		// (without the record, mailauth's modes; without the From domain,
		//  nothing aligns)
		const given = normalizeAuthOutput({dmarc: {status: {result: 'pass'}, alignment: {spf: {result: 'trusted.example', strict: true}, dkim: {result: 'trusted.example', strict: true}}}, dkim: {results: [{signingDomain: 'trusted.example', status: {result: 'pass'}}]}});
		assert.equal(given.dmarc.status.result, 'fail');
		assert.equal(normalizeAuthOutput({dmarc: {status: {result: 'pass', header: {d: 'trusted.example'}}, rr: 'v=DMARC1; adkim=s', alignment: {spf: {result: false}, dkim: {result: 'mail.trusted.example'}}}}).dmarc.status.result, 'fail');
		const from = {from: {value: [{address: 'alice@trusted.example'}]}};
		const strictSpf = {dmarc: {status: {result: 'pass'}, domain: 'trusted.example', alignment: {dkim: {result: false, strict: true}, spf: {result: 'bounce.trusted.example', strict: true}}}};
		assert.deepEqual(trustedReputationValues(from, {}, strictSpf), []);
		const relaxedSpf = {dmarc: {status: {result: 'pass'}, domain: 'trusted.example', alignment: {dkim: {result: false}, spf: {result: 'bounce.trusted.example'}}}};
		assert.deepEqual(trustedReputationValues(from, {}, relaxedSpf)[0].signers, ['bounce.trusted.example']);
	});

	it('trusts no signature of a From address when DMARC fails', () => {
		// (as a checker that enforces strict alignment reports it)
		assert.deepEqual(trustedReputationValues({from: {value: [{address: 'alice@trusted.example'}]}}, {}, {
			dkim: {results: [{status: {result: 'pass', aligned: 'news.trusted.example'}}], aligned: 'news.trusted.example'},
			dmarc: {status: {result: 'fail'}, domain: 'trusted.example'},
		}), []);
	});
});

describe('list matching of long names', () => {
	it('matches a From domain of 50,000 labels in linear time', async () => {
		const host = `${'a.'.repeat(50_000)}spam.example`;
		const list = new Set(['example', 'spam.example']);
		const started = cpuTime();
		// (by its last 127 labels: a denylist still matches it)
		assert.equal(matchList(`x@${host}`, list), 'spam.example');
		assert.equal(matchList(`x@${'a.'.repeat(50_000)}other.example`, list), null);
		assert.equal(matchList(host, list, {hostnamesOnly: true}), null);
		const checker = new ReputationChecker({denylist: ['spam.example'], allowlist: ['spam.example']});
		const result = await checker.check([`x@${host}`]);
		assert.equal(result.isDenylisted, true);
		assert.deepEqual(result.allowlisted, {});
		assert.ok(cpuTime() - started < 1500);
	});

	it('denylists any name under a listed domain, and allowlists only hostnames', async () => {
		const list = new Set(['evil.example', 'xn--bcher-kva.example']);
		for (const host of [`${'x'.repeat(64)}.evil.example`, `${`${'a'.repeat(60)}.`.repeat(5)}evil.example`, 'a_b!.evil.example', 'x.a!b.evil.example', 'mail.evil.example']) {
			assert.equal(matchList(`deals@${host}`, list), 'evil.example', host);
		}

		// (an international name that is no hostname, in ASCII too)
		assert.equal(matchList('deals@a!b.bücher.example', list), 'xn--bcher-kva.example');
		// (a parent domain more than 253 characters long is not read)
		assert.equal(matchList(`${'a'.repeat(250)}.evil.example`, new Set([`${'a'.repeat(250)}.evil.example`.slice(1)])), null);
		assert.equal(matchList('a_b!.evil.example', list, {hostnamesOnly: true}), null);
		assert.equal(matchList(`${'x'.repeat(64)}.evil.example`, list, {hostnamesOnly: true}), null);
		assert.equal(matchList('mail.evil.example', list, {hostnamesOnly: true}), 'evil.example');
		const scanner = new SpamScanner({...offline, denylist: ['evil.example']});
		for (const host of [`${'x'.repeat(64)}.evil.example`, 'a_b!.evil.example']) {
			const result = await scanner.scan(`From: Promo <deals@${host}>\r\nTo: you@recipient.example\r\nSubject: Offer\r\n\r\nBuy now.\r\n`);
			assert.equal(result.results.reputation.isDenylisted, true, host);
		}

		const checker = new ReputationChecker({allowlist: ['evil.example']});
		assert.equal((await checker.check(['a_b!.evil.example'])).isAllowlisted, false);
	});
});

describe('IPv6 list entries', () => {
	it('matches IPv6 addresses in any form', async () => {
		for (const [ip, canonical] of [
			['2001:0DB8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
			['2001:db8:0:0:1:0:0:1', '2001:db8::1:0:0:1'],
			['2001:0:0:1:0:0:0:1', '2001:0:0:1::1'],
			['2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'],
			['0:0:0:0:0:0:0:0', '::'],
			['1:0:0:0:0:0:0:0', '1::'],
			['64:ff9b::c000:201', '64:ff9b::192.0.2.1'],
			['::FFFF:0:c000:201', '::ffff:0:192.0.2.1'],
			['::ffff:1:c000:201', '::ffff:1:c000:201'],
			['0:0:0:1:ffff:0:1:1', '::1:ffff:0:1:1'],
			['64:ff9b:0:0:0:1:1:1', '64:ff9b::1:1:1'],
			['64:1::1', '64:1::1'],
			['fe80::0001%eth0', 'fe80::1'],
		]) {
			assert.equal(normalizeIp(ip), canonical, ip);
		}

		const checker = new ReputationChecker({allowlist: ['2001:0db8::0001'], denylist: ['2001:DB8:0:0:0:0:0:2']});
		assert.equal((await checker.check(['2001:db8::1'])).isAllowlisted, true);
		assert.equal((await checker.check(['2001:db8:0::0:2'])).isDenylisted, true);
		assert.equal(matchList('2001:db8:0:0::1', checker.allowlist), '2001:db8::1');
	});
});

describe('authentication points of forwarded mail', () => {
	const failed = (policy, extra = {}) => ({
		dkim: {status: {result: 'none'}}, spf: {status: {result: 'fail'}}, dmarc: {status: {result: 'fail'}, policy}, arc: {status: {result: 'none'}}, ...extra,
	});

	it('scores a DMARC failure by the domain\'s policy, and SPF on top of it only for policy none', () => {
		assert.deepEqual(calculateAuthScore(failed('reject')).tests, [{name: 'DMARC_FAIL', score: 3.5}]);
		assert.deepEqual(calculateAuthScore(failed('quarantine')).tests, [{name: 'DMARC_FAIL', score: 3.5}]);
		assert.deepEqual(calculateAuthScore(failed(null)).tests, [{name: 'DMARC_FAIL', score: 3.5}]);
		assert.deepEqual(calculateAuthScore({...failed('reject'), spf: {status: {result: 'softfail'}}}).tests, [{name: 'DMARC_FAIL', score: 3.5}]);
		// (policy none is never cheaper to spoof than no DMARC record)
		assert.deepEqual(calculateAuthScore(failed('none')).tests, [{name: 'SPF_FAIL', score: 2}, {name: 'DMARC_FAIL', score: 1}]);
		assert.deepEqual(calculateAuthScore(failed(' None ')).tests, [{name: 'SPF_FAIL', score: 2}, {name: 'DMARC_FAIL', score: 1}]);
		assert.deepEqual(calculateAuthScore(failed('none'), {dmarcFailNone: 2}).tests, [{name: 'SPF_FAIL', score: 2}, {name: 'DMARC_FAIL', score: 2}]);
		assert.deepEqual(calculateAuthScore({spf: {status: {result: 'fail'}}, dmarc: {status: {result: 'none'}}}).tests, [{name: 'SPF_FAIL', score: 2}]);
		// (an ARC seal anyone could add changes nothing, and earns nothing)
		assert.deepEqual(calculateAuthScore(failed('reject', {arc: {status: {result: 'pass'}, sealer: 'attacker.example', trusted: false}})).tests, [{name: 'DMARC_FAIL', score: 3.5}]);
		assert.deepEqual(calculateAuthScore(failed('reject', {dkim: {status: {result: 'fail'}}, arc: {status: {result: 'pass'}, trusted: true}})).tests, [{name: 'ARC_PASS', score: -0.5}]);
		assert.deepEqual(calculateAuthScore(failed('reject', {arc: {status: {result: 'fail'}, trusted: true}})).tests.map(test => test.name), ['DMARC_FAIL', 'ARC_FAIL']);
	});

	it('reads a policy with spaces or capitals as RFC 7489 does', async () => {
		const dns = domains();
		dns.add('nonep.example', {dmarc: 'v=DMARC1; p= None ', spf: 'v=spf1 ip4:192.0.2.10 -all'});
		const scanner = new SpamScanner({...offline, authentication: {resolver: dns.resolver}});
		const result = await scanner.scan(mail('<billing@nonep.example>', 'Please see the invoice.\r\n'), {session: session('203.0.113.9', 'billing@nonep.example')});
		assert.equal(result.results.authentication.dmarc.policy, 'none');
		assert.equal(result.results.authentication.dmarc.p, 'none');
		assert.deepEqual(result.results.authentication.score.tests, [{name: 'SPF_FAIL', score: 2}, {name: 'DMARC_FAIL', score: 1}]);
	});

	it('gives no points for SPF and DMARC failing on mail a trusted forwarder sealed as passing', async () => {
		const dns = domains();
		dns.add('trusted.example', {dmarc: 'v=DMARC1; p=reject', spf: 'v=spf1 ip4:192.0.2.10 -all'});
		dns.add('lists.example', {spf: 'v=spf1 ip4:198.51.100.20 -all'});
		dns.add('attacker.example', {spf: 'v=spf1 ip4:198.51.100.7 -all'});
		const signed = await dns.sign(mail('<alice@trusted.example>', 'The minutes are below.\r\n'), 'trusted.example');
		// (a mailing list adds a footer, which breaks the signature, and seals
		//  what it received)
		const edited = signed.replace('below.', 'below.\r\n-- \r\nlist footer');
		const seal = async (domain, raw, results = 'dkim=pass header.d=trusted.example; spf=pass smtp.mailfrom=trusted.example; dmarc=pass header.from=trusted.example') => (await sealMessage(Buffer.from(raw), {
			signingDomain: domain, selector: 's1', privateKey: dns.keys[domain], authResults: `mx.${domain}; ${results}`, cv: 'none', i: 1,
		})).toString() + raw;
		const forwarded = await seal('lists.example', edited);
		const options = {
			ip: '198.51.100.20', sender: 'alice@trusted.example', resolver: dns.resolver, trustedArcSealers: ['lists.example', 'not a domain'],
		};
		const trusted = await authenticate(forwarded, options);
		assert.deepEqual([trusted.spf.status.result, trusted.dmarc.status.result, trusted.dmarc.policy, trusted.arc.status.result, trusted.arc.sealer, trusted.arc.trusted], ['fail', 'fail', 'reject', 'pass', 'lists.example', true]);
		assert.deepEqual(calculateAuthScore(trusted).tests, [{name: 'ARC_PASS', score: -0.5}]);
		const untrusted = await authenticate(forwarded, {...options, trustedArcSealers: undefined});
		assert.equal(untrusted.arc.trusted, false);
		assert.deepEqual(calculateAuthScore(untrusted).tests, [{name: 'DMARC_FAIL', score: 3.5}]);

		// (a spoof the trusted list relayed, which failed DMARC when it got it)
		const relayed = await seal('lists.example', mail('<ceo@trusted.example>', 'Wire the money now.\r\n'), 'dkim=none; spf=fail smtp.mailfrom=trusted.example; dmarc=fail header.from=trusted.example');
		const spoof = await authenticate(relayed, options);
		assert.deepEqual([spoof.arc.status.result, spoof.arc.sealer, spoof.arc.trusted], ['pass', 'lists.example', false]);
		assert.deepEqual(calculateAuthScore(spoof).tests, [{name: 'DMARC_FAIL', score: 3.5}]);

		// (spoofing a domain whose policy is reject still scores in full, with
		//  a seal of the attacker's own)
		const spoofed = await seal('attacker.example', mail('<alice@trusted.example>', 'Verify your account now.\r\n'));
		const attack = await authenticate(spoofed, {...options, ip: '198.51.100.7', sender: 'alice@trusted.example'});
		assert.equal(attack.arc.status.result, 'pass');
		assert.equal(attack.arc.trusted, false);
		assert.deepEqual(calculateAuthScore(attack).tests, [{name: 'DMARC_FAIL', score: 3.5}]);

		// (sent to the list from the domain of its member: not a self spoof when
		//  the trusted list sealed it as passing, a self spoof otherwise)
		const member = {...session('198.51.100.20', 'alice@trusted.example'), envelope: {mailFrom: {address: 'alice@trusted.example'}, rcptTo: [{address: 'bob@trusted.example'}]}};
		const scan = (raw, trust, client = member) => new SpamScanner({...offline, authentication: {resolver: dns.resolver, trustedArcSealers: trust}}).scan(raw, {session: client});
		assert.ok(!names(await scan(forwarded, ['lists.example'])).includes('SELF_SPOOF'));
		assert.ok(names(await scan(forwarded, undefined)).includes('SELF_SPOOF'));
		assert.ok(names(await scan(relayed, ['lists.example'])).includes('SELF_SPOOF'));
		assert.ok(names(await scan(spoofed, ['lists.example'], {...member, remoteAddress: '198.51.100.7'})).includes('SELF_SPOOF'));
	});

	it('trusts an ARC set by its seal, of the same domain as its message signature, and the results it sealed', () => {
		const output = (sealDomain, results, from = 'alice@trusted.example') => {
			const arc = {
				status: {result: 'pass'}, signature: {signingDomain: 'lists.example'}, authenticationResults: results,
			};
			// (as mailauth gives it: not enumerable)
			Object.defineProperty(arc, 'chain', {value: [{'arc-seal': {parsed: {d: {value: sealDomain}}}}]});
			return {arc, dkim: {headerFrom: [from]}};
		};

		const trust = {trustedArcSealers: ['lists.example']};
		const dmarcPass = {dmarc: {result: 'pass', header: {from: 'trusted.example'}}};
		assert.deepEqual(normalizeAuthOutput(output('lists.example', dmarcPass), trust).arc, {status: {result: 'pass'}, sealer: 'lists.example', trusted: true});
		// (a seal signed again by another domain over the list's message
		//  signature)
		assert.deepEqual(normalizeAuthOutput(output('attacker.example', dmarcPass), trust).arc, {status: {result: 'pass'}, sealer: null, trusted: false});
		// (a DKIM or SPF pass aligned with the From domain, as relaxed DMARC)
		assert.equal(normalizeAuthOutput(output('lists.example', {dkim: [{result: 'pass', header: {d: 'mail.trusted.example'}}]}), trust).arc.trusted, true);
		assert.equal(normalizeAuthOutput(output('lists.example', {spf: {result: 'pass', smtp: {mailfrom: 'bounce@trusted.example'}}}), trust).arc.trusted, true);
		for (const results of [
			{dmarc: {result: 'pass', header: {from: 'other.example'}}},
			{dkim: [{result: 'pass', header: {d: 'other.example'}}], spf: {result: 'fail', smtp: {mailfrom: 'bounce@trusted.example'}}},
			{dkim: {result: 'pass'}},
			null,
		]) {
			assert.equal(normalizeAuthOutput(output('lists.example', results), trust).arc.trusted, false, JSON.stringify(results));
		}

		// (with no single From address, or none given, nothing is vouched for)
		assert.equal(normalizeAuthOutput({...output('lists.example', dmarcPass), dkim: {headerFrom: ['a@trusted.example', 'b@trusted.example']}}, trust).arc.trusted, false);
		assert.equal(normalizeAuthOutput(output('lists.example', dmarcPass, 'no-domain'), trust).arc.trusted, false);
		// (results passed in: no chain, no sealer)
		assert.deepEqual(normalizeAuthOutput({arc: {status: {result: 'pass'}, signature: {signingDomain: 'lists.example'}}}, trust).arc, {status: {result: 'pass'}, sealer: null, trusted: false});
		assert.equal(normalizeAuthOutput({...output('lists.example', dmarcPass), arc: {...output('lists.example', dmarcPass).arc, status: {result: 'fail'}}}, trust).arc.sealer, null);
		assert.equal(normalizeAuthOutput(output('mx.lists.example', dmarcPass), trust).arc.sealer, null);
	});
});

describe('messages without one From address', () => {
	it('fails DMARC for a message whose DMARC mailauth skips', async () => {
		const dns = domains();
		dns.add('bank.example', {dmarc: 'v=DMARC1; p=reject', spf: 'v=spf1 ip4:192.0.2.10 -all'});
		dns.add('attacker.example', {spf: 'v=spf1 ip4:203.0.113.9 -all'});
		const scanner = new SpamScanner({...offline, authentication: {resolver: dns.resolver}});
		const body = '\r\nPlease review the attached statement.\r\n';
		const cases = {
			'two addresses': 'From: Bank <ceo@bank.example>, x@attacker.example\r\n',
			'two fields': 'From: x@attacker.example\r\nFrom: Bank <ceo@bank.example>\r\n',
			'encoded word': 'From: Bank =?utf-8?Q?=3Cceo=40bank.example=3E?=\r\n',
			group: 'From: Bank: ceo@bank.example;\r\n',
			none: 'Sender: ceo@bank.example\r\n',
		};
		for (const [name, header] of Object.entries(cases)) {
			const result = await scanner.scan(`${header}To: you@recipient.example\r\nSubject: Statement\r\n${body}`, {session: session('203.0.113.9', 'x@attacker.example')});
			assert.equal(result.results.authentication.dmarc.status.result, 'fail', name);
			assert.deepEqual(result.results.authentication.score.tests, [{name: 'SPF_PASS', score: -0.5}, {name: 'DMARC_FAIL', score: 3.5}], name);
		}

		const one = await scanner.scan(`From: x@attacker.example\r\nTo: you@recipient.example\r\nSubject: Statement\r\n${body}`, {session: session('203.0.113.9', 'x@attacker.example')});
		assert.equal(one.results.authentication.dmarc.status.result, 'none');
		assert.equal(normalizeAuthOutput({dkim: {headerFrom: []}, dmarc: false}).dmarc.status.comment, '0 From addresses');
	});
});

describe('authentication credit for signatures of part of the body', () => {
	it('gives no DKIM_PASS or DMARC_PASS for an l= replay', async () => {
		const dns = domains();
		dns.add('trusted.example', {dmarc: 'v=DMARC1; p=reject', spf: 'v=spf1 ip4:192.0.2.10 -all'});
		dns.add('attacker.example', {spf: 'v=spf1 ip4:198.51.100.7 -all'});
		const scanner = new SpamScanner({...offline, authentication: {resolver: dns.resolver}});
		const signed = await dns.sign(mail('Alice <alice@trusted.example>', 'Short legit body.\r\n'), 'trusted.example', {maxBodyLength: 19});
		const replayed = await scanner.scan(`${signed}Your account is locked.\r\n`, {session: session('198.51.100.7', 'bounce@attacker.example')});
		assert.deepEqual(replayed.results.authentication.score.tests, [{name: 'SPF_PASS', score: -0.5}]);
		// (with SPF aligned too, DMARC rests on more than the signature)
		const direct = await scanner.scan(`${signed}And more.\r\n`, {session: session('192.0.2.10', 'alice@trusted.example')});
		assert.deepEqual(direct.results.authentication.score.tests.map(test => test.name), ['SPF_PASS', 'DMARC_PASS']);
		const whole = await scanner.scan(signed, {session: session('198.51.100.7', 'bounce@attacker.example')});
		assert.deepEqual(whole.results.authentication.score.tests.map(test => test.name), ['DKIM_PASS', 'SPF_PASS', 'DMARC_PASS']);
	});
});
