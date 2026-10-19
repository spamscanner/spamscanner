import assert from 'node:assert/strict';
import {Buffer, File} from 'node:buffer';
import {createHash, generateKeyPairSync} from 'node:crypto';
import {once} from 'node:events';
import {writeFileSync} from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import {describe, it} from 'node:test';
import {dkimSign} from 'mailauth/lib/dkim/sign.js';
import {
	MAX_DKIM_SIGNATURES, authenticate, calculateAuthScore, createResolver, formatAuthResultsHeader, limitResolver, normalizeAuthOutput, summarizeAuth, summarizeDkim,
} from '../src/auth.js';
import {clamdAddress, ping, scanBuffer} from '../src/clamav.js';
import {
	CLOUDFLARE_FAMILY, DnsChecker, KNOWN_LISTS, isListedAnswer, isLookupName, normalizeIp, reverseName,
} from '../src/dnsbl.js';
import {requestJson} from '../src/http.js';
import {boundedForAuth} from '../src/parse.js';
import {ReputationChecker, matchList} from '../src/reputation.js';
import {
	dnsServer, eicar, fakeClamd, message, temporaryDirectory,
} from './helpers/index.js';
import {cpuTime} from './helpers/cpu-time.js';

describe('clamd client', () => {
	it('scans over TCP and Unix sockets', async () => {
		const tcp = await fakeClamd();
		const socketPath = path.join(temporaryDirectory(), 'clamd.sock');
		const unix = await fakeClamd({path: socketPath});
		try {
			assert.deepEqual(await scanBuffer(Buffer.from('hello'), {port: tcp.port}), {infected: false, viruses: [], reply: 'stream: OK'});
			const infected = await scanBuffer(eicar(), {socket: socketPath, chunkSize: 10});
			assert.equal(infected.infected, true);
			assert.deepEqual(infected.viruses, ['Eicar-Test-Signature']);
			assert.equal(await ping({host: '127.0.0.1', port: tcp.port}), true);
			assert.equal(await ping({socketPaths: [socketPath]}), true);
		} finally {
			await tcp.close();
			await unix.close();
		}
	});

	it('reports clamd errors, missing sockets and silence', async () => {
		const broken = await fakeClamd({reply: 'INSTREAM size limit exceeded. ERROR\0'});
		const silent = net.createServer(() => {});
		silent.listen(0, '127.0.0.1');
		await once(silent, 'listening');
		try {
			await assert.rejects(scanBuffer(Buffer.from('x'), {port: broken.port}), /size limit exceeded/);
			await assert.rejects(scanBuffer(Buffer.from('x'), {port: silent.address().port, timeout: 200}), /did not answer within 200 ms/);
			await assert.rejects(scanBuffer(Buffer.from('x'), {socketPaths: []}), /No clamd socket found/);
			await assert.rejects(scanBuffer(Buffer.from('x'), {port: 1}), /ECONNREFUSED/);
			assert.equal(await ping({socketPaths: []}), false);
			assert.equal(await ping({port: 1}), false);
		} finally {
			await broken.close();
			silent.close();
		}

		const empty = await fakeClamd({reply: ''});
		try {
			await assert.rejects(scanBuffer(Buffer.from('x'), {port: empty.port}), /clamd: no reply/);
		} finally {
			await empty.close();
		}
	});

	it('finds clamd\'s address', () => {
		assert.deepEqual(clamdAddress({socket: '/s'}), {path: '/s'});
		assert.deepEqual(clamdAddress({host: 'h'}), {host: 'h', port: 3310});
		assert.deepEqual(clamdAddress({port: '9'}), {host: '127.0.0.1', port: 9});
		const file = path.join(temporaryDirectory(), 'exists');
		writeFileSync(file, '');
		assert.deepEqual(clamdAddress({socketPaths: ['/nope', file]}), {path: file});
		assert.equal(clamdAddress({socketPaths: ['/nope']}), null);
		assert.ok(clamdAddress() === null || typeof clamdAddress().path === 'string');
	});
});

describe('DNS blocklists and filtering resolvers', () => {
	it('builds reversed query names', () => {
		assert.equal(reverseName('192.0.2.1', 'zen.spamhaus.org'), '1.2.0.192.zen.spamhaus.org');
		assert.equal(reverseName('2001:db8::1', 'zen.spamhaus.org'), `1.0.0.0.${'0.'.repeat(20)}8.b.d.0.1.0.0.2.zen.spamhaus.org`);
		assert.equal(reverseName('::1', 'z').split('.').length, 33);
		assert.equal(reverseName('fe80::', 'z').split('.')[31], 'f');
		assert.equal(reverseName('not an ip', 'z'), null);
	});

	it('tells listings from refusal codes', () => {
		assert.equal(isListedAnswer('127.0.0.2', 'zen.spamhaus.org'), true);
		assert.equal(isListedAnswer('127.255.255.254', 'zen.spamhaus.org'), false);
		assert.equal(isListedAnswer('127.0.0.255', 'multi.surbl.org'), false);
		assert.equal(isListedAnswer('127.0.0.1', 'multi.uribl.com'), false);
		assert.equal(isListedAnswer('127.0.0.2', 'multi.uribl.com'), true);
		assert.equal(isListedAnswer('10.0.0.1', 'x'), false);
		assert.ok(KNOWN_LISTS.ip['zen.spamhaus.org']);
	});

	it('takes the answers SURBL, URIBL and Spamhaus give blocked or wrong queries for no listing', async () => {
		// (SURBL answers 127.0.0.1 to a resolver it blocks, as URIBL does)
		for (const zone of ['multi.surbl.org', 'MULTI.SURBL.ORG.', 'multi.uribl.com']) {
			assert.equal(isListedAnswer('127.0.0.1', zone), false, zone);
			assert.equal(isListedAnswer('127.0.0.4', zone), true, zone);
		}

		// (Spamhaus: a misspelled zone, a public resolver, too many queries,
		//  an address looked up in the DBL)
		for (const address of ['127.255.255.252', '127.255.255.254', '127.255.255.255']) {
			assert.equal(isListedAnswer(address, 'zen.spamhaus.org'), false, address);
			assert.equal(isListedAnswer(address, 'dbl.spamhaus.org'), false, address);
		}

		assert.equal(isListedAnswer('127.0.1.255', 'dbl.spamhaus.org'), false);
		assert.equal(isListedAnswer('127.0.1.255', 'key.dbl.dq.spamhaus.net'), false);
		assert.equal(isListedAnswer('127.0.1.2', 'dbl.spamhaus.org'), true);
		// (127.0.0.1 elsewhere, and in a zone only named like SURBL's, is a listing)
		assert.equal(isListedAnswer('127.0.0.1', 'bl.example'), true);
		assert.equal(isListedAnswer('127.0.0.1', 'notsurbl.org'), true);
		const dns = await dnsServer({'link.example.multi.surbl.org A': ['127.0.0.1'], 'spam.example.multi.surbl.org A': ['127.0.0.1', '127.0.0.8']});
		try {
			const checker = new DnsChecker({servers: [dns.server], timeout: 3000});
			assert.deepEqual(await checker.checkDomains(['link.example', 'spam.example'], ['multi.surbl.org']), [{zone: 'multi.surbl.org', value: 'spam.example', answers: ['127.0.0.8']}]);
		} finally {
			await dns.close();
		}
	});

	it('looks up IPs and domains over real DNS, caching answers', async () => {
		const dns = await dnsServer({
			'1.2.0.192.zen.spamhaus.org A': ['127.0.0.4'],
			'1.2.0.192.bl.example A': ['127.255.255.254'],
			'evil.example.dbl.spamhaus.org A': ['127.0.1.2'],
			'slow.example.dbl.spamhaus.org A': 'timeout',
		});
		try {
			const checker = new DnsChecker({servers: [dns.server], timeout: 1000});
			assert.deepEqual(await checker.checkIp('192.0.2.1', ['zen.spamhaus.org', 'bl.example', 'clean.example']), [{zone: 'zen.spamhaus.org', value: '192.0.2.1', answers: ['127.0.0.4']}]);
			assert.deepEqual(await checker.checkIp('not-an-ip', ['zen.spamhaus.org']), []);
			assert.deepEqual(await checker.checkDomains(['evil.example', 'good.example', 'slow.example', '192.0.2.1'], ['dbl.spamhaus.org']), [{zone: 'dbl.spamhaus.org', value: 'evil.example', answers: ['127.0.1.2']}]);
			const before = dns.queries.length;
			await checker.checkIp('192.0.2.1', ['zen.spamhaus.org']);
			assert.equal(dns.queries.length, before);
			// Timeouts are not cached.
			await checker.checkDomains(['slow.example'], ['dbl.spamhaus.org']);
			assert.equal(dns.queries.filter(query => query.startsWith('slow.')).length, 2);
		} finally {
			await dns.close();
		}
	});

	it('asks the malware resolver first, then the family resolver', async () => {
		const malware = await dnsServer({'malware.example A': ['0.0.0.0'], 'adult.example A': ['192.0.2.9'], 'fine.example A': ['192.0.2.10']});
		const family = await dnsServer({'adult.example A': ['0.0.0.0'], 'fine.example A': ['192.0.2.10']});
		try {
			const checker = new DnsChecker({timeout: 3000});
			const options = {malwareServers: [malware.server], familyServers: [family.server]};
			assert.deepEqual(await checker.checkCloudflare(['malware.example', 'adult.example', 'fine.example', '192.0.2.1'], options), [{host: 'malware.example', category: 'malware'}, {host: 'adult.example', category: 'adult'}]);
			assert.deepEqual(await checker.checkCloudflare(['adult.example'], {...options, adult: false}), []);
			assert.equal(CLOUDFLARE_FAMILY[0], '1.1.1.3');
		} finally {
			await malware.close();
			await family.close();
		}
	});

	it('does not ask about an address or a name no lookup could answer', async () => {
		const asked = [];
		const checker = new DnsChecker({
			async resolve4(name) {
				asked.push(name);
				return [];
			},
		});
		for (const name of ['[2001:db8::1]', '2001:db8::1', '192.0.2.1', `${'a'.repeat(64)}.example`, 'a..example', `${'a.'.repeat(130)}example`, '']) {
			assert.equal(isLookupName(name), false, name);
		}

		assert.equal(isLookupName('mail.example.org.'), true);
		assert.equal(isLookupName(null), false);
		assert.deepEqual(await checker.checkCloudflare(['[2001:db8::1]', `${'a'.repeat(64)}.example`, 'fine.example']), []);
		assert.deepEqual(asked, ['fine.example', 'fine.example']);
	});

	it('keeps its cache bounded and accepts a custom lookup', async () => {
		const lookups = [];
		const checker = new DnsChecker({
			cacheSize: 2,
			async resolve4(name) {
				lookups.push(name);
				if (name.startsWith('fail')) {
					throw new Error('SERVFAIL');
				}

				return ['127.0.0.2'];
			},
		});
		for (const name of ['a', 'b', 'c', 'fail']) {
			await checker.resolve4(name);
		}

		assert.equal(checker.cache.size, 2);
		assert.deepEqual(await checker.resolve4('fail'), []);
		assert.equal(checker.resolver(null), checker.resolver(null));
	});
});

describe('authentication', () => {
	const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
	const dkimKey = `v=DKIM1; k=rsa; p=${publicKey.export({type: 'spki', format: 'der'}).toString('base64')}`;

	// (one signing time: mailauth otherwise reads the clock for t= when it
	//  signs and again when it writes the header, and a second may pass)
	async function signed(raw, domain = 'example.org') {
		const result = await dkimSign(raw, {signTime: new Date(), signatureData: [{signingDomain: domain, selector: 's1', privateKey: privateKey.export({type: 'pkcs1', format: 'pem'})}]});
		return result.signatures + raw;
	}

	it('checks SPF, DKIM and DMARC over real DNS', async () => {
		const dns = await dnsServer({
			'example.org TXT': ['v=spf1 ip4:192.0.2.10 -all'],
			's1._domainkey.example.org TXT': [dkimKey],
			'_dmarc.example.org TXT': ['v=DMARC1; p=reject'],
		});
		try {
			const raw = await signed(message({from: 'alice@example.org', subject: 'Signed'}));
			const pass = await authenticate(raw, {
				ip: '192.0.2.10', helo: 'mx.example.org', sender: 'alice@example.org', mta: 'mx.test', dnsServers: [dns.server], timeout: 2000,
			});
			assert.equal(pass.spf.status.result, 'pass');
			assert.equal(pass.dkim.status.result, 'pass');
			assert.equal(pass.dkim.aligned, 'example.org');
			assert.equal(pass.dmarc.status.result, 'pass');
			assert.match(pass.headers, /Authentication-Results: mx\.test/);
			assert.match(formatAuthResultsHeader(pass), /^mx\.test;[\s\S]*spf=pass[\s\S]*dmarc=pass/);
			assert.match(formatAuthResultsHeader(pass, 'mx.example.com'), /^mx\.example\.com;[\s\S]*dkim=pass/);
			assert.equal(summarizeAuth(pass), 'spf=pass dkim=pass dmarc=pass arc=none');
			assert.ok(calculateAuthScore(pass).score < 0);

			const spoofed = await authenticate(Buffer.from(message({from: 'alice@example.org'})), {ip: '203.0.113.5', sender: 'alice@example.org', dnsServers: [dns.server]});
			assert.equal(spoofed.spf.status.result, 'fail');
			assert.equal(spoofed.dkim.status.result, 'none');
			assert.equal(spoofed.dmarc.status.result, 'fail');
			// (SPF failing adds nothing to DMARC failing)
			assert.deepEqual(calculateAuthScore(spoofed).tests, [{name: 'DMARC_FAIL', score: 3.5}]);
		} finally {
			await dns.close();
		}
	});

	it('checks a header that would take mailauth too long cut down, and fails DMARC for a From field too long to read whole', async () => {
		const dns = await dnsServer({
			'example.org TXT': ['v=spf1 ip4:192.0.2.10 -all'],
			's1._domainkey.example.org TXT': [dkimKey],
			'_dmarc.example.org TXT': ['v=DMARC1; p=reject'],
		});
		const check = raw => authenticate(raw, {
			ip: '192.0.2.10', helo: 'mx.example.org', sender: 'alice@example.org', dnsServers: [dns.server], timeout: 2000,
		});
		try {
			// (40,000 folded lines took mailauth 13 seconds; unfolded, the
			//  relaxed signature still verifies)
			const raw = await signed(message({from: 'alice@example.org', subject: 'Signed'}));
			const started = cpuTime();
			const folded = await check(`X-Filler: x${'\r\n x'.repeat(40_000)}\r\n${raw}`);
			assert.ok(cpuTime() - started < 2000);
			assert.equal(folded.dkim.status.result, 'pass');
			assert.equal(folded.dmarc.status.result, 'pass');
			// (two From addresses fail DMARC; the first alone, all mailauth would
			//  read of the field cut, would pass it with SPF)
			const two = `alice@example.org, ${'b,'.repeat(2500)}evil@attacker.example`;
			const cut = await check(message({from: two}));
			assert.equal(cut.spf.status.result, 'pass');
			assert.equal(cut.dmarc.status.result, 'fail');
			assert.match(formatAuthResultsHeader(cut), /dmarc=fail/);
		} finally {
			await dns.close();
		}
	});

	it('gives mailauth the File global on Node.js 18, which lacks it', async () => {
		const original = globalThis.File;
		delete globalThis.File;
		try {
			await authenticate(Buffer.from(message({})), {ip: '192.0.2.1', dnsServers: ['127.0.0.1:1'], timeout: 200});
			assert.equal(globalThis.File, File);
		} finally {
			globalThis.File = original;
		}
	});

	it('does nothing without a client IP and fails soft on errors', async () => {
		const none = await authenticate('From: a@example.org\r\n\r\nx');
		assert.equal(none.error, 'No client IP address given');
		assert.equal(none.spf.status.result, 'none');
		const broken = await authenticate('From: a@example.org\r\n\r\nx', {
			ip: '192.0.2.1',
			resolver() {
				throw new TypeError('resolver exploded');
			},
		});
		assert.notEqual(broken.spf.status.result, 'pass');
		const thrown = await authenticate(null, {ip: '192.0.2.1', resolver: async () => [], sender: {}});
		assert.match(thrown.error, /indexOf/);
		assert.equal(thrown.spf.status.result, 'none');
	});

	it('resolves with timeouts and rejects unsupported record types', async () => {
		const dns = await dnsServer({'slow.example A': 'timeout', 'fast.example A': ['192.0.2.1']});
		try {
			const resolver = createResolver(300, [dns.server]);
			assert.deepEqual(await resolver('fast.example'), ['192.0.2.1']);
			await assert.rejects(resolver('slow.example', 'A'), error => ['ETIMEOUT', 'ECANCELLED'].includes(error.code));
			await assert.rejects(resolver('x.example', 'HINFO'), {code: 'ENOTIMP'});
			assert.equal(typeof createResolver(), 'function');
		} finally {
			await dns.close();
		}
	});

	// (a resolver that finds nothing, counting what it is asked)
	function countingResolver(delay = 0) {
		const asked = [];
		const resolver = async (name, type) => {
			asked.push(`${type} ${name}`);
			if (delay > 0) {
				await new Promise(resolve => {
					setTimeout(resolve, delay);
				});
			}

			const error = new Error('not found');
			error.code = 'ENOTFOUND';
			throw error;
		};

		return {asked, resolver};
	}

	function manySignatures(count, body) {
		const algorithms = ['rsa-sha256', 'rsa-sha1', 'ed25519-sha256'];
		const canonicalizations = ['simple/simple', 'relaxed/relaxed', 'relaxed/simple', 'simple/relaxed'];
		let headers = '';
		for (let i = 0; i < count; i++) {
			// (each with the hash of the start of the body it signs, so its key is
			//  looked up)
			const length = body.length - (i % 50);
			const bodyHash = createHash(algorithms[i % 3] === 'rsa-sha1' ? 'sha1' : 'sha256').update(body.slice(0, length)).digest('base64');
			headers += `DKIM-Signature: v=1; a=${algorithms[i % 3]}; c=${canonicalizations[i % 4]};\r\n\td=d${i}.signer.test; s=s; h=from; l=${length};\r\n\tbh=${bodyHash}; b=AAAA\r\n`;
		}

		return Buffer.from(`${headers}From: a@sender.test\r\nTo: b@example.org\r\nSubject: x\r\n\r\n${body}`);
	}

	it('checks only the first DKIM signatures of a message with hundreds', async () => {
		const {asked, resolver} = countingResolver();
		const body = `${'y'.repeat(998)}\r\n`.repeat(200);
		const result = await authenticate(manySignatures(400, body), {ip: '192.0.2.1', sender: 'a@sender.test', resolver});
		assert.equal(result.dkim.results.length, MAX_DKIM_SIGNATURES);
		assert.equal(asked.filter(query => query.includes('._domainkey.')).length, MAX_DKIM_SIGNATURES);
		assert.match(result.dkim.status.comment, /^d0\.signer\.test: /);
	});

	it('keeps the first DKIM-Signature fields, folded lines and all, and the body', () => {
		const field = i => `DKIM-Signature: v=1; d=d${i}.test;\r\n\ts=s; b=AAAA\r\n`;
		const many = Array.from({length: MAX_DKIM_SIGNATURES + 2}, (_, i) => field(i)).join('');
		const raw = Buffer.from(`Received: x\r\n${many}dkim-signature : v=1; d=late.test\r\nFrom: a@b.test\r\n\r\n${field(99)}`);
		const kept = Array.from({length: MAX_DKIM_SIGNATURES}, (_, i) => field(i)).join('');
		assert.deepEqual(boundedForAuth(raw), {raw: Buffer.from(`Received: x\r\n${kept}From: a@b.test\r\n\r\n${field(99)}`), fromCut: false});
		const few = Buffer.from(`${kept}From: a@b.test\r\n\r\nbody`);
		assert.equal(boundedForAuth(few).raw, few);
	});

	it('stops a message\'s DNS lookups at its deadline and query budget', async () => {
		// (each lookup takes 100 ms; none is sent or waited for 100 ms after
		//  the timeout, so the DKIM keys, looked up one after another, are not
		//  all found, nor SPF and DMARC checked)
		const slow = countingResolver(100);
		const result = await authenticate(manySignatures(8, 'hello\r\n'), {
			ip: '192.0.2.1', sender: 'a@sender.test', resolver: slow.resolver, timeout: 50,
		});
		const sent = slow.asked.length;
		assert.ok(sent <= 3, `${sent} lookups sent in 150 ms of 100 ms lookups`);
		assert.equal(result.dkim.status.result, 'temperror');
		await new Promise(resolve => {
			setTimeout(resolve, 150);
		});
		assert.equal(slow.asked.length, sent);

		const budget = countingResolver();
		await authenticate(manySignatures(8, 'hello\r\n'), {
			ip: '192.0.2.1', sender: 'a@sender.test', resolver: budget.resolver, maxDnsQueries: 3,
		});
		assert.equal(budget.asked.length, 3);

		const answer = async () => ['192.0.2.1'];
		const limited = limitResolver(answer, {maxQueries: 1});
		assert.deepEqual(await limited('a.test', 'A'), ['192.0.2.1']);
		await assert.rejects(limited('a.test', 'A'), {code: 'ETIMEOUT', message: /More than 1 DNS lookups/});
		await assert.rejects(limitResolver(answer, {deadline: Date.now() - 1})('a.test', 'A'), {code: 'ETIMEOUT'});
		const hanging = limitResolver(() => new Promise(() => {}), {deadline: Date.now() + 20});
		await assert.rejects(hanging('a.test', 'A'), {code: 'ETIMEOUT'});
		assert.deepEqual(await limitResolver(answer)('a.test'), ['192.0.2.1']);
	});

	it('leaves room for SPF at the limits of RFC 7208', async () => {
		let queries = 0;
		const resolver = async (name, type) => {
			queries++;
			if (type === 'TXT' && name === 'sender.test') {
				return [[`v=spf1 ${Array.from({length: 10}, (_, i) => `mx:m${i}.sender.test`).join(' ')} -all`]];
			}

			if (type === 'MX') {
				return Array.from({length: 10}, (_, i) => ({exchange: `h${i}.${name}`, priority: i}));
			}

			if (type === 'A' || type === 'AAAA') {
				return type === 'A' ? ['198.51.100.1'] : ['2001:db8::1'];
			}

			const error = new Error('not found');
			error.code = 'ENOTFOUND';
			throw error;
		};

		const result = await authenticate(Buffer.from('From: a@sender.test\r\n\r\nhi\r\n'), {ip: '192.0.2.1', sender: 'a@sender.test', resolver});
		assert.equal(result.spf.status.result, 'fail');
		assert.ok(queries > 100, `${queries} queries`);
	});

	it('writes at most 8 KiB of Authentication-Results, whole results only', () => {
		const long = i => ` dkim=neutral (no key) header.i=@${'d'.repeat(900)}${i}.test header.s=s`;
		const results = Array.from({length: 20}, (_, i) => long(i));
		const headers = `Authentication-Results: mx;\r\n${results.join(';\r\n')};\r\n spf=fail smtp.mailfrom=a.test;\r\n dkim=fail header.i=@${'x'.repeat(9000)}\r\n`;
		const value = formatAuthResultsHeader({headers}, 'mx.example');
		assert.ok(value.length <= 8192, `${value.length} characters`);
		assert.match(value, /^mx\.example;\r\n dkim=neutral/);
		assert.match(value, /;\r\n spf=fail smtp\.mailfrom=a\.test$/);
		assert.doesNotMatch(value, /x{100}/);
		for (const part of value.split(';').slice(1)) {
			assert.match(part, /^\r\n (?:dkim=neutral \(no key\) header\.i=@d{900}\d+\.test header\.s=s|spf=fail smtp\.mailfrom=a\.test)$/);
		}
	});

	it('fills in what mailauth leaves out', () => {
		const empty = normalizeAuthOutput();
		assert.equal(empty.spf.status.result, 'none');
		assert.equal(empty.headers, '');
		const full = normalizeAuthOutput({
			spf: {status: {result: 'pass'}, domain: 'a.example'}, dmarc: {
				status: {result: 'pass'}, policy: 'reject', domain: 'a.example', p: 'reject',
			}, arc: {status: {result: 'pass'}}, bimi: {status: {result: 'pass'}, location: 'https://a.example/logo.svg'}, receivedChain: [1], headers: 'X: y',
		});
		assert.deepEqual([full.spf.domain, full.dmarc.policy, full.dmarc.p, full.arc.status.result, full.bimi.location, full.receivedChain.length, full.headers], ['a.example', 'reject', 'reject', 'pass', 'https://a.example/logo.svg', 1, 'X: y']);
	});

	it('summarizes DKIM results', () => {
		assert.equal(summarizeDkim({}).status.result, 'none');
		assert.equal(summarizeDkim({results: [{status: {result: 'none'}}]}).status.result, 'none');
		assert.equal(summarizeDkim({results: [{signingDomain: 'a.example', status: {result: 'fail', comment: 'bad sig'}}]}).status.result, 'fail');
		assert.equal(summarizeDkim({results: [{status: {result: 'temperror'}}]}).status.result, 'temperror');
		assert.equal(summarizeDkim({results: [{status: {result: 'neutral'}}, {status: {result: 'policy'}}]}).status.result, 'neutral');
		assert.match(summarizeDkim({results: [{}]}).status.comment, /\?: invalid/);
		assert.equal(summarizeDkim({results: [{signingDomain: 'a', status: {result: 'pass'}}]}).aligned, null);
	});

	it('formats headers and scores without mailauth\'s own headers', () => {
		const result = {
			dkim: {status: {result: 'fail'}, results: [{signingDomain: 'a.example', status: {result: 'fail'}}]}, spf: {status: {result: 'softfail'}, domain: 'b.example'}, dmarc: {status: {result: 'fail'}, domain: 'c.example'}, arc: {status: {result: 'fail'}},
		};
		assert.equal(formatAuthResultsHeader(result, 'mx'), 'mx;\r\n\tdkim=fail header.d=a.example;\r\n\tspf=softfail smtp.mailfrom=b.example;\r\n\tdmarc=fail header.from=c.example;\r\n\tarc=fail');
		assert.equal(formatAuthResultsHeader({headers: 'Received-SPF: none\r\n'}), 'spamscanner;\r\n\tdkim=none;\r\n\tspf=none;\r\n\tdmarc=none;\r\n\tarc=none');
		assert.equal(formatAuthResultsHeader(undefined), 'spamscanner;\r\n\tdkim=none;\r\n\tspf=none;\r\n\tdmarc=none;\r\n\tarc=none');
		assert.deepEqual(calculateAuthScore(result, {arcFail: 0}).tests.map(test => test.name), ['DKIM_FAIL', 'DMARC_FAIL']);
		assert.deepEqual(calculateAuthScore(undefined), {score: 0, tests: []});
		assert.equal(summarizeAuth(undefined), 'spf=none dkim=none dmarc=none arc=none');
	});
});

describe('IPv4 addresses in IPv6 form', () => {
	it('looks up a mapped IPv4 address as IPv4, without an IPv6 zone', () => {
		for (const ip of ['::ffff:192.0.2.1', '::FFFF:c000:201', '0:0:0:0:0:ffff:192.0.2.1']) {
			assert.equal(normalizeIp(ip), '192.0.2.1', ip);
			assert.equal(reverseName(ip, 'zen.spamhaus.org'), '1.2.0.192.zen.spamhaus.org', ip);
		}

		assert.equal(normalizeIp('fe80::1%eth0'), 'fe80::1');
		assert.equal(reverseName('fe80::1%eth0', 'z'), `1.${'0.'.repeat(28)}8.e.f.z`);
		// (an IPv4 address at the end of another IPv6 address is two groups of it)
		assert.equal(reverseName('64:ff9b::192.0.2.1', 'z'), `1.0.2.0.0.0.0.c.${'0.'.repeat(16)}b.9.f.f.4.6.0.0.z`);
		assert.equal(normalizeIp('2001:DB8::1'), '2001:db8::1');
		assert.equal(normalizeIp('mail.example'), 'mail.example');
	});

	it('matches a mapped client address against an IPv4 allowlist entry', async () => {
		const checker = new ReputationChecker({allowlist: ['192.0.2.1'], denylist: ['::ffff:198.51.100.7']});
		assert.equal((await checker.check(['::ffff:192.0.2.1'])).isAllowlisted, true);
		assert.equal((await checker.check(['198.51.100.7'])).isDenylisted, true);
		assert.equal(matchList('::ffff:192.0.2.1', new Set(['192.0.2.1'])), '192.0.2.1');
	});
});

describe('lookups without an answer', () => {
	it('tells no answer from not listed, and caches only answers', async () => {
		let calls = 0;
		const checker = new DnsChecker({
			timeout: 100,
			async resolve4(name) {
				calls++;
				if (name === 'gone.example') {
					throw Object.assign(new Error('queryA ENOTFOUND'), {code: 'ENOTFOUND'});
				}

				if (name === 'empty.example') {
					throw Object.assign(new Error('queryA ENODATA'), {code: 'ENODATA'});
				}

				if (name === 'broken.example') {
					throw Object.assign(new Error('queryA ESERVFAIL'), {code: 'ESERVFAIL'});
				}

				return new Promise(() => {});
			},
		});
		assert.deepEqual(await checker.answer('gone.example'), []);
		assert.deepEqual(await checker.answer('empty.example'), []);
		assert.equal(await checker.answer('broken.example'), null);
		assert.equal(await checker.answer('silent.example'), null);
		assert.deepEqual(await checker.resolve4('broken.example'), []);
		assert.deepEqual([...checker.cache.keys()], ['|gone.example', '|empty.example']);
		calls = 0;
		await checker.answer('gone.example');
		await checker.answer('broken.example');
		assert.equal(calls, 1);
	});

	it('lists the hosts Cloudflare\'s resolvers did not answer for', async () => {
		const checker = new DnsChecker({
			timeout: 100,
			async resolve4(name, servers) {
				if (name.startsWith('silent') || (name.startsWith('quiet') && servers[0] === CLOUDFLARE_FAMILY[0])) {
					throw Object.assign(new Error('queryA ETIMEOUT'), {code: 'ETIMEOUT'});
				}

				return name.startsWith('bad') ? ['0.0.0.0'] : ['192.0.2.1'];
			},
		});
		const found = await checker.checkCloudflare(['bad.example', 'silent.example', 'quiet.example', 'fine.example']);
		assert.deepEqual(found, [{host: 'bad.example', category: 'malware'}]);
		assert.deepEqual(found.unanswered, ['silent.example', 'quiet.example']);
		assert.deepEqual((await checker.checkCloudflare(['quiet.example'], {adult: false})).unanswered, []);
		assert.equal(JSON.stringify(found), '[{"host":"bad.example","category":"malware"}]');
	});
});

describe('deadlines', () => {
	it('gives clamd one deadline for the whole scan, however it trickles', async () => {
		const trickle = net.createServer({allowHalfOpen: true}, socket => {
			socket.on('error', () => {});
			socket.resume();
			const timer = setInterval(() => socket.write(' '), 50);
			socket.on('close', () => clearInterval(timer));
		});
		trickle.listen(0, '127.0.0.1');
		await once(trickle, 'listening');
		try {
			const started = Date.now();
			await assert.rejects(scanBuffer(Buffer.from('x'), {port: trickle.address().port, timeout: 300}), /did not answer within 300 ms/);
			assert.ok(Date.now() - started < 1000);
		} finally {
			trickle.close();
		}
	});

	it('notices a connection dropped in the middle of a reply', async () => {
		const server = http.createServer((request, response) => {
			response.writeHead(200, {'content-length': 1000, 'content-type': 'application/json'});
			response.write('{"a":');
			setTimeout(() => request.socket.destroy(), 50);
		});
		server.listen(0, '127.0.0.1');
		await once(server, 'listening');
		try {
			const started = Date.now();
			await assert.rejects(requestJson('GET', `http://127.0.0.1:${server.address().port}/`, null, {timeout: 5000}), /aborted|ECONNRESET/);
			assert.ok(Date.now() - started < 2000);
		} finally {
			server.close();
		}
	});
});
