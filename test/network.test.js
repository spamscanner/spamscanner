import assert from 'node:assert/strict';
import {Buffer, File} from 'node:buffer';
import {generateKeyPairSync} from 'node:crypto';
import {once} from 'node:events';
import {writeFileSync} from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {describe, it} from 'node:test';
import {dkimSign} from 'mailauth/lib/dkim/sign.js';
import {
	authenticate, calculateAuthScore, createResolver, formatAuthResultsHeader, normalizeAuthOutput, summarizeAuth, summarizeDkim,
} from '../src/auth.js';
import {clamdAddress, ping, scanBuffer} from '../src/clamav.js';
import {
	CLOUDFLARE_FAMILY, DnsChecker, KNOWN_LISTS, isListedAnswer, reverseName,
} from '../src/dnsbl.js';
import {
	dnsServer, eicar, fakeClamd, message, temporaryDirectory,
} from './helpers/index.js';

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

	it('looks up IPs and domains over real DNS, caching answers', async () => {
		const dns = await dnsServer({
			'1.2.0.192.zen.spamhaus.org A': ['127.0.0.4'],
			'1.2.0.192.bl.example A': ['127.255.255.254'],
			'evil.example.dbl.spamhaus.org A': ['127.0.1.2'],
			'slow.example.dbl.spamhaus.org A': 'timeout',
		});
		try {
			const checker = new DnsChecker({servers: [dns.server], timeout: 300});
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
			const checker = new DnsChecker({timeout: 500});
			const options = {malwareServers: [malware.server], familyServers: [family.server]};
			assert.deepEqual(await checker.checkCloudflare(['malware.example', 'adult.example', 'fine.example', '192.0.2.1'], options), [{host: 'malware.example', category: 'malware'}, {host: 'adult.example', category: 'adult'}]);
			assert.deepEqual(await checker.checkCloudflare(['adult.example'], {...options, adult: false}), []);
			assert.equal(CLOUDFLARE_FAMILY[0], '1.1.1.3');
		} finally {
			await malware.close();
			await family.close();
		}
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

	async function signed(raw, domain = 'example.org') {
		const result = await dkimSign(raw, {signatureData: [{signingDomain: domain, selector: 's1', privateKey: privateKey.export({type: 'pkcs1', format: 'pem'})}]});
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
			assert.deepEqual(calculateAuthScore(spoofed).tests.map(test => test.name), ['SPF_FAIL', 'DMARC_FAIL']);
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
		assert.deepEqual(calculateAuthScore(result, {arcFail: 0}).tests.map(test => test.name), ['DKIM_FAIL', 'SPF_SOFTFAIL', 'DMARC_FAIL']);
		assert.deepEqual(calculateAuthScore(undefined), {score: 0, tests: []});
		assert.equal(summarizeAuth(undefined), 'spf=none dkim=none dmarc=none arc=none');
	});
});
