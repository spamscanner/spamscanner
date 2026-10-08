import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {once} from 'node:events';
import net from 'node:net';
import path from 'node:path';
import {describe, it} from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import SpamScanner from '../src/index.js';
import {GTUBE} from '../src/is-arbitrary.js';
import {
	MilterServer, PROTOCOL, cstrings, packet,
} from '../src/milter.js';
import {
	cstr, dnsServer, milterClient, temporaryDirectory,
} from './helpers/index.js';

const scanner = new SpamScanner({classifier: false, phishing: {cloudflare: false}});

function optneg({leadingSpace = false} = {}) {
	const data = Buffer.alloc(12);
	data.writeUInt32BE(6, 0);
	data.writeUInt32BE(0x1_FF, 4);
	data.writeUInt32BE(leadingSpace ? PROTOCOL.HDR_LEADSPC | PROTOCOL.NOUNKNOWN | PROTOCOL.NOHELO : 0, 8);
	return data;
}

function connect(hostname, family = '4', address = '192.0.2.1') {
	const port = Buffer.alloc(2);
	port.writeUInt16BE(25);
	return family === 'U' ? Buffer.concat([cstr(hostname), Buffer.from('U')]) : Buffer.concat([cstr(hostname), Buffer.from(family), port, cstr(address)]);
}

async function start(options, scan = scanner) {
	const server = new MilterServer(scan, options);
	const {port} = await server.listen(0);
	return {server, port};
}

// Run one SMTP transaction through the milter and return its answers.
async function transaction(port, {
	headers = [['From', 'alice@example.org'], ['Subject', 'Hello']], body = 'Hi Bob, see you at lunch.\r\n', leadingSpace = false, hostname = 'mail.example.org', family = '4', address = '192.0.2.1',
} = {}) {
	const client = await milterClient(port);
	try {
		client.send('O', optneg({leadingSpace}));
		const negotiated = await client.read();
		client.send('D', Buffer.concat([Buffer.from('C'), cstr('j', 'mx.example.com', '{daemon_name}', 'smtpd')]));
		client.send('C', connect(hostname, family, address));
		assert.equal((await client.read()).command, 'c');
		client.send('H', cstr('mail.example.org'));
		await client.read();
		client.send('M', cstr('<alice@example.org>', 'SIZE=100'));
		await client.read();
		client.send('R', cstr('<bob@example.com>'));
		await client.read();
		client.send('T');
		await client.read();
		for (const [name, value] of headers) {
			client.send('L', value === undefined ? cstr(name) : cstr(name, leadingSpace ? ` ${value}` : value));

			await client.read();
		}

		client.send('N');
		await client.read();
		client.send('B', body);
		await client.read();
		client.send('E');
		const answers = await client.readUntilFinal();
		return {negotiated, answers, client};
	} catch (error) {
		client.close();
		throw error;
	}
}

function added(answers) {
	return Object.fromEntries(answers.filter(item => item.command === 'h').map(item => cstrings(item.data)));
}

function changed(answers) {
	return answers.filter(item => item.command === 'm').map(item => [item.data.readUInt32BE(0), ...cstrings(item.data.subarray(4))]);
}

describe('milter protocol helpers', () => {
	it('encodes packets and splits NUL-terminated strings', () => {
		assert.deepEqual(packet('c'), Buffer.from([0, 0, 0, 1, 0x63]));
		assert.deepEqual(packet('h', 'a'), Buffer.from([0, 0, 0, 2, 0x68, 0x61]));
		assert.deepEqual(cstrings(Buffer.from('a\0b\0')), ['a', 'b']);
		assert.deepEqual(cstrings(Buffer.from('a\0b')), ['a', 'b']);
	});
});

describe('MilterServer', () => {
	it('adds X-Spam headers to ham and removes the ones a sender forged', async () => {
		const {server, port} = await start();
		const scans = [];
		server.on('scan', scan => scans.push(scan));
		try {
			const {negotiated, answers, client} = await transaction(port, {headers: [['From', 'alice@example.org'], ['X-Spam-Flag', 'NO'], ['X-Spam-Flag', 'NO'], ['Subject', 'Lunch'], ['X-Empty']]});
			assert.equal(negotiated.command, 'O');
			assert.equal(negotiated.data.readUInt32BE(0), 6);
			// Add headers, change headers and quarantine; nothing else.
			assert.equal(negotiated.data.readUInt32BE(4), 0x31);
			assert.equal(negotiated.data.readUInt32BE(8), 0);
			assert.deepEqual(changed(answers), [[1, 'X-Spam-Flag', ''], [2, 'X-Spam-Flag', '']]);
			assert.equal(added(answers)['X-Spam-Flag'], 'NO');
			assert.equal(answers.at(-1).command, 'c');
			assert.equal(scans[0].session.remoteAddress, '192.0.2.1');
			assert.equal(scans[0].session.resolvedClientHostname, 'mail.example.org');
			assert.equal(scans[0].session.helo, 'mail.example.org');
			assert.deepEqual(scans[0].session.envelope, {mailFrom: {address: 'alice@example.org'}, rcptTo: [{address: 'bob@example.com'}]});
			assert.equal(scans[0].result.mail.subject, 'Lunch');
			client.send('Q');
			await once(client.socket, 'end');
		} finally {
			await server.close();
		}
	});

	it('tags the subject of spam and rejects it at the reject threshold', async () => {
		const {server, port} = await start({reject: true, subjectTag: '[SPAM]'});
		try {
			const {answers, client} = await transaction(port, {body: `${GTUBE}\r\n`});
			client.close();
			assert.equal(added(answers)['X-Spam-Flag'], 'YES');
			assert.deepEqual(changed(answers), [[1, 'Subject', '[SPAM] Hello']]);
			const reply = answers.at(-1);
			assert.equal(reply.command, 'y');
			assert.equal(cstrings(reply.data)[0], '451 4.7.1 Message rejected as spam');
			// An already tagged subject, and a message with no subject.
			const tagged = await transaction(port, {headers: [['Subject', '[SPAM] Hello']], body: GTUBE});
			tagged.client.close();
			assert.deepEqual(changed(tagged.answers), []);
			const none = await transaction(port, {headers: [['From', 'x@example.org']], body: GTUBE});
			none.client.close();
			assert.deepEqual(changed(none.answers), [[1, 'Subject', '[SPAM]']]);
		} finally {
			await server.close();
		}

		const permanent = await start({reject: true, rejectCode: 550, rejectMessage: 'No\r\nthanks'});
		try {
			const {answers, client} = await transaction(permanent.port, {body: GTUBE});
			client.close();
			assert.equal(cstrings(answers.at(-1).data)[0], '550 5.7.1 No  thanks');
		} finally {
			await permanent.server.close();
		}
	});

	it('quarantines spam, or only tags it by default', async () => {
		const {server, port} = await start({quarantine: true});
		try {
			const {answers, client} = await transaction(port, {body: GTUBE});
			client.close();
			const held = answers.find(item => item.command === 'q');
			assert.match(cstrings(held.data)[0], /^Spam Scanner score \d+\.\d$/);
			assert.equal(answers.at(-1).command, 'c');
		} finally {
			await server.close();
		}

		const plain = await start();
		try {
			const {answers, client} = await transaction(plain.port, {body: GTUBE});
			client.close();
			assert.equal(added(answers)['X-Spam-Flag'], 'YES');
			assert.ok(!answers.some(item => item.command === 'q' || item.command === 'y'));
			assert.equal(answers.at(-1).command, 'c');
		} finally {
			await plain.server.close();
		}
	});

	it('keeps the leading space of header values when the MTA asks for it', async () => {
		const {server, port} = await start({subjectTag: '[SPAM]'});
		const scans = [];
		server.on('scan', scan => scans.push(scan));
		try {
			const {negotiated, answers, client} = await transaction(port, {leadingSpace: true, body: GTUBE});
			client.close();
			assert.equal(negotiated.data.readUInt32BE(8), PROTOCOL.HDR_LEADSPC | PROTOCOL.NOUNKNOWN);
			assert.equal(added(answers)['X-Spam-Flag'], ' YES');
			assert.deepEqual(changed(answers), [[1, 'Subject', ' [SPAM] Hello']]);
			assert.equal(scans[0].result.mail.subject, 'Hello');
		} finally {
			await server.close();
		}
	});

	it('adds Authentication-Results when authentication is on', async () => {
		const dns = await dnsServer({'example.org TXT': ['v=spf1 ip4:192.0.2.1 -all']});
		const checking = new SpamScanner({
			classifier: false, phishing: {cloudflare: false}, authentication: {dnsServers: [dns.server], timeout: 2000},
		});
		const {server, port} = await start({hostname: 'mx.example.com'}, checking);
		try {
			const {answers, client} = await transaction(port);
			client.close();
			assert.match(added(answers)['Authentication-Results'], /^mx\.example\.com;[\s\S]*spf=pass/);
		} finally {
			await server.close();
			await dns.close();
		}
	});

	it('reads clients with unknown, bracketed and IPv6 names, and odd addresses', async () => {
		const {server, port} = await start();
		const scans = [];
		server.on('scan', scan => scans.push(scan));
		try {
			for (const options of [{hostname: 'unknown'}, {hostname: '[192.0.2.1]'}, {hostname: 'v6.example.org', family: '6', address: 'IPv6:2001:db8::1'}, {hostname: 'local', family: 'U'}]) {
				const {client} = await transaction(port, options);
				client.close();
			}

			assert.deepEqual(scans.map(scan => scan.session.resolvedClientHostname), [undefined, undefined, 'v6.example.org', 'local']);
			assert.deepEqual(scans.map(scan => scan.session.remoteAddress), ['192.0.2.1', '192.0.2.1', '2001:db8::1', undefined]);
			// Addresses without brackets, empty ones and broken ones.
			const client = await milterClient(port);
			client.send('M', cstr('plain@example.org'));
			await client.read();
			client.send('R', cstr(''));
			await client.read();
			client.send('R');
			await client.read();
			client.send('R', cstr('a<b@example.org'));
			await client.read();
			client.send('B', 'body');
			await client.read();
			client.send('E');
			await client.readUntilFinal();
			client.close();
			assert.deepEqual(scans.at(-1).session.envelope, {mailFrom: {address: 'plain@example.org'}, rcptTo: [{address: ''}, {address: ''}, {address: 'a<b@example.org'}]});
		} finally {
			await server.close();
		}
	});

	it('limits the body it keeps, and starts over after abort and quit-new-connection', async () => {
		const {server, port} = await start({maxSize: 10});
		const scans = [];
		server.on('scan', scan => scans.push(scan));
		try {
			const client = await milterClient(port);
			client.send('C', connect('mail.example.org'));
			await client.read();
			client.send('M', cstr('<a@example.org>'));
			await client.read();
			client.send('L', cstr('Subject', 'Dropped'));
			await client.read();
			client.send('A');
			client.send('M', cstr('<b@example.org>'));
			await client.read();
			client.send('B', 'short');
			await client.read();
			client.send('B', 'this part is past the limit');
			await client.read();
			client.send('E');
			await client.readUntilFinal();
			assert.equal(scans[0].session.envelope.mailFrom.address, 'b@example.org');
			assert.equal(scans[0].result.mail.subject, undefined);
			assert.equal(scans[0].result.mail.text, 'short');
			client.send('K');
			client.send('U', cstr('NOOP'));
			assert.equal((await client.read()).command, 'c');
			client.send('E');
			await client.readUntilFinal();
			assert.equal(scans[1].session.remoteAddress, undefined);
			client.close();
		} finally {
			await server.close();
		}
	});

	it('handles packets split across reads and several packets in one read', async () => {
		const {server, port} = await start();
		try {
			const client = await milterClient(port);
			const bytes = Buffer.concat([packet('C', connect('mail.example.org')), packet('H', cstr('helo'))]);
			client.socket.write(bytes.subarray(0, 3));
			await delay(20);
			client.socket.write(bytes.subarray(3, 9));
			await delay(20);
			client.socket.write(bytes.subarray(9));
			assert.equal((await client.read()).command, 'c');
			assert.equal((await client.read()).command, 'c');
			client.close();
		} finally {
			await server.close();
		}
	});

	it('closes connections that send invalid packets', async () => {
		const {server, port} = await start();
		const errors = [];
		server.on('error', error => errors.push(error.message));
		try {
			for (const length of [0, 0x7F_FF_FF_FF]) {
				const socket = net.createConnection(port, '127.0.0.1');

				await once(socket, 'connect');
				const bytes = Buffer.alloc(5);
				bytes.writeUInt32BE(length);
				socket.write(bytes);

				await once(socket, 'close');
			}

			assert.deepEqual(errors, ['Invalid milter packet length 0', 'Invalid milter packet length 2147483647']);
		} finally {
			await server.close();
		}
	});

	it('answers tempfail, or accept if asked, when a scan fails', async () => {
		const failing = {
			async scan() {
				throw new Error('scanner broke');
			},
		};
		for (const [onError, expected] of [[undefined, 't'], ['accept', 'a']]) {
			const {server, port} = await start(onError ? {onError} : {}, failing);
			const errors = [];
			server.on('error', error => errors.push(error.message));
			try {
				const client = await milterClient(port);
				client.send('E');

				assert.equal((await client.read()).command, expected);
				client.close();
				assert.deepEqual(errors, ['scanner broke']);
			} finally {
				await server.close();
			}
		}
	});

	it('does not write to a connection the MTA already closed', async () => {
		let release;
		let started;
		const scanning = new Promise(resolve => {
			started = resolve;
		});
		const slow = {
			async scan(raw, options) {
				await new Promise(resolve => {
					release = resolve;
					started();
				});
				return scanner.scan(raw, options);
			},
		};
		const {server, port} = await start({}, slow);
		const scanned = once(server, 'scan');
		try {
			const client = await milterClient(port);
			client.send('B', 'body');
			await client.read();
			client.send('E');
			await scanning;

			client.close();
			await delay(50);
			release();
			const [{result}] = await scanned;
			assert.equal(result.isSpam, false);
		} finally {
			await server.close();
		}
	});

	it('listens on Unix sockets and numeric strings, and reports listen errors', async () => {
		const socket = path.join(temporaryDirectory(), 'milter.sock');
		const unix = new MilterServer(scanner);
		const listening = once(unix, 'listening');
		assert.equal(await unix.listen(socket), socket);
		assert.deepEqual(await listening, [socket]);
		const client = await milterClient(socket);
		client.send('H', cstr('helo'));
		assert.equal((await client.read()).command, 'c');
		client.close();
		await unix.close();

		const first = new MilterServer(scanner);
		const {port} = await first.listen('0');
		const second = new MilterServer(scanner);
		await assert.rejects(second.listen(String(port)), /EADDRINUSE/);
		// Later errors go to listeners, and are ignored without any.
		second.server.emit('error', new Error('ignored'));
		const errors = [];
		second.on('error', error => errors.push(error.message));
		second.server.emit('error', new Error('later'));
		assert.deepEqual(errors, ['later']);
		await first.close();
	});
});
