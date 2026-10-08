import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {once} from 'node:events';
import {readFileSync} from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {describe, it} from 'node:test';
import SpamScanner from '../src/index.js';
import {GTUBE} from '../src/is-arbitrary.js';
import {
	SPAMD_EXIT_CODES, createSpamdServer, parseRequest, report,
} from '../src/spamd.js';
import {message, temporaryDirectory} from './helpers/index.js';

const scanner = () => new SpamScanner({classifier: false, phishing: {cloudflare: false}});
const spam = message({subject: 'Test', text: GTUBE});
const ham = message({subject: 'Lunch', text: 'See you at noon.'});

async function start(options, scan = scanner()) {
	const server = createSpamdServer(scan, options);
	server.listen(0, '127.0.0.1');
	await once(server, 'listening');
	return {
		port: server.address().port,
		close: () => new Promise(resolve => {
			server.close(resolve);
		}),
	};
}

// Send a request as spamc does and read the whole answer.
async function request(port, command, body = '', {headers = {}, length = true, end = true} = {}) {
	const socket = net.createConnection(port, '127.0.0.1');
	await once(socket, 'connect');
	const chunks = [];
	socket.on('data', chunk => chunks.push(chunk));
	const content = Buffer.from(body);
	const lines = [`${command} SPAMC/1.5`, ...(length ? [`Content-length: ${content.length}`] : []), ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`)];
	socket.write(Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n\r\n`), content]));
	if (end) {
		socket.end();
	}

	await once(socket, 'close');
	const text = Buffer.concat(chunks).toString('utf8');
	const split = text.indexOf('\r\n\r\n');
	const [status, ...fields] = text.slice(0, split === -1 ? text.length : split).split('\r\n');
	return {
		status, headers: Object.fromEntries(fields.map(line => line.split(': '))), body: split === -1 ? '' : text.slice(split + 4), text,
	};
}

describe('spamd protocol', () => {
	it('parses request lines and headers', () => {
		assert.deepEqual(parseRequest('CHECK SPAMC/1.5\r\nContent-length: 10\r\nUser: bob'), {command: 'CHECK', version: '1.5', headers: {'content-length': '10', user: 'bob'}});
		assert.throws(() => parseRequest('FROB SPAMC/1.5'), error => error.code === SPAMD_EXIT_CODES.EX_PROTOCOL);
		assert.throws(() => parseRequest('CHECK HTTP/1.1'), /Bad request line/);
		assert.throws(() => parseRequest('CHECK SPAMC/1.5\r\nno colon'), /Bad header line/);
	});

	it('answers CHECK, SYMBOLS, REPORT and REPORT_IFSPAM', async () => {
		const {port, close} = await start();
		try {
			const check = await request(port, 'CHECK', spam);
			assert.equal(check.status, 'SPAMD/1.5 0 EX_OK');
			assert.match(check.headers.Spam, /^True ; \d+\.\d \/ 5\.0$/);
			assert.equal(check.body, '');
			const clean = await request(port, 'CHECK', ham);
			assert.match(clean.headers.Spam, /^False ; /);
			const symbols = await request(port, 'SYMBOLS', spam);
			assert.match(symbols.body, /^GTUBE(?:,\w+)*$/);
			assert.equal(Number(symbols.headers['Content-length']), symbols.body.length);
			const full = await request(port, 'REPORT', spam);
			assert.match(full.body, /has identified this incoming email as possible spam[\s\S]*1000\.0 GTUBE/);
			assert.match((await request(port, 'REPORT', ham)).body, /has scanned this incoming email/);
			assert.match((await request(port, 'REPORT_IFSPAM', spam)).body, /GTUBE/);
			assert.equal((await request(port, 'REPORT_IFSPAM', ham)).body, '');
		} finally {
			await close();
		}
	});

	it('answers PROCESS with the message and HEADERS with its header block', async () => {
		const {port, close} = await start({subjectTag: '[SPAM]'});
		try {
			const processed = await request(port, 'PROCESS', spam);
			assert.match(processed.body, /^X-Spam-Flag: YES\r\n[\s\S]*^Subject: \[SPAM] Test\r\n[\s\S]*\r\n\r\n/m);
			assert.ok(processed.body.endsWith(spam.slice(spam.indexOf('\r\n\r\n') + 4)));
			assert.equal(Number(processed.headers['Content-length']), Buffer.byteLength(processed.body));
			const headers = await request(port, 'HEADERS', ham);
			assert.match(headers.body, /^X-Spam-Flag: NO\r\n[\s\S]*^Subject: Lunch\r\n[\s\S]*\r\n\r\n$/m);
			assert.ok(!headers.body.includes('See you at noon'));
		} finally {
			await close();
		}
	});

	it('answers PING and SKIP, and reads messages without a Content-length', async () => {
		const {port, close} = await start();
		try {
			assert.equal((await request(port, 'PING', '', {length: false})).status, 'SPAMD/1.5 0 PONG');
			assert.equal((await request(port, 'SKIP', '', {length: false})).text, '');
			// Without Content-length, the end of the input ends the message.
			assert.match((await request(port, 'CHECK', spam, {length: false})).headers.Spam, /^True/);
		} finally {
			await close();
		}
	});

	it('learns from TELL only when allowed, and saves the model', async () => {
		const closed = await start();
		try {
			const refused = await request(closed.port, 'TELL', spam, {headers: {'Message-class': 'spam', Set: 'local'}});
			assert.match(refused.status, /^SPAMD\/1\.5 77 /);
		} finally {
			await closed.close();
		}

		const modelPath = path.join(temporaryDirectory(), 'model.json');
		const learning = scanner();
		const open = await start({allowTell: true, modelPath}, learning);
		try {
			const told = await request(open.port, 'TELL', spam, {headers: {'Message-class': 'spam', Set: 'local'}});
			assert.equal(told.status, 'SPAMD/1.5 0 EX_OK');
			assert.equal(told.headers.DidSet, 'local');
			assert.equal(learning.getClassifier().nspam, 1);
			assert.equal(JSON.parse(readFileSync(modelPath, 'utf8')).nspam, 1);
			const removed = await request(open.port, 'TELL', spam, {headers: {'Message-class': 'spam', Remove: 'local'}});
			assert.equal(removed.headers.DidRemove, 'local');
			assert.equal(learning.getClassifier().nspam, 0);
			assert.match((await request(open.port, 'TELL', spam, {headers: {'Message-class': 'maybe'}})).status, /^SPAMD\/1\.5 64 /);
			assert.match((await request(open.port, 'TELL', spam)).status, /^SPAMD\/1\.5 64 /);
		} finally {
			await open.close();
		}

		const memory = scanner();
		const unsaved = await start({allowTell: true}, memory);
		try {
			await request(unsaved.port, 'TELL', ham, {headers: {'Message-class': 'ham'}});
			assert.equal(memory.getClassifier().nham, 1);
		} finally {
			await unsaved.close();
		}
	});

	it('refuses bad requests', async () => {
		const {port, close} = await start({maxSize: 100});
		try {
			assert.match((await request(port, 'FROB', 'x')).status, /^SPAMD\/1\.5 76 Bad request line/);
			assert.match((await request(port, 'CHECK', 'x', {headers: {Bogus: ''}, length: false})).status, /^SPAMD\/1\.5 0 /);
			assert.match((await request(port, 'CHECK', 'x', {headers: {Compress: 'zlib'}})).status, /^SPAMD\/1\.5 76 Compressed/);
			assert.match((await request(port, 'CHECK', 'x', {headers: {'Content-length': '-1'}, length: false})).status, /^SPAMD\/1\.5 76 Bad Content-length/);
			assert.match((await request(port, 'CHECK', 'x'.repeat(500))).status, /^SPAMD\/1\.5 65 Message larger than 100 bytes/);
			// A head that never ends, and a connection closed before the head.
			const socket = net.createConnection(port, '127.0.0.1');
			await once(socket, 'connect');
			const chunks = [];
			socket.on('data', chunk => chunks.push(chunk));
			socket.write(`CHECK SPAMC/1.5\r\nX: ${'a'.repeat(70 * 1024)}`);
			await once(socket, 'close');
			assert.match(Buffer.concat(chunks).toString(), /^SPAMD\/1\.5 76 Request head too long/);
			const early = net.createConnection(port, '127.0.0.1');
			await once(early, 'connect');
			const answer = [];
			early.on('data', chunk => answer.push(chunk));
			early.end('CHECK SPAMC/1.5\r\n');
			await once(early, 'close');
			assert.match(Buffer.concat(answer).toString(), /^SPAMD\/1\.5 76 Incomplete request/);
			// A client that resets its connection does not stop the server.
			const reset = net.createConnection(port, '127.0.0.1');
			await once(reset, 'connect');
			reset.write('CHECK SPAMC/1.5\r\nContent-length: 50\r\n\r\npartial');
			reset.resetAndDestroy();
			assert.equal((await request(port, 'PING', '', {length: false})).status, 'SPAMD/1.5 0 PONG');
		} finally {
			await close();
		}
	});

	it('answers EX_SOFTWARE when a scan fails, and ignores data after the request', async () => {
		const {port, close} = await start({}, {
			async scan() {
				throw new Error('scanner\nbroke');
			},
		});
		try {
			assert.equal((await request(port, 'CHECK', ham)).status, 'SPAMD/1.5 70 scanner broke');
			// Data sent after a complete request is ignored.
			const socket = net.createConnection(port, '127.0.0.1');
			await once(socket, 'connect');
			const chunks = [];
			socket.on('data', chunk => chunks.push(chunk));
			socket.write('PING SPAMC/1.5\r\n\r\n');
			await once(socket, 'data');
			socket.end('trailing data');
			await once(socket, 'close');
			assert.equal(Buffer.concat(chunks).toString(), 'SPAMD/1.5 0 PONG\r\n\r\n');
		} finally {
			await close();
		}
	});

	it('writes a SpamAssassin-style report', () => {
		const text = report({
			isSpam: false, score: -1, threshold: 5, tests: [{name: 'BAYES_00', score: -2.5, description: 'Classifier spam probability 0.0%'}],
		});
		assert.match(text, /\(-1\.0 points, 5\.0 required\)[\s\S]*-2\.5 BAYES_00 {15}Classifier spam probability 0\.0%\r\n$/);
	});
});
