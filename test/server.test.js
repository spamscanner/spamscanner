import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {once} from 'node:events';
import {readFileSync} from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {describe, it} from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import SpamScanner from '../src/index.js';
import {GTUBE} from '../src/is-arbitrary.js';
import {
	createHttpServer, createTcpServer, serializeResult, sessionFromQuery,
} from '../src/server.js';
import {VERSION} from '../src/version.js';
import {message, temporaryDirectory} from './helpers/index.js';

const scanner = () => new SpamScanner({classifier: false, phishing: {cloudflare: false}});
const ham = message({subject: 'Lunch', text: 'See you at noon by the fountain.'});
const spam = message({subject: 'Test', text: GTUBE});

async function listen(server) {
	server.listen(0, '127.0.0.1');
	await once(server, 'listening');
	const {port} = server.address();
	return {
		url: `http://127.0.0.1:${port}`,
		port,
		close: () => new Promise(resolve => {
			server.close(resolve);
			server.closeAllConnections?.();
		}),
	};
}

// Send a raw message over TCP and read the answer.
async function tcp(port, data, {end = true} = {}) {
	const socket = net.createConnection(port, '127.0.0.1');
	await once(socket, 'connect');
	const chunks = [];
	socket.on('data', chunk => chunks.push(chunk));
	socket.write(data);
	if (end) {
		socket.end();
	}

	await once(socket, 'close');
	return Buffer.concat(chunks).toString('utf8');
}

describe('result and query helpers', () => {
	it('drops the parsed message and tokens unless verbose, and the received chain', () => {
		const result = {
			isSpam: false, mail: {subject: 'Hi'}, tokens: ['hi'], results: {authentication: {spf: {}, receivedChain: [1]}},
		};
		assert.deepEqual(serializeResult(result), {isSpam: false, results: {authentication: {spf: {}}}});
		assert.deepEqual(serializeResult({...result, mail: undefined, results: {}}, {verbose: true}), {
			isSpam: false, results: {}, tokens: ['hi'], subject: null,
		});
		assert.equal(serializeResult(result, {verbose: true}).subject, 'Hi');
	});

	it('reads the SMTP session from query parameters', () => {
		assert.deepEqual(sessionFromQuery(new URLSearchParams('ip=192.0.2.1&hostname=mx.example.org&helo=mx&from=a@example.org&to=b@example.com,%20c@example.com&to=d@example.com')), {
			remoteAddress: '192.0.2.1',
			resolvedClientHostname: 'mx.example.org',
			helo: 'mx',
			envelope: {mailFrom: {address: 'a@example.org'}, rcptTo: [{address: 'b@example.com'}, {address: 'c@example.com'}, {address: 'd@example.com'}]},
		});
		assert.deepEqual(sessionFromQuery(new URLSearchParams('to=b@example.com')).envelope, {mailFrom: {address: ''}, rcptTo: [{address: 'b@example.com'}]});
		assert.deepEqual(sessionFromQuery(new URLSearchParams('from=')).envelope, {mailFrom: {address: ''}, rcptTo: []});
		assert.deepEqual(sessionFromQuery(new URLSearchParams('')), {});
	});
});

describe('HTTP server', () => {
	it('reports health and scans messages', async () => {
		const server = await listen(createHttpServer(scanner()));
		try {
			const health = await fetch(`${server.url}/health`);
			assert.deepEqual(await health.json(), {ok: true, version: VERSION});
			assert.equal(health.headers.get('cache-control'), 'no-store');
			const scan = await fetch(`${server.url}/scan?ip=192.0.2.1&from=a@example.org&to=b@example.com`, {method: 'POST', body: spam});
			const result = await scan.json();
			assert.equal(result.isSpam, true);
			assert.equal(result.action, 'reject');
			assert.equal(result.mail, undefined);
			assert.equal(result.tokens, undefined);
			const verbose = await (await fetch(`${server.url}/scan?verbose=1`, {method: 'POST', body: ham})).json();
			assert.equal(verbose.subject, 'Lunch');
			assert.ok(verbose.tokens.includes('fountain'));
		} finally {
			await server.close();
		}
	});

	it('returns the message with headers added from /check', async () => {
		const server = await listen(createHttpServer(scanner()));
		try {
			const checked = await fetch(`${server.url}/check?subjectTag=%5BSPAM%5D`, {method: 'POST', body: spam});
			assert.equal(checked.headers.get('content-type'), 'message/rfc822');
			assert.equal(checked.headers.get('x-spam-flag'), 'YES');
			assert.equal(checked.headers.get('x-spam-action'), 'reject');
			assert.match(checked.headers.get('x-spam-score'), /^\d+\.\d$/);
			const text = await checked.text();
			assert.match(text, /^X-Spam-Flag: YES\r\n/m);
			assert.match(text, /^Subject: \[SPAM] Test\r\n/m);
			const clean = await (await fetch(`${server.url}/check?subjectTag=%5BSPAM%5D`, {method: 'POST', body: ham})).text();
			assert.match(clean, /^X-Spam-Flag: NO\r\n/m);
			assert.match(clean, /^Subject: Lunch\r\n/m);
			const untagged = await (await fetch(`${server.url}/check`, {method: 'POST', body: spam})).text();
			assert.match(untagged, /^Subject: Test\r\n/m);
		} finally {
			await server.close();
		}
	});

	it('refuses wrong methods, unknown paths and large messages', async () => {
		const server = await listen(createHttpServer(scanner(), {maxSize: 1000}));
		try {
			const get = await fetch(`${server.url}/scan`);
			assert.equal(get.status, 405);
			assert.equal(get.headers.get('allow'), 'POST');
			assert.equal((await fetch(`${server.url}/nope`, {method: 'POST', body: ham})).status, 404);
			const large = await fetch(`${server.url}/scan`, {method: 'POST', body: 'x'.repeat(5000)});
			assert.equal(large.status, 413);
			assert.deepEqual(await large.json(), {error: 'Message larger than 1000 bytes'});
			// The server keeps working after a client goes away mid-message.
			const socket = net.createConnection(server.port, '127.0.0.1');
			await once(socket, 'connect');
			socket.write('POST /scan HTTP/1.1\r\nHost: x\r\nContent-Length: 500\r\n\r\npartial');
			await delay(50);
			socket.destroy();
			await delay(50);
			assert.equal((await fetch(`${server.url}/health`)).status, 200);
		} finally {
			await server.close();
		}
	});

	it('requires the token, and learns only when it has one', async () => {
		const modelPath = path.join(temporaryDirectory(), 'model.json');
		const learning = scanner();
		const server = await listen(createHttpServer(learning, {token: 'secret', modelPath}));
		try {
			assert.equal((await fetch(`${server.url}/health`)).status, 200);
			const missing = await fetch(`${server.url}/scan`, {method: 'POST', body: ham});
			assert.equal(missing.status, 401);
			assert.equal(missing.headers.get('www-authenticate'), 'Bearer');
			assert.equal((await fetch(`${server.url}/scan`, {method: 'POST', body: ham, headers: {authorization: 'Bearer wrong!'}})).status, 401);
			assert.equal((await fetch(`${server.url}/scan`, {method: 'POST', body: ham, headers: {authorization: 'Bearer secret'}})).status, 200);
			const learned = await fetch(`${server.url}/learn/spam`, {method: 'POST', body: spam, headers: {authorization: 'bearer secret'}});
			assert.deepEqual(await learned.json(), {ok: true, learned: 'spam'});
			assert.equal(learning.getClassifier().nspam, 1);
			assert.equal(JSON.parse(readFileSync(modelPath, 'utf8')).nspam, 1);
		} finally {
			await server.close();
		}

		const open = scanner();
		const plain = await listen(createHttpServer(open));
		try {
			const refused = await fetch(`${plain.url}/learn/ham`, {method: 'POST', body: ham});
			assert.equal(refused.status, 403);
		} finally {
			await plain.close();
		}

		const unsaved = scanner();
		const memory = await listen(createHttpServer(unsaved, {token: 't'}));
		try {
			assert.equal((await fetch(`${memory.url}/learn/ham`, {method: 'POST', body: ham, headers: {authorization: 'Bearer t'}})).status, 200);
			assert.equal(unsaved.getClassifier().nham, 1);
		} finally {
			await memory.close();
		}
	});

	it('answers 500 when a scan fails', async () => {
		const server = await listen(createHttpServer({
			async scan() {
				throw new Error('scanner broke');
			},
		}));
		try {
			const response = await fetch(`${server.url}/scan`, {method: 'POST', body: ham});
			assert.equal(response.status, 500);
			assert.deepEqual(await response.json(), {error: 'scanner broke'});
		} finally {
			await server.close();
		}
	});
});

describe('TCP server', () => {
	it('answers with one line of JSON or text', async () => {
		const json = await listen(createTcpServer(scanner()));
		const text = await listen(createTcpServer(scanner(), {json: false}));
		try {
			const result = JSON.parse(await tcp(json.port, spam));
			assert.equal(result.isSpam, true);
			assert.equal(result.mail, undefined);
			assert.match(await tcp(text.port, spam), /^SPAM \d+\.\d\/5\.0 GTUBE[\w,]*\n$/);
			assert.match(await tcp(text.port, ham), /^HAM -?\d+\.\d\/5\.0 [\w,]*\n$/);
		} finally {
			await json.close();
			await text.close();
		}
	});

	it('refuses large messages and reports scan failures', async () => {
		const small = await listen(createTcpServer(scanner(), {maxSize: 100}));
		const failing = {
			async scan() {
				throw new Error('scanner broke');
			},
		};
		const broken = await listen(createTcpServer(failing));
		const brokenText = await listen(createTcpServer(failing, {json: false}));
		try {
			assert.deepEqual(JSON.parse(await tcp(small.port, 'x'.repeat(5000))), {error: 'Message larger than 100 bytes'});
			assert.deepEqual(JSON.parse(await tcp(broken.port, ham)), {error: 'scanner broke'});
			assert.equal(await tcp(brokenText.port, ham), 'ERROR scanner broke\n');
			// A client that resets its connection does not stop the server.
			const socket = net.createConnection(broken.port, '127.0.0.1');
			await once(socket, 'connect');
			socket.write('partial');
			socket.resetAndDestroy();
			await delay(50);
			assert.deepEqual(JSON.parse(await tcp(broken.port, ham)), {error: 'scanner broke'});
		} finally {
			await small.close();
			await broken.close();
			await brokenText.close();
		}
	});
});
