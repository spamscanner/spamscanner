import {Buffer} from 'node:buffer';
import {timingSafeEqual} from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import {rewriteMessage, spamHeaders} from './headers.js';
import {VERSION} from './version.js';

/**
 * The largest message the servers and the command line read by default, in
 * bytes (25 MiB): above Postfix's default message_size_limit (10 MB) and the
 * limits of most mail services.
 */
export const MAX_MESSAGE_SIZE = 25 * 1024 * 1024;

/**
 * The most connections each server keeps open at once by default (and, for
 * the HTTP API, requests it handles at once): each may hold a message of up
 * to MAX_MESSAGE_SIZE bytes while it is scanned. Postfix runs at most 100
 * smtpd and 100 cleanup processes by default, each with one milter connection.
 */
export const MAX_CONNECTIONS = 200;

/**
 * A scan result without the parsed message and word list, for sending over
 * the network or printing.
 * @param {object} result
 * @param {object} [options]
 * @param {boolean} [options.verbose] - keep tokens and every detector's raw output
 * @returns {object}
 */
export function serializeResult(result, options = {}) {
	const {mail, tokens, ...rest} = result;
	const output = {
		...rest,
		results: {...result.results},
	};
	if (output.results.authentication) {
		const {receivedChain, ...auth} = output.results.authentication;
		output.results.authentication = auth;
	}

	if (options.verbose) {
		output.tokens = tokens;
		output.subject = mail?.subject ?? null;
	}

	return output;
}

/**
 * Session details from request query parameters: ip, hostname (verified
 * reverse DNS), helo, from (envelope sender) and to (recipients, repeatable or
 * comma separated).
 * @param {URLSearchParams} query
 * @returns {object}
 */
export function sessionFromQuery(query) {
	const session = {};
	if (query.get('ip')) {
		session.remoteAddress = query.get('ip');
	}

	if (query.get('hostname')) {
		session.resolvedClientHostname = query.get('hostname');
	}

	if (query.get('helo')) {
		session.helo = query.get('helo');
	}

	const recipients = query.getAll('to').flatMap(value => value.split(',')).map(value => value.trim()).filter(Boolean);
	if (query.has('from') || recipients.length > 0) {
		session.envelope = {mailFrom: {address: query.get('from') || ''}, rcptTo: recipients.map(address => ({address}))};
	}

	return session;
}

function sameToken(given, expected) {
	const a = Buffer.from(String(given));
	const b = Buffer.from(String(expected));
	return a.length === b.length && timingSafeEqual(a, b);
}

function readBody(request, limit) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let size = 0;
		request.on('data', chunk => {
			size += chunk.length;
			if (size <= limit) {
				chunks.push(chunk);
			}
		});
		// The rest of an oversized body is read and dropped, so the client gets
		// the 413 answer rather than a reset connection.
		request.on('end', () => {
			if (size > limit) {
				const error = new Error(`Message larger than ${limit} bytes`);
				error.statusCode = 413;
				reject(error);
				return;
			}

			resolve(Buffer.concat(chunks));
		});
		request.on('error', reject);
	});
}

/**
 * An HTTP server for mail servers and scripts.
 *
 * - GET  /health            → {"ok": true, "version": "..."}
 * - POST /scan              → the scan result as JSON
 * - POST /check             → the message with X-Spam headers added (message/rfc822),
 *                             with X-Spam-Flag, X-Spam-Score and X-Spam-Action response headers
 * - POST /learn/spam, /learn/ham → teach the classifier (only with a token)
 *
 * The request body is the raw message. Query parameters: ip, hostname, helo,
 * from, to (see sessionFromQuery), and for /check, subjectTag. Authentication
 * (SPF, DKIM, DMARC, ARC) and IP blocklists run only when ip is given.
 *
 * @param {import('./index.js').SpamScanner} scanner
 * @param {object} [options]
 * @param {string} [options.token] - required as "Authorization: Bearer <token>" when set
 * @param {number} [options.maxSize] - largest message accepted, in bytes
 * @param {string} [options.modelPath] - where /learn saves the classifier
 * @param {number} [options.maxConnections] - connections kept open, and requests handled, at once
 * @returns {http.Server}
 */
export function createHttpServer(scanner, options = {}) {
	const {
		token = null, maxSize = MAX_MESSAGE_SIZE, modelPath = null, maxConnections = MAX_CONNECTIONS,
	} = options;
	// Requests being read or scanned. Pipelined requests on one connection are
	// handled at the same time, so the connection limit alone does not bound them.
	let active = 0;
	const server = http.createServer(async (request, response) => {
		const send = (status, body, headers = {}) => {
			const isBuffer = Buffer.isBuffer(body);
			response.writeHead(status, {'content-type': isBuffer ? 'message/rfc822' : 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers});
			response.end(isBuffer ? body : `${JSON.stringify(body)}\n`);
		};

		try {
			const url = new URL(request.url, 'http://localhost');
			if (request.method === 'GET' && url.pathname === '/health') {
				send(200, {ok: true, version: VERSION});
				return;
			}

			if (token && !sameToken((request.headers.authorization || '').replace(/^bearer\s+/i, ''), token)) {
				send(401, {error: 'Unauthorized'}, {'www-authenticate': 'Bearer'});
				return;
			}

			if (request.method !== 'POST') {
				send(405, {error: 'Method not allowed'}, {allow: 'POST'});
				return;
			}

			const learn = /^\/learn\/(spam|ham)$/.exec(url.pathname);
			if (!['/scan', '/check'].includes(url.pathname) && !learn) {
				send(404, {error: 'Not found'});
				return;
			}

			// Refused before the body is read, so a client cannot make the server
			// read a large message for nothing.
			if (learn && !token) {
				send(403, {error: 'Learning needs the server to be started with a token'});
				return;
			}

			// (refused before the body is read, and the connection closed, so a
			//  client gets the answer without sending the message first)
			const length = request.headers['content-length'];
			if (length !== undefined && Number(length) > maxSize) {
				send(413, {error: `Message larger than ${maxSize} bytes`}, {connection: 'close'});
				return;
			}

			if (active >= maxConnections) {
				send(503, {error: 'Too many requests at once'}, {connection: 'close', 'retry-after': '1'});
				return;
			}

			active++;
			try {
				const raw = await readBody(request, maxSize);
				if (learn) {
					await scanner.learn(raw, learn[1]);
					if (modelPath) {
						scanner.saveModel(modelPath);
					}

					send(200, {ok: true, learned: learn[1]});
					return;
				}

				const result = await scanner.scan(raw, {session: sessionFromQuery(url.searchParams)});
				if (url.pathname === '/scan') {
					send(200, serializeResult(result, {verbose: url.searchParams.get('verbose') === '1'}));
					return;
				}

				const tag = url.searchParams.get('subjectTag');
				const rewritten = rewriteMessage(raw, spamHeaders(result, {version: VERSION}), {subjectTag: result.isSpam && tag ? tag : null});
				send(200, rewritten, {'x-spam-flag': result.isSpam ? 'YES' : 'NO', 'x-spam-score': result.score.toFixed(1), 'x-spam-action': result.action});
			} finally {
				active--;
			}
		} catch (error) {
			send(error.statusCode || 500, {error: error.message});
		}
	});
	server.maxConnections = maxConnections;
	return server;
}

/**
 * A plain TCP server: a client sends a raw message and closes its side; the
 * server answers with the result as one line of JSON (or a short text line)
 * and closes the connection.
 *
 * The client's IP address is not known, so authentication (SPF, DKIM, DMARC,
 * ARC) and IP blocklists do not run for these scans.
 * @param {import('./index.js').SpamScanner} scanner
 * @param {object} [options]
 * @param {boolean} [options.json] - answer in JSON (default true)
 * @param {number} [options.maxSize]
 * @param {number} [options.timeout] - close a connection that sends nothing for this many milliseconds (default 60000)
 * @param {number} [options.maxConnections] - connections kept open at once; more are closed at once
 * @returns {net.Server}
 */
export function createTcpServer(scanner, options = {}) {
	const {
		json = true, maxSize = MAX_MESSAGE_SIZE, timeout = 60_000, maxConnections = MAX_CONNECTIONS,
	} = options;
	// Half-open: the client closes its side to mark the end of the message and
	// still reads the answer.
	const server = net.createServer({allowHalfOpen: true}, socket => {
		const chunks = [];
		let size = 0;
		socket.setTimeout(timeout, () => socket.destroy());
		const onEnd = async () => {
			// The scan itself may take a while; the client is waiting for it.
			socket.setTimeout(0);
			try {
				const result = await scanner.scan(Buffer.concat(chunks));
				socket.end(json ? `${JSON.stringify(serializeResult(result))}\n` : `${result.isSpam ? 'SPAM' : 'HAM'} ${result.score.toFixed(1)}/${result.threshold.toFixed(1)} ${result.tests.map(test => test.name).join(',')}\n`);
			} catch (error) {
				socket.end(json ? `${JSON.stringify({error: error.message})}\n` : `ERROR ${error.message}\n`);
			}
		};

		const onData = chunk => {
			size += chunk.length;
			if (size > maxSize) {
				// Answer once, stop reading the rest of the message and close.
				socket.off('data', onData);
				socket.off('end', onEnd);
				socket.end(`${JSON.stringify({error: `Message larger than ${maxSize} bytes`})}\n`, () => socket.destroy());
				return;
			}

			chunks.push(chunk);
		};

		socket.on('data', onData);
		socket.on('end', onEnd);
		socket.on('error', () => {});
	});
	server.maxConnections = maxConnections;
	return server;
}
