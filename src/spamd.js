import {Buffer} from 'node:buffer';
import net from 'node:net';
import {rewriteMessage, spamHeaders, splitMessage} from './headers.js';
import {VERSION} from './version.js';

// SpamAssassin's spamd protocol, as spoken by spamc, Exim's "spam" ACL
// condition, Haraka's spamassassin plugin and other SpamAssassin clients.
// https://spamassassin.apache.org/full/4.0.x/doc/spamd.html

const EX_OK = 0;
const EX_USAGE = 64;
const EX_DATAERR = 65;
const EX_SOFTWARE = 70;
const EX_PROTOCOL = 76;
const EX_NOPERM = 77;

const COMMANDS = new Set(['CHECK', 'SYMBOLS', 'REPORT', 'REPORT_IFSPAM', 'PROCESS', 'HEADERS', 'PING', 'SKIP', 'TELL']);

/**
 * Parse a request head: the command line and its headers.
 * @param {string} head - everything before the blank line
 * @returns {{command: string, version: string, headers: Record<string, string>}}
 */
export function parseRequest(head) {
	const [line, ...rest] = head.split('\r\n');
	const match = /^([A-Z_]+) SPAMC\/(\d+\.\d+)$/.exec(line);
	if (!match || !COMMANDS.has(match[1])) {
		throw Object.assign(new Error(`Bad request line: ${line}`), {code: EX_PROTOCOL});
	}

	const headers = {};
	for (const header of rest) {
		const colon = header.indexOf(':');
		if (colon < 1) {
			throw Object.assign(new Error(`Bad header line: ${header}`), {code: EX_PROTOCOL});
		}

		headers[header.slice(0, colon).trim().toLowerCase()] = header.slice(colon + 1).trim();
	}

	return {command: match[1], version: match[2], headers};
}

function reply(code, text, headers = [], body = null) {
	const lines = [`SPAMD/1.5 ${code} ${text}`];
	if (body !== null) {
		lines.push(`Content-length: ${body.length}`);
	}

	lines.push(...headers.map(([name, value]) => `${name}: ${value}`), '', '');
	return body === null ? Buffer.from(lines.join('\r\n')) : Buffer.concat([Buffer.from(lines.join('\r\n')), body]);
}

/**
 * The text of a REPORT answer: one line per test with its points.
 * @param {object} result
 * @returns {string}
 */
export function report(result) {
	const lines = [
		`Spam detection software, running on the system "spamscanner", has ${result.isSpam ? 'identified this incoming email as possible spam' : 'scanned this incoming email'}.`,
		'',
		`Content analysis details:   (${result.score.toFixed(1)} points, ${result.threshold.toFixed(1)} required)`,
		'',
		' pts rule name              description',
		'---- ---------------------- --------------------------------------------------',
		...result.tests.map(test => `${test.score.toFixed(1).padStart(4)} ${test.name.padEnd(22)} ${test.description}`),
	];
	return `${lines.join('\r\n')}\r\n`;
}

/**
 * Answer one spamd request.
 * @param {import('./index.js').SpamScanner} scanner
 * @param {{command: string, headers: Record<string, string>}} request
 * @param {Buffer} message
 * @param {object} options - see createSpamdServer
 * @returns {Promise<Buffer|null>} the answer, or null for SKIP
 */
export async function answer(scanner, request, message, options) {
	const {command, headers} = request;
	if (command === 'PING') {
		return reply(EX_OK, 'PONG');
	}

	if (command === 'SKIP') {
		return null;
	}

	if (command === 'TELL') {
		if (!options.allowTell) {
			return reply(EX_NOPERM, 'TELL commands are not enabled, start the server with allowTell');
		}

		const category = (headers['message-class'] || '').toLowerCase();
		const remove = (headers.remove || '').toLowerCase().includes('local');
		if (category !== 'spam' && category !== 'ham') {
			return reply(EX_USAGE, 'TELL needs a Message-class of spam or ham');
		}

		await (remove ? scanner.unlearn(message, category) : scanner.learn(message, category));
		if (options.modelPath) {
			scanner.saveModel(options.modelPath);
		}

		return reply(EX_OK, 'EX_OK', [remove ? ['DidRemove', 'local'] : ['DidSet', 'local']]);
	}

	const result = await scanner.scan(message);
	const verdict = ['Spam', `${result.isSpam ? 'True' : 'False'} ; ${result.score.toFixed(1)} / ${result.threshold.toFixed(1)}`];
	switch (command) {
		case 'CHECK': {
			return reply(EX_OK, 'EX_OK', [verdict]);
		}

		case 'SYMBOLS': {
			return reply(EX_OK, 'EX_OK', [verdict], Buffer.from(result.tests.map(test => test.name).join(',')));
		}

		case 'REPORT':
		case 'REPORT_IFSPAM': {
			return reply(EX_OK, 'EX_OK', [verdict], command === 'REPORT' || result.isSpam ? Buffer.from(report(result)) : Buffer.alloc(0));
		}

		default: {
			// PROCESS returns the whole message with headers added; HEADERS only its header block.
			const rewritten = rewriteMessage(message, spamHeaders(result, {version: VERSION}), {subjectTag: result.isSpam ? options.subjectTag : null});
			if (command === 'PROCESS') {
				return reply(EX_OK, 'EX_OK', [verdict], rewritten);
			}

			const {header, newline} = splitMessage(rewritten);
			return reply(EX_OK, 'EX_OK', [verdict], Buffer.from(`${header}${newline}${newline}`, 'latin1'));
		}
	}
}

/**
 * A spamd-compatible server, so that spamc, Exim's "spam" condition, Haraka
 * and other SpamAssassin clients can use Spam Scanner unchanged.
 *
 * Supports CHECK, SYMBOLS, REPORT, REPORT_IFSPAM, PROCESS, HEADERS, PING,
 * SKIP and (with allowTell) TELL. Compressed requests are refused.
 *
 * @param {import('./index.js').SpamScanner} scanner
 * @param {object} [options]
 * @param {number} [options.maxSize] - largest message accepted, in bytes
 * @param {boolean} [options.allowTell] - accept TELL (learning) requests
 * @param {string} [options.modelPath] - where TELL saves the classifier
 * @param {string|null} [options.subjectTag] - tag for spam in PROCESS and HEADERS answers
 * @returns {net.Server}
 */
export function createSpamdServer(scanner, options = {}) {
	const settings = {
		maxSize: 25 * 1024 * 1024, allowTell: false, modelPath: null, subjectTag: null, ...options,
	};
	return net.createServer({allowHalfOpen: true}, socket => {
		let buffer = Buffer.alloc(0);
		let request = null;
		let done = false;
		const finish = async message => {
			done = true;
			try {
				const output = await answer(scanner, request, message, settings);
				socket.end(output ?? undefined);
			} catch (error) {
				socket.end(reply(error.code ?? EX_SOFTWARE, error.message.replaceAll(/[\r\n]/g, ' ')));
			}
		};

		const fail = (code, text) => {
			done = true;
			socket.end(reply(code, text));
		};

		socket.on('data', chunk => {
			if (done) {
				return;
			}

			buffer = Buffer.concat([buffer, chunk]);
			if (!request) {
				const end = buffer.indexOf('\r\n\r\n');
				if (end === -1) {
					if (buffer.length > 64 * 1024) {
						fail(EX_PROTOCOL, 'Request head too long');
					}

					return;
				}

				try {
					request = parseRequest(buffer.subarray(0, end).toString('latin1'));
				} catch (error) {
					fail(error.code, error.message);
					return;
				}

				buffer = buffer.subarray(end + 4);
				if (request.headers.compress) {
					fail(EX_PROTOCOL, 'Compressed requests are not supported');
					return;
				}

				const length = Number(request.headers['content-length'] ?? 0);
				if (!Number.isSafeInteger(length) || length < 0) {
					fail(EX_PROTOCOL, 'Bad Content-length');
					return;
				}

				if (length > settings.maxSize) {
					fail(EX_DATAERR, `Message larger than ${settings.maxSize} bytes`);
					return;
				}

				request.length = length;
			}

			if (buffer.length >= request.length && (request.length > 0 || ['PING', 'SKIP'].includes(request.command))) {
				finish(buffer.subarray(0, request.length));
			}
		});
		// Spamc closes its side after the message; without a Content-length the
		// end of the input ends the message.
		socket.on('end', () => {
			if (!done) {
				if (request) {
					finish(buffer.subarray(0, settings.maxSize));
				} else {
					fail(EX_PROTOCOL, 'Incomplete request');
				}
			}
		});
		socket.on('error', () => {});
	});
}

export const SPAMD_EXIT_CODES = {
	EX_OK, EX_USAGE, EX_DATAERR, EX_SOFTWARE, EX_PROTOCOL, EX_NOPERM,
};
