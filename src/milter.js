import {Buffer} from 'node:buffer';
import {EventEmitter} from 'node:events';
import net from 'node:net';
import {spamHeaders} from './headers.js';
import {formatAuthResultsHeader} from './auth.js';
import {VERSION} from './version.js';

// Milter protocol (version 6), as spoken by Postfix and Sendmail.
export const COMMANDS = {
	ABORT: 'A', BODY: 'B', CONNECT: 'C', MACRO: 'D', BODYEOB: 'E', HELO: 'H', QUIT_NC: 'K', HEADER: 'L', MAIL: 'M', EOH: 'N', OPTNEG: 'O', QUIT: 'Q', RCPT: 'R', DATA: 'T', UNKNOWN: 'U',
};

export const RESPONSES = {
	ACCEPT: 'a', CONTINUE: 'c', DISCARD: 'd', ADDHEADER: 'h', INSHEADER: 'i', CHGHEADER: 'm', QUARANTINE: 'q', REJECT: 'r', TEMPFAIL: 't', REPLYCODE: 'y', OPTNEG: 'O',
};

export const ACTIONS = {
	ADDHDRS: 0x01, CHGBODY: 0x02, ADDRCPT: 0x04, DELRCPT: 0x08, CHGHDRS: 0x10, QUARANTINE: 0x20, CHGFROM: 0x40,
};

export const PROTOCOL = {
	NOCONNECT: 0x1, NOHELO: 0x2, NOMAIL: 0x4, NORCPT: 0x8, NOBODY: 0x10, NOHDRS: 0x20, NOEOH: 0x40, NR_HDR: 0x80, NOUNKNOWN: 0x1_00, NODATA: 0x2_00, SKIP: 0x4_00, RCPT_REJ: 0x8_00, NR_CONN: 0x10_00, NR_HELO: 0x20_00, NR_MAIL: 0x40_00, NR_RCPT: 0x80_00, NR_DATA: 0x1_00_00, NR_UNKN: 0x2_00_00, NR_EOH: 0x4_00_00, NR_BODY: 0x8_00_00, HDR_LEADSPC: 0x10_00_00,
};

const MAX_PACKET = 64 * 1024 * 1024;

/**
 * Encode one milter packet: a 4-byte length, a command letter and its data.
 * @param {string} command
 * @param {Buffer|string} [data]
 * @returns {Buffer}
 */
export function packet(command, data = Buffer.alloc(0)) {
	const payload = Buffer.isBuffer(data) ? data : Buffer.from(data, 'latin1');
	const header = Buffer.alloc(5);
	header.writeUInt32BE(payload.length + 1);
	header.write(command, 4, 'latin1');
	return Buffer.concat([header, payload]);
}

/**
 * Split NUL-terminated strings.
 * @param {Buffer} data
 * @returns {string[]}
 */
export function cstrings(data) {
	const parts = data.toString('latin1').split('\0');
	if (parts.at(-1) === '') {
		parts.pop();
	}

	return parts;
}

function cstring(value) {
	return Buffer.from(`${value}\0`, 'latin1');
}

function address(value) {
	const text = String(value ?? '').trim();
	const match = /^<?([^<>]*)>?$/.exec(text);
	return match ? match[1] : text;
}

/**
 * One milter connection: collects the SMTP session, headers and body, then
 * scans the message at the end of the body and tells the MTA what to do.
 */
export class MilterSession {
	/**
	 * @param {net.Socket} socket
	 * @param {object} server - the MilterServer
	 */
	constructor(socket, server) {
		this.socket = socket;
		this.server = server;
		this.buffer = Buffer.alloc(0);
		this.leadingSpace = false;
		this.pending = [];
		this.processing = false;
		this.resetConnection();
		socket.on('data', chunk => this.receive(chunk));
		socket.on('error', error => server.report(error));
	}

	resetConnection() {
		this.connection = {};
		this.macros = {};
		this.resetMessage();
	}

	resetMessage() {
		this.envelope = {mailFrom: null, rcptTo: []};
		this.headers = [];
		this.body = [];
		this.size = 0;
		this.truncated = false;
	}

	send(command, data) {
		if (!this.socket.destroyed) {
			this.socket.write(packet(command, data));
		}
	}

	receive(chunk) {
		this.buffer = Buffer.concat([this.buffer, chunk]);
		while (this.buffer.length >= 4) {
			const length = this.buffer.readUInt32BE(0);
			if (length === 0 || length > MAX_PACKET) {
				this.socket.destroy(new Error(`Invalid milter packet length ${length}`));
				return;
			}

			if (this.buffer.length < 4 + length) {
				return;
			}

			this.pending.push({command: String.fromCodePoint(this.buffer[4]), data: this.buffer.subarray(5, 4 + length)});
			this.buffer = this.buffer.subarray(4 + length);
		}

		if (!this.processing) {
			this.process();
		}
	}

	// Commands are handled one at a time, in order, even while a scan runs.
	async process() {
		this.processing = true;
		while (this.pending.length > 0) {
			const {command, data} = this.pending.shift();
			try {
				// eslint-disable-next-line no-await-in-loop -- commands must be handled in order
				await this.handle(command, data);
			} catch (error) {
				this.server.report(error);
				this.send(this.server.options.onError === 'accept' ? RESPONSES.ACCEPT : RESPONSES.TEMPFAIL);
				this.resetMessage();
			}
		}

		this.processing = false;
	}

	async handle(command, data) {
		const {options} = this.server;
		switch (command) {
			case COMMANDS.OPTNEG: {
				const version = data.readUInt32BE(0);
				const actions = data.readUInt32BE(4);
				const protocol = data.readUInt32BE(8);
				const wanted = ACTIONS.ADDHDRS | ACTIONS.CHGHDRS | ACTIONS.QUARANTINE;
				this.leadingSpace = Boolean(protocol & PROTOCOL.HDR_LEADSPC);
				const reply = Buffer.alloc(12);
				reply.writeUInt32BE(Math.min(version, 6), 0);
				reply.writeUInt32BE(actions & wanted, 4);
				reply.writeUInt32BE(protocol & (PROTOCOL.HDR_LEADSPC | PROTOCOL.NOUNKNOWN), 8);
				this.send(RESPONSES.OPTNEG, reply);
				break;
			}

			case COMMANDS.MACRO: {
				// The command letter the macros belong to, then name/value pairs.
				const pairs = cstrings(data.subarray(1));
				for (let i = 0; i + 1 < pairs.length; i += 2) {
					this.macros[pairs[i].replaceAll(/^{|}$/g, '')] = pairs[i + 1];
				}

				break;
			}

			case COMMANDS.CONNECT: {
				const nul = data.indexOf(0);
				const hostname = data.subarray(0, nul).toString('latin1');
				const family = String.fromCodePoint(data[nul + 1]);
				let ip = null;
				if (family === '4' || family === '6') {
					ip = cstrings(data.subarray(nul + 4))[0];
				}

				this.connection = {
					hostname, family, remoteAddress: ip && ip.replace(/^ipv6:/i, ''),
				};
				this.send(RESPONSES.CONTINUE);
				break;
			}

			case COMMANDS.HELO: {
				this.connection.helo = cstrings(data)[0];
				this.send(RESPONSES.CONTINUE);
				break;
			}

			case COMMANDS.MAIL: {
				this.resetMessage();
				this.envelope.mailFrom = {address: address(cstrings(data)[0])};
				this.send(RESPONSES.CONTINUE);
				break;
			}

			case COMMANDS.RCPT: {
				this.envelope.rcptTo.push({address: address(cstrings(data)[0])});
				this.send(RESPONSES.CONTINUE);
				break;
			}

			case COMMANDS.HEADER: {
				const [name, value = ''] = cstrings(data);
				this.headers.push([name, value]);
				this.send(RESPONSES.CONTINUE);
				break;
			}

			case COMMANDS.BODY: {
				if (this.size + data.length <= options.maxSize) {
					this.body.push(Buffer.from(data));
					this.size += data.length;
				} else {
					this.truncated = true;
				}

				this.send(RESPONSES.CONTINUE);
				break;
			}

			case COMMANDS.BODYEOB: {
				await this.endOfMessage();
				break;
			}

			case COMMANDS.ABORT: {
				this.resetMessage();
				break;
			}

			case COMMANDS.QUIT_NC: {
				this.resetConnection();
				break;
			}

			case COMMANDS.QUIT: {
				this.socket.end();
				break;
			}

			default: {
				// DATA, EOH, UNKNOWN and anything newer.
				this.send(RESPONSES.CONTINUE);
			}
		}
	}

	rawMessage() {
		const head = this.headers.map(([name, value]) => `${name}:${this.leadingSpace || value.startsWith(' ') || value.startsWith('\t') ? '' : ' '}${value}`).join('\r\n');
		return Buffer.concat([Buffer.from(this.headers.length > 0 ? `${head}\r\n\r\n` : '\r\n', 'latin1'), ...this.body]);
	}

	async endOfMessage() {
		const {options, scanner} = this.server;
		const {hostname} = this.connection;
		const session = {
			remoteAddress: this.connection.remoteAddress || undefined,
			// Postfix and Sendmail send the client's hostname only when its reverse
			// DNS was confirmed; otherwise "unknown" or "[address]".
			resolvedClientHostname: hostname && hostname !== 'unknown' && !hostname.startsWith('[') ? hostname : undefined,
			helo: this.connection.helo,
			envelope: this.envelope,
		};
		const result = await scanner.scan(this.rawMessage(), {session});
		this.server.emit('scan', {session, result});

		// Remove X-Spam headers the sender added, so they cannot pose as ours.
		const counts = new Map();
		for (const [name] of this.headers) {
			const key = name.toLowerCase();
			counts.set(key, (counts.get(key) || 0) + 1);
			if (key.startsWith('x-spam-')) {
				const index = Buffer.alloc(4);
				index.writeUInt32BE(counts.get(key));
				this.send(RESPONSES.CHGHEADER, Buffer.concat([index, cstring(name), cstring('')]));
			}
		}

		const headers = spamHeaders(result, {version: VERSION});
		if (result.results.authentication) {
			headers.unshift(['Authentication-Results', formatAuthResultsHeader(result.results.authentication, options.hostname)]);
		}

		for (const [name, value] of headers) {
			this.send(RESPONSES.ADDHEADER, Buffer.concat([cstring(name), cstring(`${this.leadingSpace ? ' ' : ''}${value}`.replaceAll('\r\n', '\n'))]));
		}

		if (result.isSpam && options.subjectTag) {
			const subject = this.headers.find(([name]) => name.toLowerCase() === 'subject');
			const current = subject ? subject[1].trim() : '';
			if (!current.startsWith(options.subjectTag)) {
				const index = Buffer.alloc(4);
				index.writeUInt32BE(1);
				this.send(RESPONSES.CHGHEADER, Buffer.concat([index, cstring('Subject'), cstring(`${this.leadingSpace ? ' ' : ''}${options.subjectTag}${current ? ` ${current}` : ''}`)]));
			}
		}

		if (result.action === 'reject' && options.reject) {
			const code = String(options.rejectCode);
			const enhanced = code.startsWith('4') ? '4.7.1' : '5.7.1';
			const text = String(options.rejectMessage).replaceAll(/[\r\n]/g, ' ');
			this.send(RESPONSES.REPLYCODE, cstring(`${code} ${enhanced} ${text}`));
		} else if (result.isSpam && options.quarantine) {
			this.send(RESPONSES.QUARANTINE, cstring(`Spam Scanner score ${result.score.toFixed(1)}`));
			this.send(RESPONSES.CONTINUE);
		} else {
			this.send(RESPONSES.CONTINUE);
		}

		this.resetMessage();
	}
}

/**
 * A milter server for Postfix (smtpd_milters) and Sendmail (INPUT_MAIL_FILTER).
 *
 * Every message gets X-Spam-Flag, X-Spam-Score, X-Spam-Level, X-Spam-Status
 * and X-Spam-Action headers (and Authentication-Results when authentication
 * is on). Spam can also have its subject tagged, be held in the quarantine,
 * or, at the reject threshold, be refused during the SMTP transaction.
 *
 * Emits "scan" ({session, result}) for every message, "error" on failures and
 * "listening" when ready.
 */
export class MilterServer extends EventEmitter {
	/**
	 * @param {import('./index.js').SpamScanner} scanner
	 * @param {object} [options]
	 * @param {boolean} [options.reject] - refuse messages at the reject threshold (default: tag only)
	 * @param {number} [options.rejectCode] - 451 (try again later, the default) or 550
	 * @param {string} [options.rejectMessage]
	 * @param {boolean} [options.quarantine] - hold spam in the MTA's quarantine
	 * @param {string|null} [options.subjectTag] - e.g. "[SPAM]"
	 * @param {string} [options.hostname] - this server's name, for Authentication-Results
	 * @param {number} [options.maxSize] - body bytes kept for scanning
	 * @param {'tempfail'|'accept'} [options.onError] - answer when a scan fails
	 */
	constructor(scanner, options = {}) {
		super();
		this.scanner = scanner;
		this.options = {
			reject: false, rejectCode: 451, rejectMessage: 'Message rejected as spam', quarantine: false, subjectTag: null, hostname: 'spamscanner', maxSize: 25 * 1024 * 1024, onError: 'tempfail', ...options,
		};
		this.sockets = new Set();
		this.server = net.createServer(socket => {
			this.sockets.add(socket);
			socket.on('close', () => this.sockets.delete(socket));
			return new MilterSession(socket, this);
		});
		this.server.on('error', error => this.report(error));
	}

	// Errors go to "error" listeners; with none, a broken connection or failed
	// scan must not stop the server.
	report(error) {
		if (this.listenerCount('error') > 0) {
			this.emit('error', error);
		}
	}

	/**
	 * Start listening on a TCP port or a Unix socket path.
	 * @param {number|string} port
	 * @param {string} [host]
	 * @returns {Promise<import('node:net').AddressInfo|string>}
	 */
	listen(port, host = '127.0.0.1') {
		return new Promise((resolve, reject) => {
			this.server.once('error', reject);
			const done = () => {
				this.server.off('error', reject);
				this.emit('listening', this.server.address());
				resolve(this.server.address());
			};

			if (typeof port === 'string' && !/^\d+$/.test(port)) {
				this.server.listen(port, done);
			} else {
				this.server.listen(Number(port), host, done);
			}
		});
	}

	/**
	 * Stop accepting connections and close open ones; the MTA treats messages
	 * in progress as a temporary failure.
	 * @returns {Promise<void>}
	 */
	close() {
		return new Promise(resolve => {
			this.server.close(() => resolve());
			for (const socket of this.sockets) {
				socket.destroy();
			}
		});
	}
}
