import {Buffer} from 'node:buffer';
import {existsSync} from 'node:fs';
import net from 'node:net';

// Where distributions put clamd's socket.
export const SOCKET_PATHS = ['/var/run/clamav/clamd.ctl', '/run/clamav/clamd.ctl', '/run/clamd.scan/clamd.sock', '/var/run/clamd.scan/clamd.sock', '/var/run/clamav/clamd.sock', '/tmp/clamd.socket', '/opt/homebrew/var/run/clamav/clamd.sock', '/usr/local/var/run/clamav/clamd.sock'];

/**
 * The clamd address to use: an explicit socket, an explicit host and port, or
 * the first socket file that exists.
 * @param {object} [options]
 * @returns {{path: string}|{host: string, port: number}|null}
 */
export function clamdAddress(options = {}) {
	if (options.socket) {
		return {path: options.socket};
	}

	if (options.host || options.port) {
		return {host: options.host || '127.0.0.1', port: Number(options.port) || 3310};
	}

	const found = (options.socketPaths || SOCKET_PATHS).find(candidate => existsSync(candidate));
	return found ? {path: found} : null;
}

/**
 * Send one command to clamd and read its reply.
 * @param {object} address
 * @param {(socket: net.Socket) => void} write
 * @param {number} timeout
 * @returns {Promise<string>}
 */
function exchange(address, write, timeout) {
	return new Promise((resolve, reject) => {
		const socket = net.createConnection(address);
		const chunks = [];
		// A promise settles once, so later events (end after a timeout) are ignored.
		const finish = (error, value) => {
			socket.destroy();
			if (error) {
				reject(error);
			} else {
				resolve(value);
			}
		};

		socket.setTimeout(timeout, () => finish(new Error(`clamd did not answer within ${timeout} ms`)));
		socket.on('connect', () => write(socket));
		socket.on('data', chunk => chunks.push(chunk));
		socket.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8').replaceAll('\0', '').trim()));
		socket.on('error', error => finish(error));
	});
}

/**
 * Scan a buffer with clamd (the ClamAV daemon) using its INSTREAM command.
 * @param {Buffer} buffer
 * @param {object} [options]
 * @param {string} [options.socket] - clamd's Unix socket
 * @param {string} [options.host] - or its TCP host
 * @param {number} [options.port] - and port (3310)
 * @param {number} [options.timeout] - milliseconds
 * @param {number} [options.chunkSize]
 * @returns {Promise<{infected: boolean, viruses: string[], reply: string}>}
 */
export async function scanBuffer(buffer, options = {}) {
	const address = clamdAddress(options);
	if (!address) {
		throw new Error('No clamd socket found; set clamav.socket or clamav.host and clamav.port');
	}

	const chunkSize = options.chunkSize ?? 65_536;
	const reply = await exchange(address, socket => {
		socket.write('zINSTREAM\0');
		for (let offset = 0; offset < buffer.length; offset += chunkSize) {
			const chunk = buffer.subarray(offset, offset + chunkSize);
			const size = Buffer.alloc(4);
			size.writeUInt32BE(chunk.length);
			socket.write(size);
			socket.write(chunk);
		}

		socket.end(Buffer.alloc(4));
	}, options.timeout ?? 30_000);
	if (/\bOK$/.test(reply)) {
		return {infected: false, viruses: [], reply};
	}

	const found = [...reply.matchAll(/:\s*(.+?)\s+FOUND/g)].map(match => match[1]);
	if (found.length > 0) {
		return {infected: true, viruses: found, reply};
	}

	throw new Error(`clamd: ${reply || 'no reply'}`);
}

/**
 * Check that clamd answers.
 * @param {object} [options] - socket, host, port, timeout
 * @returns {Promise<boolean>}
 */
export async function ping(options = {}) {
	const address = clamdAddress(options);
	if (!address) {
		return false;
	}

	try {
		return (await exchange(address, socket => socket.end('zPING\0'), options.timeout ?? 5000)) === 'PONG';
	} catch {
		return false;
	}
}
