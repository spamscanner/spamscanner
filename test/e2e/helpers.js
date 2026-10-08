import {once} from 'node:events';
import {readdirSync, readFileSync, existsSync} from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

/**
 * Send one message over SMTP and return the server's replies.
 * @param {object} options
 * @param {number} options.port
 * @param {string} options.from
 * @param {string} options.to
 * @param {string} options.data - the message, with CRLF line endings
 * @returns {Promise<{data: string, replies: string[]}>} data: the reply to the end of DATA
 */
export async function smtpSend({
	port, host = '127.0.0.1', from, to, data,
}) {
	const socket = net.createConnection(port, host);
	await once(socket, 'connect');
	socket.setEncoding('utf8');
	let buffer = '';
	const waiting = [];
	socket.on('data', chunk => {
		buffer += chunk;
		// A reply ends with a line "NNN text" (no dash after the code).
		const match = /(?:^|\r\n)(\d{3}) [^\r\n]*\r\n$/.exec(buffer);
		if (match && waiting.length > 0) {
			const reply = buffer;
			buffer = '';
			waiting.shift()(reply.trim());
		}
	});
	const read = () => new Promise(resolve => {
		waiting.push(resolve);
	});
	const command = line => {
		const reply = read();
		socket.write(`${line}\r\n`);
		return reply;
	};

	const replies = [await read()];
	replies.push(await command('EHLO client.example.org'), await command(`MAIL FROM:<${from}>`), await command(`RCPT TO:<${to}>`), await command('DATA'));
	const final = read();
	const body = data.replaceAll(/^\./gm, '..');
	socket.write(`${body}${body.endsWith('\r\n') ? '' : '\r\n'}.\r\n`);
	const reply = await final;
	replies.push(reply);
	socket.end('QUIT\r\n');
	return {data: reply, replies};
}

/**
 * Wait for a new message in a Maildir and return its content.
 * @param {string} maildir
 * @param {Set<string>} seen - names already there
 * @param {number} [timeout]
 * @returns {Promise<string|null>}
 */
export async function waitForDelivery(maildir, seen, timeout = 15_000) {
	const directory = path.join(maildir, 'new');
	const started = Date.now();
	while (Date.now() - started < timeout) {
		const fresh = existsSync(directory) ? readdirSync(directory).filter(name => !seen.has(name)) : [];
		if (fresh.length > 0) {
			seen.add(fresh[0]);
			return readFileSync(path.join(directory, fresh[0]), 'utf8');
		}

		await delay(200);
	}

	return null;
}

/**
 * Names of the messages already in a Maildir.
 * @param {string} maildir
 * @returns {Set<string>}
 */
export function delivered(maildir) {
	const directory = path.join(maildir, 'new');
	return new Set(existsSync(directory) ? readdirSync(directory) : []);
}
