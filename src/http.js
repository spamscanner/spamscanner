import {Buffer} from 'node:buffer';
import http from 'node:http';
import https from 'node:https';

/**
 * Send an HTTP request and read a JSON reply, with one deadline for the whole
 * exchange and a limit on the reply's size.
 * @param {'GET'|'POST'} method
 * @param {string} url
 * @param {object|null} body - sent as JSON
 * @param {object} [options]
 * @param {Record<string, string>} [options.headers]
 * @param {number} [options.timeout] - milliseconds for the whole request
 * @param {number} [options.maxResponseBytes]
 * @param {string|Buffer} [options.ca] - extra certificate authority, for self-hosted servers
 * @returns {Promise<any>}
 */
export function requestJson(method, url, body, options = {}) {
	const {headers = {}, timeout = 30_000, maxResponseBytes = 1_048_576, ca} = options;
	const target = new URL(url);
	const transport = target.protocol === 'https:' ? https : http;
	const payload = body === null || body === undefined ? null : Buffer.from(JSON.stringify(body));
	return new Promise((resolve, reject) => {
		let settled = false;
		const finish = (error, value) => {
			if (settled) {
				return;
			}

			settled = true;
			clearTimeout(timer);
			if (error) {
				reject(error);
			} else {
				resolve(value);
			}
		};

		const request = transport.request(target, {
			method,
			headers: {
				accept: 'application/json',
				'user-agent': 'spamscanner',
				...(payload ? {'content-type': 'application/json', 'content-length': payload.length} : {}),
				...headers,
			},
			...(ca ? {ca} : {}),
		}, response => {
			const chunks = [];
			let size = 0;
			response.on('data', chunk => {
				size += chunk.length;
				if (size > maxResponseBytes) {
					request.destroy();
					finish(new Error(`Response from ${target.origin} larger than ${maxResponseBytes} bytes`));
					return;
				}

				chunks.push(chunk);
			});
			response.on('end', () => {
				const text = Buffer.concat(chunks).toString('utf8');
				if (response.statusCode < 200 || response.statusCode >= 300) {
					const error = new Error(`HTTP ${response.statusCode} from ${target.origin}${target.pathname}: ${text.slice(0, 300)}`);
					error.statusCode = response.statusCode;
					finish(error);
					return;
				}

				try {
					finish(null, JSON.parse(text));
				} catch {
					finish(new Error(`Invalid JSON from ${target.origin}${target.pathname}: ${text.slice(0, 200)}`));
				}
			});
		});
		const timer = setTimeout(() => {
			request.destroy();
			finish(new Error(`Request to ${target.origin}${target.pathname} timed out after ${timeout} ms`));
		}, timeout);
		request.on('error', error => finish(error));
		request.end(payload ?? undefined);
	});
}
