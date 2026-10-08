import {Buffer} from 'node:buffer';

/**
 * Fold a header value so lines stay near 78 characters, breaking after spaces
 * and after commas (as SpamAssassin does for its test lists).
 * @param {string} name
 * @param {string} value
 * @param {string} [newline]
 * @returns {string} the full header line(s), without a final line break
 */
export function foldHeader(name, value, newline = '\r\n') {
	const pieces = String(value).split(/(?<=[ ,])/);
	const lines = [];
	let line = `${name}: `;
	for (const piece of pieces) {
		if (line.length + piece.trimEnd().length > 78 && line.trim().length > name.length + 1) {
			lines.push(line.trimEnd());
			line = '\t';
		}

		line += piece;
	}

	lines.push(line.trimEnd());
	return lines.join(newline);
}

/**
 * The X-Spam headers for a scan result, in the format SpamAssassin uses, so
 * existing Sieve, procmail and mail client rules keep working.
 *
 * - X-Spam-Flag: YES or NO
 * - X-Spam-Score: the score, e.g. 7.3
 * - X-Spam-Level: one star per point (Sieve: header :contains "X-Spam-Level" "*****")
 * - X-Spam-Status: Yes or No, with score, threshold, tests and version
 * - X-Spam-Action: accept, tag or reject
 *
 * @param {{score: number, threshold: number, isSpam: boolean, action: string, tests: Array<{name: string}>}} result
 * @param {object} [options]
 * @param {string} [options.version]
 * @returns {Array<[string, string]>} header name and value pairs
 */
export function spamHeaders(result, options = {}) {
	const tests = result.tests.map(test => test.name).join(',') || 'none';
	const score = result.score.toFixed(1);
	return [
		['X-Spam-Flag', result.isSpam ? 'YES' : 'NO'],
		['X-Spam-Score', score],
		['X-Spam-Level', '*'.repeat(Math.max(0, Math.min(50, Math.floor(result.score))))],
		['X-Spam-Status', `${result.isSpam ? 'Yes' : 'No'}, score=${score} required=${result.threshold.toFixed(1)} tests=${tests}${options.version ? ` version=${options.version}` : ''}`],
		['X-Spam-Action', result.action],
	];
}

/**
 * Split a raw message into its header block and body, keeping every byte.
 * @param {Buffer} raw
 * @returns {{header: string, body: Buffer, newline: string}}
 */
export function splitMessage(raw) {
	const text = raw.toString('latin1');
	const match = /\r?\n\r?\n/.exec(text);
	if (!match) {
		const newline = text.includes('\n') && !text.includes('\r\n') ? '\n' : '\r\n';
		return {header: text.replace(/\r?\n$/, ''), body: Buffer.alloc(0), newline};
	}

	const newline = match[0].startsWith('\r\n') ? '\r\n' : '\n';
	return {header: text.slice(0, match.index), body: raw.subarray(Buffer.byteLength(text.slice(0, match.index + match[0].length), 'latin1')), newline};
}

/**
 * Add headers to a raw message and optionally tag its subject.
 *
 * Existing X-Spam-* headers are removed first: a sender could otherwise add
 * "X-Spam-Flag: NO" to slip past rules that trust it.
 *
 * @param {Buffer|string} source
 * @param {Array<[string, string]>} headers - added at the top, in order
 * @param {object} [options]
 * @param {string|null} [options.subjectTag] - prefix for the Subject, e.g. "[SPAM]"
 * @param {RegExp} [options.remove] - names of headers to remove (default: X-Spam-*)
 * @returns {Buffer}
 */
export function rewriteMessage(source, headers = [], options = {}) {
	const raw = Buffer.isBuffer(source) ? source : Buffer.from(String(source), 'utf8');
	const {header, body, newline} = splitMessage(raw);
	const remove = options.remove ?? /^x-spam-/i;
	const lines = header === '' ? [] : header.split(/\r?\n/);

	// Group folded lines with the header they continue.
	const fields = [];
	for (const line of lines) {
		if (/^[ \t]/.test(line) && fields.length > 0) {
			fields.at(-1).push(line);
		} else {
			fields.push([line]);
		}
	}

	const kept = fields.filter(([first]) => !remove.test(first.split(':')[0].trim()));
	if (options.subjectTag) {
		const tag = options.subjectTag;
		const subject = kept.find(([first]) => /^subject\s*:/i.test(first));
		if (subject) {
			const current = subject.join(newline).replace(/^subject\s*:\s*/i, '');
			if (!current.startsWith(tag)) {
				subject.splice(0, subject.length, `Subject: ${tag} ${current}`.split(/\r?\n/)[0], ...current.split(/\r?\n/).slice(1));
			}
		} else {
			kept.push([`Subject: ${tag}`]);
		}
	}

	const added = headers.map(([name, value]) => foldHeader(name, Buffer.from(String(value), 'utf8').toString('latin1'), newline));
	const head = [...added, ...kept.map(field => field.join(newline))].join(newline);
	return Buffer.concat([Buffer.from(`${head}${newline}${newline}`, 'latin1'), body]);
}
