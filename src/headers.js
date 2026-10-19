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
 * - X-Spam-Virus-Scan: failed, when ClamAV could not scan an attachment
 *
 * @param {{score: number, threshold: number, isSpam: boolean, action: string, tests: Array<{name: string}>, results?: {virusScanErrors?: Array<object>}}} result
 * @param {object} [options]
 * @param {string} [options.version]
 * @returns {Array<[string, string]>} header name and value pairs
 */
export function spamHeaders(result, options = {}) {
	const tests = result.tests.map(test => test.name).join(',') || 'none';
	const score = result.score.toFixed(1);
	const headers = [
		['X-Spam-Flag', result.isSpam ? 'YES' : 'NO'],
		['X-Spam-Score', score],
		['X-Spam-Level', '*'.repeat(Math.max(0, Math.min(50, Math.floor(result.score))))],
		['X-Spam-Status', `${result.isSpam ? 'Yes' : 'No'}, score=${score} required=${result.threshold.toFixed(1)} tests=${tests}${options.version ? ` version=${options.version}` : ''}`],
		['X-Spam-Action', result.action],
	];
	if (result.results?.virusScanErrors?.length > 0) {
		headers.push(['X-Spam-Virus-Scan', 'failed']);
	}

	return headers;
}

/**
 * Split a raw message into its header block and body, keeping every byte.
 * @param {Buffer} raw
 * @returns {{header: string, body: Buffer, newline: string}}
 */
export function splitMessage(raw) {
	const text = raw.toString('latin1');
	// (a message that starts with a blank line has no headers, only a body)
	const match = /^\r?\n|\r?\n\r?\n/.exec(text);
	if (!match) {
		const newline = text.includes('\n') && !text.includes('\r\n') ? '\n' : '\r\n';
		return {header: text.replace(/\r?\n$/, ''), body: Buffer.alloc(0), newline};
	}

	const newline = match[0].startsWith('\r') ? '\r\n' : '\n';
	return {header: text.slice(0, match.index), body: raw.subarray(Buffer.byteLength(text.slice(0, match.index + match[0].length), 'latin1')), newline};
}

// The most bytes of text in one encoded word of a subject tag: 39 bytes are
// 52 characters of base64, so "=?UTF-8?B?...?=" is 64 characters, under the
// 75 of RFC 2047, and fits after "Subject: " in the 76 characters RFC 2047
// allows a line with an encoded word.
const ENCODED_BYTES = 39;
// The longest word of a tag written as it is: a longer one is encoded, so the
// header can be folded within those 76 characters (and always within 998).
const PLAIN_WORD = 64;
// The longest line of a header with an encoded word (RFC 2047, section 2)
const ENCODED_LINE = 76;
// The longest line of a header (RFC 5322, section 2.1.1)
const MAX_LINE = 998;
// An encoded word (RFC 2047), and one that starts a value and is followed by
// a space or nothing, as a decoder reads it: not "=?not an encoded word"
const ENCODED_WORD = /=\?[^?\s]+\?[bq]\?[^?\s]*\?=/i;
const ENCODED_START = /^=\?[^?\s]+\?[bq]\?[^?]*\?=/i;

/**
 * A subject tag as it can go in a header: on one line, and, when it is not
 * printable ASCII, holds "=?" (which would read as the start of an encoded
 * word) or a word too long to fold, as encoded words (RFC 2047) of at most
 * 64 characters, split only between whole characters and separated by
 * spaces, so "[垃圾]" survives and a tag cannot add header lines. A tag empty
 * after cleanup is "".
 * @param {string} tag
 * @param {boolean} [spaceAfter] - for a tag before an encoded word: the space
 *   after an encoded tag goes inside it, since the space between two encoded
 *   words is not shown
 * @returns {string}
 */
export function subjectTagText(tag, spaceAfter = false) {
	const line = String(tag).replaceAll(/\p{Cc}+/gu, ' ').trim();
	if (line === '' || (/^[\u0020-\u007E]*$/.test(line) && !line.includes('=?') && line.split(' ').every(word => word.length <= PLAIN_WORD))) {
		return line;
	}

	const words = [];
	let chunk = '';
	for (const character of spaceAfter ? `${line} ` : line) {
		if (Buffer.byteLength(chunk + character, 'utf8') > ENCODED_BYTES) {
			words.push(chunk);
			chunk = '';
		}

		chunk += character;
	}

	words.push(chunk);
	return words.map(word => `=?UTF-8?B?${Buffer.from(word, 'utf8').toString('base64')}?=`).join(' ');
}

/**
 * A Subject header's value with a tag before it (see subjectTagText), folded
 * between the tag's words so a line with an encoded word stays within 76
 * characters, and before the subject when the line would be too long, or
 * null when the tag is empty or the subject already starts with it.
 * @param {string} tag
 * @param {string} current - the subject's value, as written, perhaps folded
 * @param {string} [newline]
 * @returns {string|null} the value, after "Subject: "
 */
export function taggedSubject(tag, current, newline = '\r\n') {
	const unfolded = current.replaceAll(/\r?\n/g, '');
	const plain = subjectTagText(tag);
	if (plain === '' || unfolded.startsWith(plain) || unfolded.startsWith(subjectTagText(tag, true))) {
		return null;
	}

	const text = subjectTagText(tag, ENCODED_START.test(current));
	const first = current.split(/\r?\n/)[0];
	// (a line with an encoded word, of the tag or of the subject)
	const encoded = text.startsWith('=?') || ENCODED_WORD.test(first);
	const lines = [];
	let line = 'Subject:';
	for (const [index, word] of text.split(' ').entries()) {
		if (index > 0 && word !== '' && line.length + 1 + word.length > ENCODED_LINE) {
			lines.push(line);
			line = '';
		}

		line += ` ${word}`;
	}

	if (current !== '') {
		if (line.length + 1 + first.length > (encoded ? ENCODED_LINE : MAX_LINE)) {
			lines.push(line);
			line = '';
		}

		line += ` ${current}`;
	}

	lines.push(line);
	return lines.join(newline).slice('Subject: '.length);
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
		const subject = kept.find(([first]) => /^subject\s*:/i.test(first));
		const value = taggedSubject(options.subjectTag, subject ? subject.join(newline).replace(/^subject\s*:\s*/i, '') : '', newline);
		if (value !== null) {
			const field = `Subject: ${value}`.split(/\r?\n/);
			if (subject) {
				subject.splice(0, subject.length, ...field);
			} else {
				kept.push(field);
			}
		}
	}

	const added = headers.map(([name, value]) => foldHeader(name, Buffer.from(String(value), 'utf8').toString('latin1'), newline));
	// (an mbox "From " line, as procmail passes a message, stays the first)
	const mbox = kept.length > 0 && kept[0][0].startsWith('From ') ? kept.shift() : [];
	const head = [...mbox, ...added, ...kept.map(field => field.join(newline))].join(newline);
	// (and no headers at all, but the blank line before the body)
	return Buffer.concat([Buffer.from(head === '' && header === '' ? newline : `${head}${newline}${newline}`, 'latin1'), body]);
}
