import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {simpleParser} from 'mailparser';

// (no text made from HTML by mailparser: html-to-text takes quadratic time on
// deeply nested HTML, and fails on HTML nested a few thousand levels deep;
// getFeatures reads the text HTML shows instead)
const PARSER_OPTIONS = {
	skipHtmlToText: true, skipImageLinks: true, skipTextToHtml: true, skipTextLinks: true,
};

// The limits of mailparser (of mailsplit, which it splits messages with) that
// make it fail: more than 1000 MIME parts (an inline attached message is a
// part too), and a part's header over 1 MB.
const TOO_MANY_PARTS = 'Max allowed child nodes exceeded';
const HEADER_TOO_LARGE = 'Max header size for a MIME node exceeded';
// A message beyond them is read up to this many lines that may start a part
// ("--boundary"), and this many bytes of it if a part's header is too large.
const MAX_PART_LINES = 990;
const MAX_PREFIX_BYTES = 1_000_000;
// Of a message header too large, each line is read up to this many
// characters, each field up to this many, and if the whole is still too
// large, only the fields that say who sent the message and how.
const MAX_LINE = 998;
const MAX_FIELD = 8192;
const MAX_HEADER = 512 * 1024;
const MAX_REPEATED = 100;
const KEPT_FIELDS = new Set([
	'from', 'sender', 'reply-to', 'to', 'cc', 'subject', 'date', 'message-id', 'return-path', 'received', 'authentication-results', 'arc-authentication-results', 'dkim-signature', 'mime-version', 'content-type', 'content-transfer-encoding', 'list-unsubscribe', 'list-id',
]);

// Attached messages (message/rfc822, .eml) are opened this many levels deep,
// for at most this many attachments of theirs and this many bytes of attached
// messages (the message's own attachments are always all read).
const MAX_NESTED_DEPTH = 3;
const MAX_ATTACHMENTS = 100;
const MAX_NESTED_BYTES = 25 * 1024 * 1024;

/**
 * Parse a message with mailparser, which does not make text of HTML here:
 * `text` is that of the plain text parts only (empty for a message of HTML
 * alone), and the text HTML shows is read by getFeatures.
 * @param {Buffer|string} raw
 * @returns {Promise<object>} the parsed message
 */
export async function parseMessage(raw) {
	const buffer = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
	const mail = await simpleParser(finishable(buffer), PARSER_OPTIONS);
	// (without the line breaks that adds to the last part)
	const added = buffer.at(-1) === 0x0A ? 2 : 3;
	for (const key of ['text', 'html']) {
		if (typeof mail[key] === 'string') {
			mail[key] = mail[key].replace(new RegExp(`\\n{0,${added}}$`), '');
		}
	}

	// (and from an attachment left open at the end, as ClamAV and checksums
	//  read it: only one whose own bytes end the message, so not one closed
	//  by a boundary, nor one followed by another part or an epilogue, and
	//  only one not encoded, whose bytes are those of the message)
	const tail = Buffer.from('\r\n'.repeat(added));
	const last = mail.attachments?.at(-1);
	const encoding = String(last?.headers?.get?.('content-transfer-encoding') ?? '7bit').trim().toLowerCase();
	const own = Buffer.isBuffer(last?.content) && last.content.length >= tail.length && last.content.subarray(-tail.length).equals(tail) ? last.content.subarray(0, -tail.length) : null;
	if (own && ['7bit', '8bit', 'binary'].includes(encoding) && own.length <= buffer.length && buffer.subarray(buffer.length - own.length).equals(own)) {
		last.content = own;
		last.size = own.length;
		last.checksum = createHash('md5').update(own).digest('hex');
	}

	return mail;
}

/**
 * A message mailparser can finish: it never finishes one that ends in the
 * header of an attached message (however that header names or folds its
 * type, or only a file name like "fw.eml") without the blank line after it,
 * so every message gets one.
 * @param {Buffer|string} raw
 * @returns {Buffer}
 */
export function finishable(raw) {
	const buffer = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
	return Buffer.concat([buffer, Buffer.from(buffer.at(-1) === 0x0A ? '\r\n\r\n' : '\r\n\r\n\r\n')]);
}

// The message up to the start of the line at `offset` or before it.
function upToLine(raw, offset) {
	return raw.subarray(0, Math.max(raw.lastIndexOf(0x0A, offset - 1) + 1, 0));
}

// The message before its MAX_PART_LINES-th line that starts with "--", or,
// with fewer such lines (attached messages inline are parts without one),
// its first half.
function fewerParts(raw) {
	let offset = -1;
	for (let count = 0; count < MAX_PART_LINES; count++) {
		offset = raw.indexOf('\n--', offset + 1);
		if (offset === -1) {
			return upToLine(raw, Math.floor(raw.length / 2));
		}
	}

	return raw.subarray(0, offset + 1);
}

// The message with its header (up to the first blank line) cut down to
// MAX_LINE characters a line, MAX_FIELD a field, and the KEPT_FIELDS when
// the whole is over MAX_HEADER, so the sender is read whatever comes before.
function smallerHeader(raw) {
	const text = raw.toString('latin1');
	const blank = /\r?\n\r?\n/.exec(text);
	const end = blank ? blank.index : text.length;
	const fields = [];
	let start = 0;
	while (start < end) {
		let stop = text.indexOf('\n', start);
		stop = stop === -1 || stop > end ? end : stop;
		const line = text.slice(start, Math.min(stop, start + MAX_LINE)).replace(/\r$/, '');
		const last = fields.at(-1);
		if (last && (line.startsWith(' ') || line.startsWith('\t'))) {
			if (last.size + line.length <= MAX_FIELD) {
				last.lines.push(line);
				last.size += line.length;
			}
		} else {
			fields.push({name: line.slice(0, line.indexOf(':')).trim().toLowerCase(), lines: [line], size: line.length});
		}

		start = stop + 1;
	}

	const total = fields.reduce((sum, field) => sum + field.size, 0);
	// (and at most MAX_REPEATED of each, as hundreds of Received fields could
	//  still be too many)
	const counts = new Map();
	const kept = total > MAX_HEADER
		? fields.filter(field => {
			counts.set(field.name, (counts.get(field.name) || 0) + 1);
			return KEPT_FIELDS.has(field.name) && counts.get(field.name) <= MAX_REPEATED;
		})
		: fields;
	const header = kept.flatMap(field => field.lines).join('\r\n');
	return Buffer.concat([Buffer.from(`${header}\r\n\r\n`, 'latin1'), raw.subarray(blank ? blank.index + blank[0].length : raw.length)]);
}

/**
 * Parse a message, reading what can be read of one beyond mailparser's
 * limits (more than 1000 MIME parts, a part's header over 1 MB): its parts
 * before the 990th line that may start one (or its first half, again and
 * again, when attached messages inline make the parts), and, when a header
 * is too large, the message with its header lines cut down, or its first
 * megabyte when the header is that of a later part. `error` is the limit,
 * or null. Other errors are thrown, as earlier versions did (servers defer
 * the message).
 * @param {Buffer} raw
 * @param {(raw: Buffer) => Promise<object>} [parse] - for tests
 * @returns {Promise<{mail: object, error: string|null}>}
 */
export async function parseWithin(raw, parse = parseMessage) {
	let input = raw;
	let reason = null;
	for (;;) {
		try {
			// eslint-disable-next-line no-await-in-loop
			return {mail: await parse(input), error: reason};
		} catch (error) {
			const limit = error.code === 'EMAXLEN' && [TOO_MANY_PARTS, HEADER_TOO_LARGE].includes(error.message) ? error.message : null;
			let shorter = input;
			if (limit === TOO_MANY_PARTS) {
				shorter = fewerParts(input);
			} else if (limit === HEADER_TOO_LARGE) {
				shorter = smallerHeader(input);
				shorter = shorter.length < input.length ? shorter : upToLine(input, MAX_PREFIX_BYTES);
			}

			// (each try reads less, so this ends)
			if (shorter.length >= input.length) {
				throw error;
			}

			reason ??= limit;
			input = shorter;
		}
	}
}

/**
 * A message's attachments, with those of the messages attached to it (as a
 * forwarded message is), named after the message that carries them:
 * "fw.eml/invoice.exe". An attached message that cannot be read (beyond the
 * parser's limits, or failing it) never fails the scan: why goes to `errors`.
 * @param {Array<object>} attachments - mailparser attachments
 * @param {string[]} [errors] - gets why attached messages were not read whole
 * @param {(raw: Buffer) => Promise<object>} [parse] - for tests
 * @returns {Promise<Array<object>>}
 */
export async function expandAttachments(attachments = [], errors = [], parse = parseMessage) {
	const all = [];
	let budget = MAX_NESTED_BYTES;
	let nested = 0;
	const visit = async (list, prefix, depth) => {
		for (const attachment of list) {
			if (prefix) {
				if (nested >= MAX_ATTACHMENTS) {
					return;
				}

				nested++;
			}

			const name = attachment.filename || (prefix ? 'unnamed attachment' : '');
			all.push(prefix ? {...attachment, filename: `${prefix}/${name}`} : attachment);
			const {content} = attachment;
			const attached = attachment.contentType === 'message/rfc822' || /\.eml$/i.test(attachment.filename || '');
			if (attached && depth < MAX_NESTED_DEPTH && Buffer.isBuffer(content) && content.length <= budget) {
				budget -= content.length;
				let inner;
				try {
					// eslint-disable-next-line no-await-in-loop
					inner = await parseWithin(content, parse);
				} catch (error) {
					// (7.0.3 did not open attached messages, and one never failed it)
					errors.push(`${name || 'attached message'}: ${error.message}`);
					continue;
				}

				if (inner.error) {
					errors.push(inner.error);
				}

				// eslint-disable-next-line no-await-in-loop
				await visit(inner.mail.attachments, prefix ? `${prefix}/${name}` : (name || 'attached message'), depth + 1);
			}
		}
	};

	await visit(attachments, '', 0);
	return all;
}
