import {Buffer} from 'node:buffer';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {MailParser, simpleParser} from 'mailparser';

// Address fields, which mailparser (of every MIME part's header) and mailauth
// (From and Return-Path of the message's header) read with nodemailer's
// addressparser: its time grows with the square of the number of addresses
// in a field, and with the length of the field times the number of groups
// nested in it ("g:g:g:..."), so a field of a megabyte took seconds, and
// minutes in mailauth. Each is read up to this many characters, this many
// "," and ";" and this many ":" in a group, and a message's (each attached
// message's) fields up to this many characters in all, always to the end of
// a whole address: what is cut is never part of an address, so no other
// address than one the field gives is read. A field cut gets `truncated`
// (mail.from.truncated), and a From field cut gives no credit for the
// sender's authentication (see trustedReputationValues and authenticate).
const ADDRESS_FIELDS = new Set(['from', 'to', 'cc', 'bcc', 'sender', 'reply-to', 'delivered-to', 'return-path', 'disposition-notification-to']);
const MAX_ADDRESS_FIELD = 16 * 1024;
const MAX_ADDRESS_SEPARATORS = 2000;
const MAX_ADDRESS_GROUPS = 16;
const MAX_ADDRESS_TOTAL = 64 * 1024;
// (the address fields mailauth reads with addressparser)
const AUTH_ADDRESS_FIELDS = new Set(['from', 'return-path']);
// (the characters addressparser reads as operators, with the one that ends
//  each: in a group, up to its ";", everything else is text)
const ADDRESS_OPERATORS = new Map([['"', '"'], ['(', ')'], ['<', '>'], [',', ''], [':', ';'], [';', '']]);
// (the fields mailparser reads one value of, the priority of any of four)
const SINGLE_FIELDS = new Set(['message-id', 'content-id', 'from', 'sender', 'in-reply-to', 'reply-to', 'subject', 'date', 'content-disposition', 'content-type', 'content-transfer-encoding', 'priority', 'mime-version', 'content-description', 'precedence', 'errors-to', 'disposition-notification-to']);
const PRIORITY_FIELDS = new Set(['priority', 'x-priority', 'x-msmail-priority', 'importance']);
const BOUNDED = Symbol('bounded address fields');
const ROOM = Symbol('room left for address fields');

// (no text made from HTML by mailparser: html-to-text takes quadratic time on
// deeply nested HTML, and fails on HTML nested a few thousand levels deep;
// getFeatures reads the text HTML shows instead)
const PARSER_OPTIONS = {
	skipHtmlToText: true, skipImageLinks: true, skipTextToHtml: true, skipTextLinks: true, [BOUNDED]: true,
};

// A header field "Name: value" (folded or not) up to the end of the last
// whole address within the limits, and at most `room` characters (but its
// name), as addressparser reads it: an address ends at a "," or ";" outside
// quotes, a comment, angle brackets and a group, or at the ";" ending a
// group. The field itself when it is within them.
function boundAddressField(line, room) {
	const start = line.indexOf(':') + 1;
	const limit = Math.min(line.length, MAX_ADDRESS_FIELD, room);
	let end = start;
	let expecting = '';
	let escaped = false;
	let separators = 0;
	let groups = 0;
	let index = start;
	for (; index < limit; index++) {
		const chr = line[index];
		if ((chr === ',' || chr === ';') && ++separators > MAX_ADDRESS_SEPARATORS) {
			break;
		}

		if (escaped) {
			escaped = false;
		} else if (expecting !== '' && chr === expecting) {
			expecting = '';
			end = chr === ';' ? index + 1 : end;
		} else if (expecting === '' && ADDRESS_OPERATORS.has(chr)) {
			expecting = ADDRESS_OPERATORS.get(chr);
			end = chr === ',' || chr === ';' ? index : end;
		} else if (expecting === '"' && chr === '\\') {
			escaped = true;
		}

		// (a group in a group is read again, and again, for each ":")
		if (chr === ':' && expecting === ';' && ++groups > MAX_ADDRESS_GROUPS) {
			break;
		}
	}

	return index === line.length ? line : line.slice(0, end).trimEnd();
}

// Header fields ({key, line}, key the name in lower case) with their address
// fields bounded (see boundAddressField), `budget.room` characters of them in
// all, and the names of the fields cut. `only`: just these fields (by
// default every address field and List-* field)
function boundAddressLines(lines, budget, only = null) {
	const cut = new Set();
	const bounded = lines.map(entry => {
		if (only ? !only.has(entry.key) : !ADDRESS_FIELDS.has(entry.key) && !entry.key.startsWith('list-')) {
			return entry;
		}

		const line = boundAddressField(entry.line, budget.room);
		budget.room = Math.max(budget.room - line.length, 0);
		if (line === entry.line) {
			return entry;
		}

		cut.add(entry.key);
		return {...entry, line};
	});
	return {lines: bounded, cut};
}

// Mailparser reads every header (the message's and each part's) with
// processHeaders: for a parser of parseMessage (only: others are given what
// they always were), with address fields bounded, a budget for each message,
// and those cut marked `truncated`. (simpleParser makes its own MailParser,
// so this is how its headers are reached.)
const {processHeaders} = MailParser.prototype;
MailParser.prototype.processHeaders = function (lines) {
	if (!this.options[BOUNDED]) {
		return processHeaders.call(this, lines);
	}

	this[ROOM] ??= {room: MAX_ADDRESS_TOTAL};
	const bounded = boundAddressLines(lines, this[ROOM]);
	const headers = processHeaders.call(this, bounded.lines);
	// (of a field given more than once that is read once, the last with a
	//  value, as mailparser read it before 3.9.40, which reads the first)
	const keyOf = entry => PRIORITY_FIELDS.has(entry.key) ? 'priority' : entry.key;
	const counts = new Map();
	for (const key of bounded.lines.map(entry => keyOf(entry)).filter(key => SINGLE_FIELDS.has(key))) {
		counts.set(key, (counts.get(key) || 0) + 1);
	}

	for (const key of [...counts.keys()].filter(key => counts.get(key) > 1)) {
		const last = bounded.lines.findLast(entry => keyOf(entry) === key && processHeaders.call(this, [entry]).has(key));
		if (last) {
			headers.set(key, processHeaders.call(this, [last]).get(key));
		}
	}

	// (List-* fields are read into "list")
	for (const value of [...bounded.cut].flatMap(key => headers.get(key) ?? [])) {
		value.truncated = true;
	}

	return headers;
};

/**
 * The message as mailauth is to read it: its address fields bounded as
 * parseMessage bounds them (mailauth reads From and Return-Path with the same
 * parser), and, when the header would take mailauth longer than linear time
 * (it joins folded lines, and finds the fields a DKIM signature names, in
 * time that grows with the square of their number), the header cut down:
 * its folded lines unfolded (which relaxed canonicalization of DKIM does
 * too) and only the fields that say who sent the message and how, as many
 * as smallerHeader keeps, each up to MAX_FIELD characters (address fields as
 * bounded), and at most MAX_SIGNATURES signatures. Only the first
 * MAX_DKIM_SIGNATURES DKIM-Signature fields are ever kept (with their folded
 * lines; the body is untouched). `fromCut` is whether a
 * From field was cut or left out: then mailauth did not read the From
 * address the message gives.
 * @param {Buffer} raw
 * @returns {{raw: Buffer, fromCut: boolean}}
 */
export function boundedForAuth(raw) {
	// (where mailauth finds the end of the header, and its fields: a line
	//  starting with white space continues the one before, and the name is
	//  up to the first ":")
	const ends = [raw.indexOf('\n\n'), raw.indexOf('\n\r\n')].filter(index => index !== -1);
	const end = ends.length > 0 ? Math.min(...ends) + 1 : raw.length;
	const body = raw.subarray(ends.length > 0 ? raw.indexOf(0x0A, end) + 1 : raw.length);
	const text = raw.subarray(0, end).toString('latin1');
	let {length} = text;
	while (length > 0 && (text[length - 1] === '\n' || text[length - 1] === '\r')) {
		length--;
	}

	const fields = [];
	let folds = 0;
	let work = 0;
	for (let start = 0; start <= length;) {
		let stop = text.indexOf('\n', start);
		stop = stop === -1 || stop > length ? length : stop;
		const lineEnd = stop > start && text[stop - 1] === '\r' ? stop - 1 : stop;
		const last = fields.at(-1);
		if (last && /\s/.test(text[start])) {
			last.end = lineEnd;
			last.folds++;
			folds++;
			// (each folded line is moved past the fields after it, and joined
			//  to the lines after it of its field)
			work += last.folds;
		} else {
			fields.push({start, end: lineEnd, folds: 0});
		}

		start = stop + 1;
	}

	let signatures = 0;
	let dkim = 0;
	for (const field of fields) {
		field.line = text.slice(field.start, field.end);
		const colon = field.line.indexOf(':');
		field.key = (colon === -1 ? field.line : field.line.slice(0, colon)).trim().toLowerCase();
		field.dropped = field.key === 'dkim-signature' && ++dkim > MAX_DKIM_SIGNATURES;
		if (SIGNATURE_FIELDS.has(field.key) && !field.dropped) {
			// (each field a signature names is looked for among all the fields)
			signatures += field.line.split(':').length - 1;
		}
	}

	const read = dkim > MAX_DKIM_SIGNATURES ? fields.filter(field => !field.dropped) : fields;
	work += (folds + signatures) * read.length;
	// (only From and Return-Path, the address fields mailauth reads: others,
	//  To and Cc among them, are often signed, and cutting them would fail a
	//  signature that holds)
	const bounded = boundAddressLines(read, {room: MAX_ADDRESS_TOTAL}, AUTH_ADDRESS_FIELDS);
	let kept = bounded.lines;
	let fromCut = bounded.cut.has('from');
	if (work > MAX_AUTH_WORK) {
		const counts = new Map();
		kept = kept.filter(field => {
			counts.set(field.key, (counts.get(field.key) || 0) + 1);
			const keep = AUTH_FIELDS.has(field.key) && counts.get(field.key) <= (SIGNATURE_FIELDS.has(field.key) ? MAX_SIGNATURES : MAX_REPEATED);
			fromCut ||= field.key === 'from' && !keep;
			return keep;
		}).map(field => {
			const line = field.line.replaceAll(/\r?\n(?=\s)/g, '');
			return {...field, line: ADDRESS_FIELDS.has(field.key) ? line : line.slice(0, MAX_FIELD)};
		});
	} else if (bounded.cut.size === 0 && read === fields) {
		return {raw, fromCut};
	}

	const header = kept.map(field => field.line).join('\r\n');
	return {raw: Buffer.concat([Buffer.from(`${header}\r\n\r\n`, 'latin1'), body]), fromCut};
}

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
// Of a header that would take mailauth too long (more than this much work,
// in its steps: see boundedForAuth), it reads these fields, and at most this
// many signatures.
const MAX_AUTH_WORK = 10_000_000;
const SIGNATURE_FIELDS = new Set(['dkim-signature', 'arc-message-signature']);
const AUTH_FIELDS = new Set([...KEPT_FIELDS, 'arc-seal', 'arc-message-signature']);
const MAX_SIGNATURES = 10;
/**
 * DKIM-Signature fields mailauth reads of a message (see boundedForAuth): it
 * checks every signature, hashing the body once for each body length (l=)
 * and canonicalization and looking up each signer's key, so hundreds of them
 * would hold up the process and send as many DNS queries. Real mail carries
 * one to three.
 */
export const MAX_DKIM_SIGNATURES = 8;

// Attached messages (message/rfc822, .eml) are opened this many levels deep,
// for at most this many attachments of theirs and this many bytes of attached
// messages (the message's own attachments are always all read).
const MAX_NESTED_DEPTH = 3;
const MAX_ATTACHMENTS = 100;
const MAX_NESTED_BYTES = 25 * 1024 * 1024;

// Milliseconds a message (with the tries of parseWithin), or all the messages
// attached to one, may take to parse. mailparser is driven by its own stream
// events alone, so a parse it never finishes leaves nothing pending: a scan
// that would never settle, or a process that exits with it unsettled.
export const PARSE_TIMEOUT = 60_000;

/**
 * The simpleParser of mailparser on a message it can finish (see finishable),
 * settled within `timeout`: a parse that has not settled by then is stopped
 * (its parser destroyed) and rejected with an ETIMEDOUT error.
 * @param {Buffer|string} raw
 * @param {object} [options]
 * @param {number} [options.timeout] - milliseconds (PARSE_TIMEOUT)
 * @param {typeof simpleParser} [options.parser] - for tests
 * @returns {Promise<object>} the parsed message
 */
export async function simpleParse(raw, {timeout = PARSE_TIMEOUT, parser = simpleParser} = {}) {
	// (a stream, not the buffer, so a parse that stalls can be stopped:
	//  simpleParser destroys its parser when its input fails; the input is
	//  not destroyed when it ends, so it can still fail)
	const input = Readable.from([finishable(unfoldHeaders(raw))], {objectMode: false, autoDestroy: false});
	input.on('error', () => {});
	// (and fails it on an error of the splitter that reads its parts, as
	//  where its limits are met: mailparser before 3.9.30 finishes instead on
	//  one that comes after the end of its input, as each one does with the
	//  mailsplit it uses, which splits a line at a time: with what it read so
	//  far, or never, as a parse that never finishes. Node.js 18 gets 3.9.21
	//  at most.)
	const {pipe} = input;
	input.pipe = function (parser, options) {
		parser.splitter?.on('error', error => input.destroy(error));
		return pipe.call(this, parser, options);
	};

	let timer;
	try {
		return await Promise.race([
			parser(input, PARSER_OPTIONS),
			new Promise((resolve, reject) => {
				timer = setTimeout(() => {
					const error = Object.assign(new Error(`Message not parsed within ${timeout} ms`), {code: 'ETIMEDOUT'});
					input.destroy(error);
					reject(error);
				}, timeout);
			}),
		]);
	} finally {
		clearTimeout(timer);
		input.destroy();
	}
}

/**
 * Parse a message with mailparser, which does not make text of HTML here:
 * `text` is that of the plain text parts only (empty for a message of HTML
 * alone), and the text HTML shows is read by getFeatures.
 * @param {Buffer|string} raw
 * @param {{timeout?: number}} [options] - milliseconds for the parse (PARSE_TIMEOUT)
 * @returns {Promise<object>} the parsed message
 */
export async function parseMessage(raw, options = {}) {
	const buffer = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
	const mail = await simpleParse(buffer, options);
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

// A header field folded on more lines than this is read unfolded: mailsplit
// before 5.4.18 (of mailparser before 3.9.30, as Node.js 18 gets) joins the
// lines of a field in time that grows with their number times its length,
// seconds for a field of a megabyte. Real fields are folded on a few lines; a
// list of a thousand recipients on a thousand.
const MAX_FOLDS = 256;

// The value and parameters of a header field ("Name: value; key=value"), as
// libmime (parseHeaderValue) reads them for mailsplit: `value` lower case.
function headerValue(line) {
	const parameters = new Map();
	let key = null;
	let inKey = false;
	let quoted = false;
	let escaped = false;
	let value = '';
	for (const chr of line.slice(line.indexOf(':') + 1).replaceAll(/\r?\n[ \t]*/g, ' ')) {
		if (inKey && chr === '=') {
			key = value.trim().toLowerCase();
			inKey = false;
			value = '';
		} else if (inKey || escaped) {
			value += chr;
			escaped = false;
		} else if (chr === '\\') {
			escaped = true;
		} else if (chr === '"') {
			quoted = !quoted;
		} else if (chr === ';' && !quoted) {
			parameters.set(key, value.trim());
			inKey = true;
			value = '';
		} else {
			value += chr;
		}
	}

	if (!inKey) {
		parameters.set(key, value.trim());
	}

	return {value: parameters.get(null).toLowerCase(), boundary: parameters.get('boundary') ?? ''};
}

// Whether the line at raw[start, stop) is a delimiter of `boundary` as
// mailsplit reads one: 1 "--boundary", 2 "--boundary--", 0 neither.
function delimiter(raw, start, stop, boundary) {
	const rest = start + 2 + boundary.length;
	if (stop - start < boundary.length + 2 || stop - rest > 4 || raw[start] !== 0x2D || raw[start + 1] !== 0x2D || !raw.subarray(start + 2, rest).equals(boundary)) {
		return 0;
	}

	if (raw[rest] === 0x0D || raw[rest] === 0x0A) {
		return 1;
	}

	// ("--", then <CR><LF>, <LF> or nothing)
	const tail = raw.subarray(rest, stop).toString('latin1');
	return /^-{0,2}$|^--\r?\n$|^--\r$/.test(tail) ? 2 : 0;
}

/**
 * The message with each header field folded on more than MAX_FOLDS lines
 * unfolded: its line breaks and the white space after each made one space,
 * as mailparser reads a field (libmime's decodeHeader), so what it reads is
 * the same. Header fields are those of the message and, as mailsplit finds
 * them, of each MIME part and each attached message inline; everything else
 * is left as it is. The message itself when nothing is unfolded.
 * @param {Buffer} raw
 * @returns {Buffer}
 */
export function unfoldHeaders(raw) {
	const boundaries = [];
	const unfold = [];
	let head = true;
	let fields = [];
	// (the end of a header: by a blank line, a part follows)
	const endHead = blank => {
		unfold.push(...fields.filter(field => field.folds > MAX_FOLDS));
		const first = new Map();
		for (const field of fields) {
			const name = raw.toString('latin1', field.start, Math.min(field.end, field.start + 32));
			const key = name.slice(0, name.indexOf(':')).trim().toLowerCase();
			if (['content-type', 'content-transfer-encoding', 'content-disposition'].includes(key) && !first.has(key)) {
				first.set(key, headerValue(raw.toString('latin1', field.start, field.end)));
			}
		}

		fields = [];
		const type = first.get('content-type') ?? {value: '', boundary: ''};
		const encoding = (first.get('content-transfer-encoding')?.value ?? '').replaceAll(/\(.*\)/g, '').trim();
		if (blank && type.boundary) {
			boundaries.push(Buffer.from(type.boundary));
		}

		// (an attached message inline: its header follows)
		head = blank && type.value === 'message/rfc822' && ['', '7bit', '8bit', 'binary'].includes(encoding) && first.get('content-disposition')?.value === 'inline';
	};

	for (let start = 0; start < raw.length;) {
		const lf = raw.indexOf(0x0A, start);
		const stop = lf === -1 ? raw.length : lf + 1;
		const end = lf === -1 ? stop : (raw[lf - 1] === 0x0D ? lf - 1 : lf);
		const kind = boundaries.length > 0 ? delimiter(raw, start, stop, boundaries.at(-1)) : 0;
		if (kind !== 0) {
			if (head) {
				endHead(false);
			}

			// (a part, or the end of the parts)
			head = kind === 1;
			if (kind === 2) {
				boundaries.pop();
			}
		} else if (head && end === start) {
			endHead(true);
		} else if (head && fields.length > 0 && (raw[start] === 0x20 || raw[start] === 0x09)) {
			fields.at(-1).end = end;
			fields.at(-1).folds++;
		} else if (head) {
			fields.push({start, end, folds: 0});
		}

		start = stop;
	}

	unfold.push(...fields.filter(field => field.folds > MAX_FOLDS));
	if (unfold.length === 0) {
		return raw;
	}

	const chunks = [];
	let copied = 0;
	for (const field of unfold) {
		chunks.push(raw.subarray(copied, field.start), Buffer.from(raw.toString('latin1', field.start, field.end).replaceAll(/\r?\n[ \t]*/g, ' '), 'latin1'));
		copied = field.end;
	}

	chunks.push(raw.subarray(copied));
	return Buffer.concat(chunks);
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
// the whole is over MAX_HEADER, so the sender is read whatever comes before;
// address fields are cut to whole addresses instead (see boundAddressField).
// `fromCut` is whether a From field was cut or left out.
function smallerHeader(raw) {
	const text = raw.toString('latin1');
	const blank = /\r?\n\r?\n/.exec(text);
	const end = blank ? blank.index : text.length;
	const fields = [];
	let start = 0;
	while (start < end) {
		let stop = text.indexOf('\n', start);
		stop = stop === -1 || stop > end ? end : stop;
		const last = fields.at(-1);
		const whole = text.slice(start, stop).replace(/\r$/, '');
		if (last && (whole.startsWith(' ') || whole.startsWith('\t'))) {
			const line = last.address ? whole : whole.slice(0, MAX_LINE);
			if (last.address || last.size + line.length <= MAX_FIELD) {
				last.lines.push(line);
				last.size += line.length;
			}
		} else {
			const name = whole.slice(0, whole.indexOf(':')).trim().toLowerCase();
			const address = ADDRESS_FIELDS.has(name) || name.startsWith('list-');
			const line = address ? whole : whole.slice(0, MAX_LINE);
			fields.push({
				name, address, lines: [line], size: line.length,
			});
		}

		start = stop + 1;
	}

	let fromCut = false;
	for (const field of fields.filter(field => field.address)) {
		const line = field.lines.join('\r\n');
		const bounded = boundAddressField(line, Number.POSITIVE_INFINITY);
		fromCut ||= field.name === 'from' && bounded !== line;
		field.lines = [bounded];
		field.size = bounded.length;
	}

	const total = fields.reduce((sum, field) => sum + field.size, 0);
	// (and at most MAX_REPEATED of each, as hundreds of Received fields could
	//  still be too many)
	const counts = new Map();
	const kept = total > MAX_HEADER
		? fields.filter(field => {
			counts.set(field.name, (counts.get(field.name) || 0) + 1);
			const keep = KEPT_FIELDS.has(field.name) && counts.get(field.name) <= MAX_REPEATED;
			fromCut ||= field.name === 'from' && !keep;
			return keep;
		})
		: fields;
	const header = kept.flatMap(field => field.lines).join('\r\n');
	return {raw: Buffer.concat([Buffer.from(`${header}\r\n\r\n`, 'latin1'), raw.subarray(blank ? blank.index + blank[0].length : raw.length)]), fromCut};
}

/**
 * Parse a message, reading what can be read of one beyond mailparser's
 * limits (more than 1000 MIME parts, a part's header over 1 MB): its parts
 * before the 990th line that may start one (or its first half, again and
 * again, when attached messages inline make the parts), and, when a header
 * is too large, the message with its header lines cut down, or its first
 * megabyte when the header is that of a later part. `error` is the limit,
 * or null. Other errors are thrown, as earlier versions did (servers defer
 * the message), and so is a parse not finished by `deadline` (ETIMEDOUT).
 * @param {Buffer} raw
 * @param {(raw: Buffer, options: {timeout: number}) => Promise<object>} [parse] - for tests
 * @param {number} [deadline] - Date.now() milliseconds by which every try
 *   ends (PARSE_TIMEOUT from now)
 * @returns {Promise<{mail: object, error: string|null}>}
 */
export async function parseWithin(raw, parse = parseMessage, deadline = Date.now() + PARSE_TIMEOUT) {
	let input = raw;
	let reason = null;
	let fromCut = false;
	for (;;) {
		try {
			// eslint-disable-next-line no-await-in-loop
			const mail = await parse(input, {timeout: Math.max(1, deadline - Date.now())});
			// (a From field cut down is marked as parseMessage marks one)
			if (fromCut && mail.from) {
				mail.from.truncated = true;
			}

			return {mail, error: reason};
		} catch (error) {
			const limit = error.code === 'EMAXLEN' && [TOO_MANY_PARTS, HEADER_TOO_LARGE].includes(error.message) ? error.message : null;
			let shorter = input;
			if (limit === TOO_MANY_PARTS) {
				shorter = fewerParts(input);
			} else if (limit === HEADER_TOO_LARGE) {
				const smaller = smallerHeader(input);
				shorter = smaller.raw.length < input.length ? smaller.raw : upToLine(input, MAX_PREFIX_BYTES);
				fromCut ||= smaller.raw === shorter && smaller.fromCut;
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
	// (one time limit for all of them)
	const deadline = Date.now() + PARSE_TIMEOUT;
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
					inner = await parseWithin(content, parse, deadline);
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
