import {Buffer} from 'node:buffer';
import {createReadStream} from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createInterface} from 'node:readline';
import {createGunzip} from 'node:zlib';

// Files in a directory that are never messages.
const SKIP = new Set(['.DS_Store', 'Thumbs.db', 'dovecot.index', 'dovecot.index.log', 'dovecot.index.cache', 'dovecot-uidlist', 'dovecot-keywords', 'maildirfolder', 'subscriptions']);

function lines(file) {
	let stream = createReadStream(file);
	if (file.endsWith('.gz')) {
		stream = stream.pipe(createGunzip());
	}

	return createInterface({input: stream, crlfDelay: Infinity});
}

/**
 * Read the messages in an mbox file (mboxo or mboxrd; gzip is fine).
 * @param {string} file
 * @returns {AsyncGenerator<string>}
 */
export async function * readMbox(file) {
	let current = null;
	for await (const line of lines(file)) {
		if (line.startsWith('From ')) {
			if (current !== null && current.length > 0) {
				yield current.join('\n');
			}

			current = [];
			continue;
		}

		if (current === null) {
			// Text before the first separator is not a message.
			continue;
		}

		// Mboxrd escapes "From " at line starts with one or more ">".
		current.push(/^>+From /.test(line) ? line.slice(1) : line);
	}

	if (current !== null && current.length > 0) {
		yield current.join('\n');
	}
}

/**
 * Split one line of comma-separated values (RFC 4180 quoting) into fields.
 * Returns null when a quoted field continues on the next line.
 * @param {string} line
 * @returns {string[]|null}
 */
export function parseCsvLine(line) {
	const fields = [];
	let field = '';
	let quoted = false;
	for (let i = 0; i < line.length; i++) {
		const char = line[i];
		if (quoted) {
			if (char === '"' && line[i + 1] === '"') {
				field += '"';
				i++;
			} else if (char === '"') {
				quoted = false;
			} else {
				field += char;
			}
		} else if (char === '"' && field === '') {
			quoted = true;
		} else if (char === ',') {
			fields.push(field);
			field = '';
		} else {
			field += char;
		}
	}

	if (quoted) {
		return null;
	}

	fields.push(field);
	return fields;
}

const SPAM_LABELS = new Set(['1', 'spam', 'junk', 'phishing', 'phish', 'scam', 'phishing email', 'true', 'yes']);
const HAM_LABELS = new Set(['0', 'ham', 'legit', 'legitimate', 'not spam', 'not_spam', 'safe email', 'normal', 'false', 'no']);

/**
 * Turn a dataset label ("spam", "1", "Phishing Email", "ham", "0", ...) into
 * "spam" or "ham", or null when it is neither.
 * @param {unknown} value
 * @returns {'spam'|'ham'|null}
 */
export function normalizeLabel(value) {
	const label = String(value ?? '').trim().toLowerCase();
	if (SPAM_LABELS.has(label)) {
		return 'spam';
	}

	if (HAM_LABELS.has(label)) {
		return 'ham';
	}

	return null;
}

/**
 * Read labelled rows from a CSV file with a header row.
 * @param {string} file
 * @param {object} [options]
 * @param {string} [options.textColumn] - column holding the message (default: text, message, body, email text...)
 * @param {string} [options.labelColumn] - column holding the label (default: label, category, is_spam...)
 * @param {string} [options.subjectColumn]
 * @returns {AsyncGenerator<{text: string, subject: string, label: 'spam'|'ham'}>}
 */
export async function * readCsv(file, options = {}) {
	let header = null;
	let pending = '';
	let columns;
	for await (const line of lines(file)) {
		const joined = pending ? `${pending}\n${line}` : line;
		const fields = parseCsvLine(joined);
		if (fields === null) {
			pending = joined;
			continue;
		}

		pending = '';
		if (header === null) {
			header = fields.map(name => name.trim().toLowerCase());
			columns = resolveColumns(header, options, file);
			continue;
		}

		const label = normalizeLabel(fields[columns.label]);
		const text = fields[columns.text];
		if (label && typeof text === 'string' && text.trim() !== '') {
			yield {text, subject: columns.subject === -1 ? '' : (fields[columns.subject] || ''), label};
		}
	}
}

function resolveColumns(header, options, file) {
	const find = (wanted, defaults) => {
		const names = wanted ? [wanted.toLowerCase()] : defaults;
		return header.findIndex(name => names.includes(name));
	};

	const columns = {
		text: find(options.textColumn, ['text', 'message', 'body', 'email text', 'email', 'content', 'sms', 'v2']),
		label: find(options.labelColumn, ['label', 'category', 'is_spam', 'spam', 'email type', 'class', 'type', 'label_text', 'v1', 'labels']),
		subject: find(options.subjectColumn, ['subject']),
	};
	if (columns.text === -1 || columns.label === -1) {
		throw new Error(`${file}: could not find the text and label columns (header: ${header.join(', ')}). Name them with textColumn and labelColumn.`);
	}

	return columns;
}

// The first of the named fields that is present in a row.
function pick(row, wanted, names) {
	const name = (wanted ? [wanted] : names).find(key => row[key] !== undefined && row[key] !== null);
	return name === undefined ? undefined : row[name];
}

/**
 * Read labelled rows from a JSON Lines file: one object per line with a text
 * field ("text", "message", "body") and a label field ("label", "label_text",
 * "is_spam", "category").
 * @param {string} file
 * @param {object} [options] - textColumn, labelColumn, subjectColumn as for readCsv
 * @returns {AsyncGenerator<{text: string, subject: string, label: 'spam'|'ham'}>}
 */
export async function * readJsonl(file, options = {}) {
	for await (const line of lines(file)) {
		if (line.trim() === '') {
			continue;
		}

		let row;
		try {
			row = JSON.parse(line);
		} catch {
			continue;
		}

		const text = pick(row, options.textColumn, ['text', 'message', 'body', 'content']);
		const label = normalizeLabel(pick(row, options.labelColumn, ['label_text', 'label', 'is_spam', 'category', 'labels']));
		if (label && typeof text === 'string' && text.trim() !== '') {
			yield {text, subject: String(pick(row, options.subjectColumn, ['subject']) ?? ''), label};
		}
	}
}

async function * walk(directory) {
	const entries = await fs.readdir(directory, {withFileTypes: true});
	// Byte order, the same on every system.
	entries.sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
	for (const entry of entries) {
		if (SKIP.has(entry.name) || entry.name.startsWith('.')) {
			continue;
		}

		const full = path.join(directory, entry.name);
		if (entry.isDirectory()) {
			// Maildir "tmp" holds messages still being written.
			if (entry.name !== 'tmp') {
				yield * walk(full);
			}
		} else if (entry.isFile()) {
			yield full;
		}
	}
}

function looksLikeMbox(head) {
	return /^From \S+/.test(head);
}

/**
 * Read raw messages from a path: an .eml file, an mbox file, or a directory
 * of messages (one per file, such as a Maildir or a folder of .eml files,
 * searched recursively; mbox files inside are read too).
 * @param {string} source
 * @returns {AsyncGenerator<string|Buffer>}
 */
export async function * readMessages(source) {
	const stat = await fs.stat(source);
	const files = stat.isDirectory() ? walk(source) : [source];
	for await (const file of files) {
		const handle = await fs.open(file);
		let head;
		try {
			const {buffer, bytesRead} = await handle.read(Buffer.alloc(64), 0, 64, 0);
			head = buffer.subarray(0, bytesRead).toString('latin1');
		} finally {
			await handle.close();
		}

		if (file.endsWith('.mbox') || file.endsWith('.mbox.gz') || looksLikeMbox(head)) {
			yield * readMbox(file);
		} else if (!file.endsWith('.gz')) {
			yield await fs.readFile(file);
		}
	}
}
