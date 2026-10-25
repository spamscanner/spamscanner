import {Buffer} from 'node:buffer';
import {isIP} from 'node:net';
import {parse as parseDomain} from 'tldts';
import {extensionOf as savedExtensionOf} from './attachments.js';
import {lookupName} from './dnsbl.js';
import {decodeEntities} from './html.js';
import {unwrapLink} from './tokenizer.js';

//
// Every link host of a message and of what it carries, for the link checks
// (Cloudflare, domain blocklists): the classifier reads the start of a
// message, and extractLinks pairs an anchor with its end, so this reads the
// whole text and HTML again, in linear time, as a mail client or browser
// shows it:
// - the attributes a browser follows or loads, read tag by tag as a browser
//   reads them (each value in turn, so a quoted value cannot hide another
//   attribute; character references decoded; tabs and line breaks removed;
//   "//host" is a link too), and an iframe's srcdoc and a data: URL's HTML,
//   SVG or XML document as documents of their own
// - the same attributes wherever they appear, read leniently (a quote opened
//   in a comment, a script or a style cannot hide the links after it), and
//   `url()` and `@import` in styles
// - links in the text: "http://", "https://", "www.", "example.com/page"
//   and, as far as there is room, "example.com" (names under a real
//   top-level domain, not file names, nor names in the path of a link)
// - attached messages (as expandAttachments opened them), HTML, SVG and XML
//   files, text files, and calendar invitations and contact cards as their
//   programs show them
//

const LINK_ATTRIBUTES = new Set([
	'href',
	'src',
	'srcset',
	'background',
	'action',
	'formaction',
	'poster',
	'cite',
	'longdesc',
	'xlink:href',
	'style',
	'data',
	'ping',
	// (of a <meta> refresh: "0;url=https://example.com/")
	'content',
	// (a document of its own, see linksOf)
	'srcdoc',
]);
const TAG_START = /<[a-z][^\s/>]*/gi;
const URL_START = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;
const CSS_URL = /url\(\s*["']?([^()"']*)/gi;
const CSS_IMPORT = /@import\s+["']([^"'<>]*)/gi;
// (an attribute that is a link wherever it appears, e.g. in a comment; its
//  value is read up to its quote, or to "<" or ">", and an unquoted one to a
//  space, a quote or "=", so no value is read twice)
const LENIENT = /[\s"'/<](href|src|srcset|background|action|formaction|poster|cite|longdesc|xlink:href|style|data|ping|content|srcdoc)\s*=\s*/gi;
// (a letter, digit or mark of any script, "_" or "%": part of a word, so a
//  name cannot start after it)
const IN_WORD = /[\p{L}\p{N}\p{M}_%]/u;
// (the namespaces of XHTML and SVG, which no mail client follows)
const NAMESPACES = new Set(['www.w3.org', 'w3.org']);
// (no more is read of a name than a host name can be)
const MAX_HOST = 760;
// (the most values or names kept to read each once)
const MAX_SEEN = 100_000;
// (punctuation a link in text ends before: a sentence's, a parenthesis's)
const TRAILING = new Set([')', '.', ',', ';', ':', '!', '?', '\'', '"', ']']);
// (HTML decoded for its text this much at a time: decoding takes several
//  times the memory of what it decodes)
const DECODE_CHUNK = 1024 * 1024;
const CHUNK_OVERLAP = 4096;
// (documents held in others, an iframe's srcdoc or a data: URL, read at most
//  so deep, so many and of so many characters in all)
const MAX_EMBED_DEPTH = 3;
const MAX_EMBEDDED = 1000;
const MAX_EMBEDDED_LENGTH = 10 * 1024 * 1024;
// (HTML files read, at most so many, as many as attached messages are opened,
//  and of so many bytes in all, with text files; and all of it read for at
//  most so long)
const MAX_ATTACHED = 100;
const MAX_ATTACHED_BYTES = 50 * 1024 * 1024;
const MAX_READ_TIME = 5000;
// (an invitation or a contact card read in every way its programs show it,
//  of at most so many characters without its photos: one of more is not
//  decoded from quoted-printable, so one with a value in it is too complex)
const MAX_SHOWN_BYTES = 4 * 1024 * 1024;

// Whether a character is one of a host name ("a" to "z", digits, "-", ".")
function isHostCode(code) {
	return (code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57) || code === 45 || code === 46;
}

function isSpace(code) {
	return code === 32 || (code >= 9 && code <= 13);
}

// A link as a browser reads it, http or https only
function urlOf(value) {
	// (control characters and spaces around it removed, and tabs and line
	//  breaks in it; then the punctuation a link in text ends before)
	let href = value.replaceAll(/[\t\n\r]/g, '');
	let start = 0;
	let end = href.length;
	while (start < end && href.codePointAt(start) <= 32) {
		start++;
	}

	while (end > start && href.codePointAt(end - 1) <= 32) {
		end--;
	}

	while (end > start && TRAILING.has(href[end - 1])) {
		end--;
	}

	href = href.slice(start, end);
	// ("//host", and "\\host", "/\host" and "\/host" as a browser reads them)
	if (/^[\\/]{2}/.test(href)) {
		href = `https://${href.slice(2)}`;
	} else if (/^www\./i.test(href)) {
		href = `http://${href}`;
	} else if (!/^https?:/i.test(href)) {
		return null;
	}

	let url;
	try {
		url = new URL(href);
	} catch {
		return null;
	}

	return url.protocol === 'http:' || url.protocol === 'https:' ? url : null;
}

// A host as it is looked up (see lookupName), an address as it is, or null
function hostOfUrl(url) {
	let host = url.hostname.toLowerCase();
	let dots = host.length;
	while (dots > 0 && host[dots - 1] === '.') {
		dots--;
	}

	host = host.slice(0, dots);
	if (host.startsWith('[') && host.endsWith(']')) {
		host = host.slice(1, -1);
	}

	if (!host || NAMESPACES.has(host)) {
		return null;
	}

	return isIP(host) ? host : lookupName(host);
}

// The host of a link, and that of the link a security gateway (Safe Links,
// URL Defense) sends it on to, as unwrapLink reads it (`unresolved`: wrapped
// deeper than it unwraps, so where it ends is not known)
function hostsOf(value) {
	const url = urlOf(value);
	if (!url) {
		return [];
	}

	const host = hostOfUrl(url);
	const hosts = host ? [host] : [];
	const target = unwrapLink(url.href);
	if (target && target.href !== url.href) {
		const targetHost = hostOfUrl(target);
		if (targetHost && targetHost !== host) {
			hosts.push(targetHost);
		}

		const further = unwrapLink(target.href);
		if (further && further.href !== target.href) {
			hosts.unresolved = true;
		}
	}

	return hosts;
}

// The attributes of each tag, as a browser reads them: a name, and its value
// (quoted, or up to a space or ">")
function * attributesOf(html) {
	TAG_START.lastIndex = 0;
	let match;
	while ((match = TAG_START.exec(html)) !== null) {
		let i = match.index + match[0].length;
		while (i < html.length && html[i] !== '>') {
			if (isSpace(html.codePointAt(i)) || html[i] === '/') {
				i++;
				continue;
			}

			let j = i;
			while (j < html.length && html[j] !== '=' && html[j] !== '>' && html[j] !== '/' && !isSpace(html.codePointAt(j))) {
				j++;
			}

			// (a name of nothing, e.g. a stray "=": skipped)
			const name = html.slice(i, j).toLowerCase();
			if (j === i) {
				j++;
			}

			while (j < html.length && isSpace(html.codePointAt(j))) {
				j++;
			}

			if (html[j] !== '=') {
				i = j;
				continue;
			}

			j++;
			while (j < html.length && isSpace(html.codePointAt(j))) {
				j++;
			}

			let value;
			if (html[j] === '"' || html[j] === '\'') {
				const close = html.indexOf(html[j], j + 1);
				const stop = close === -1 ? html.length : close;
				value = html.slice(j + 1, stop);
				j = stop + 1;
			} else {
				const start = j;
				while (j < html.length && html[j] !== '>' && !isSpace(html.codePointAt(j))) {
					j++;
				}

				value = html.slice(start, j);
			}

			if (name) {
				yield [name, value];
			}

			i = j;
		}

		TAG_START.lastIndex = Math.max(i, match.index + 1);
	}
}

// The links in an attribute's value (`embed`: for a document it holds, an
// iframe's srcdoc, read as HTML of its own)
function linksOf(name, value, add, embed) {
	const decoded = decodeEntities(value, {attribute: true});
	switch (name) {
		case 'srcdoc': {
			embed(decoded);
			break;
		}

		case 'style': {
			for (const [, link] of decoded.matchAll(CSS_URL)) {
				add(link);
			}

			break;
		}

		case 'srcset': {
			for (const candidate of decoded.split(',')) {
				add(candidate.trim().split(/\s/, 1)[0]);
			}

			break;
		}

		// (several, separated by spaces)
		case 'ping': {
			for (const link of decoded.split(/\s+/)) {
				add(link);
			}

			break;
		}

		// (only the address of a refresh)
		case 'content': {
			const match = /(?:^|[\s;,])url\s*=\s*["']?([^\s"';]+)/i.exec(decoded.slice(0, 4096));
			if (match) {
				add(match[1]);
			}

			break;
		}

		default: {
			add(decoded);
		}
	}
}

// (the most of a quoted value read past a "<" or ">" in it)
const MAX_LENIENT_VALUE = 4096;
// (where an unquoted value ends, besides a space)
const UNQUOTED_END = new Set(['<', '>', '"', '\'', '`', '=']);

// The attributes that are links, read leniently (see LENIENT)
function lenientLinks(html, add, done, embed) {
	LENIENT.lastIndex = 0;
	let match;
	while (!done() && (match = LENIENT.exec(html)) !== null) {
		const name = match[1].toLowerCase();
		let i = LENIENT.lastIndex;
		let end = i;
		if (html[i] === '"' || html[i] === '\'') {
			const quote = html[i];
			i++;
			end = i;
			while (end < html.length && html[end] !== quote && html[end] !== '<' && html[end] !== '>') {
				end++;
			}

			// (and, where it stopped at "<" or ">", up to its quote: a browser
			//  reads a quoted value whole, "https://x<y>@evil.example" goes to
			//  evil.example)
			if (end < html.length && html[end] !== quote) {
				const close = html.indexOf(quote, end);
				if (close !== -1 && close - i <= MAX_LENIENT_VALUE) {
					linksOf(name, html.slice(i, close), add, embed);
				}
			}
		} else {
			while (end < html.length && !isSpace(html.codePointAt(end)) && !UNQUOTED_END.has(html[end])) {
				end++;
			}
		}

		linksOf(name, html.slice(i, end), add, embed);
	}
}

// (a character a link in text ends at: a space of any kind, "<", ">", a quote
//  or a backtick)
function endsLink(text, i) {
	const code = text.codePointAt(i);
	if (code < 128) {
		return isSpace(code) || code === 34 || code === 39 || code === 60 || code === 62 || code === 96;
	}

	return /\s/u.test(text[i]);
}

// Whether "://" is in the characters before a position, up to a character a
// link ends at: for positions in increasing order, each character read once
function linkReader(text) {
	let read = 0;
	let space = -1;
	let scheme = -1;
	return start => {
		for (; read < start; read++) {
			if (endsLink(text, read)) {
				space = read;
			} else if (text[read] === '/' && text[read - 1] === '/' && text[read - 2] === ':') {
				scheme = read;
			}
		}

		return scheme > space;
	};
}

// (whether the name at `start`, after "/", is after "//" that begins a link
//  without its scheme: "//example.net/", not "a.example//b.example/")
function isSchemeless(text, start) {
	if (start < 2 || text[start - 2] !== '/') {
		return false;
	}

	if (start === 2) {
		return true;
	}

	const before = text[start - 3];
	return !(before === ':' || before === '/' || isHostCode(text.codePointAt(start - 3)));
}

// A name from its labels, from its top-level domain back over at most eleven
// labels before it, as extractLinks reads one, under a real top-level domain
function bareName(name) {
	const labels = name.split('.');
	const tld = labels.pop();
	if (!/^(?:[a-z]{2,24}|xn--[a-z\d-]{1,59})$/i.test(tld)) {
		return null;
	}

	const names = [];
	while (labels.length > 0 && names.length < 11) {
		const label = labels.pop();
		if (!/^[a-z\d-]{1,63}$/i.test(label)) {
			break;
		}

		names.unshift(label);
	}

	if (names.length === 0) {
		return null;
	}

	names[0] = names[0].replace(/^-+/, '');
	if (!names[0]) {
		return null;
	}

	return `${names.join('.')}.${tld}`.toLowerCase();
}

function isRealName(host) {
	const parsed = parseDomain(host);
	return Boolean(parsed.isIcann && parsed.domain);
}

// "example.com/page": the name before each "/" (each read back at most to the
// "/" before it, so the text is read once), without a port or dots after it
// (`from`: the first position a name may start at; `cutEnd`: the text was cut
//  at its end, where a name is not read)
function bareHosts(text, add, {done, seen, from = 0, cutEnd = false}) {
	let previous = -1;
	const inLink = linkReader(text);
	for (let slash = text.indexOf('/'); slash !== -1; slash = text.indexOf('/', slash + 1)) {
		if (done()) {
			return;
		}

		const floor = Math.max(previous + 1, slash - MAX_HOST);
		previous = slash;
		let end = slash;
		while (end > floor && text.codePointAt(end - 1) >= 48 && text.codePointAt(end - 1) <= 57) {
			end--;
		}

		end = end > floor && text[end - 1] === ':' ? end - 1 : slash;
		let start = end;
		while (start > floor && isHostCode(text.codePointAt(start - 1))) {
			start--;
		}

		if (start === end || start < from || (cutEnd && slash === text.length - 1)) {
			continue;
		}

		// (not the end of a word in another script, "straße.de/", nor a name in
		//  the path of a link, "github.com/x/example.net/"; but "//example.net/"
		//  is one; nor a name in a link read as one already)
		if ((start > 0 && (IN_WORD.test(text[start - 1]) || (text[start - 1] === '/' && !isSchemeless(text, start)))) || inLink(start)) {
			continue;
		}

		while (end > start && text[end - 1] === '.') {
			end--;
		}

		const host = bareName(text.slice(start, end));
		if (!host || seen.has(host)) {
			continue;
		}

		if (seen.size < MAX_SEEN) {
			seen.add(host);
		}

		// (only under a real top-level domain: not "file.js/")
		if (isRealName(host)) {
			add(`http://${host}/`);
		}
	}
}

// "example.com", "example.com?x", "example.com:8080" and "example.com." at the
// end of a sentence: a name with no "/" after it, as mail clients make a link
// of, under a real top-level domain; not part of an address, a word or a path,
// nor in a link read as one already; each run of host characters read once
function looseHosts(text, add, {from = 0, cutEnd = false, seen, done}) {
	const inLink = linkReader(text);
	const {length} = text;
	let i = 0;
	while (i < length) {
		if (!isHostCode(text.codePointAt(i))) {
			i++;
			continue;
		}

		const start = i;
		while (i < length && isHostCode(text.codePointAt(i))) {
			i++;
		}

		let end = i;
		if (end - start > MAX_HOST || start < from || (cutEnd && end === length)) {
			continue;
		}

		while (end > start && text[end - 1] === '.') {
			end--;
		}

		const before = start > 0 ? text[start - 1] : '';
		const after = end < length ? text[end] : '';
		if (after === '/' || after === '@' || before === '@') {
			continue;
		}

		if (before && (IN_WORD.test(before) || before === '/' || before === '\\' || before === '&' || before === '#')) {
			continue;
		}

		if (after && after !== '.' && IN_WORD.test(after)) {
			continue;
		}

		const name = text.slice(start, end);
		if (!name.includes('.') || inLink(start)) {
			continue;
		}

		const lower = name.toLowerCase();
		if (seen.has(lower)) {
			continue;
		}

		if (seen.size < MAX_SEEN) {
			seen.add(lower);
		}

		if (done()) {
			return;
		}

		const host = bareName(name);
		if (host && isRealName(host)) {
			add(host);
		}
	}
}

// The parts of `html` to decode one at a time, each cut at "<" or a space
// (where no character reference or link of the text goes on), or, in a part
// with neither, cut anyway with the next part starting a little before (so no
// link is cut in two) (`cutStart` and `cutEnd`: whether a part starts or ends
// where it was cut anyway)
function * chunksOf(html) {
	let start = 0;
	let cutStart = false;
	while (start < html.length) {
		const end = Math.min(html.length, start + DECODE_CHUNK);
		if (end < html.length) {
			let cut = end;
			while (cut > end - 65_536 && cut > start) {
				if (html[cut] === '<' || isSpace(html.codePointAt(cut))) {
					break;
				}

				cut--;
			}

			if (cut > start && cut > end - 65_536) {
				yield {text: html.slice(start, cut), cutStart, cutEnd: false};
				start = cut;
				cutStart = false;
				continue;
			}

			yield {text: html.slice(start, end), cutStart, cutEnd: true};
			start = end - CHUNK_OVERLAP;
			cutStart = true;
			continue;
		}

		yield {text: html.slice(start, end), cutStart, cutEnd: false};
		start = end;
	}
}

// Text with a NUL in it, as UTF-16 a mail client decodes by a label mailparser
// does not know ("unicode", "ucs-2"): the text, and the same without its NULs
function withoutNul(text) {
	return text.includes('\0') ? `${text}\n${text.replaceAll('\0', '')}` : text;
}

// A hexadecimal digit's value, by its character code, or -1
function hexValue(code) {
	if (code >= 48 && code <= 57) {
		return code - 48;
	}

	if (code >= 65 && code <= 70) {
		return code - 55;
	}

	if (code >= 97 && code <= 102) {
		return code - 87;
	}

	return -1;
}

// The bytes of a URL's "%XX" escapes and its other characters (as UTF-8)
function percentDecoded(text) {
	const input = Buffer.from(text);
	const output = Buffer.allocUnsafe(input.length);
	let length = 0;
	for (let i = 0; i < input.length; i++) {
		const high = input[i] === 37 ? hexValue(input[i + 1]) : -1;
		const low = high === -1 ? -1 : hexValue(input[i + 2]);
		if (low === -1) {
			output[length++] = input[i];
			continue;
		}

		output[length++] = (high * 16) + low;
		i += 2;
	}

	return output.subarray(0, length);
}

// (the labels browsers read as UTF-16, see the WHATWG Encoding Standard)
const UTF16LE = new Set(['csunicode', 'iso-10646-ucs-2', 'ucs-2', 'unicode', 'unicodefeff', 'utf-16', 'utf-16le']);
const UTF16BE = new Set(['unicodefffe', 'utf-16be']);

function swapped(bytes) {
	return Buffer.from(bytes.subarray(0, bytes.length - (bytes.length % 2))).swap16().toString('utf16le');
}

// Text by its byte order mark (UTF-16 as browsers read it), else by its
// charset when it is UTF-16, else UTF-8
function decodeText(content, charset = '') {
	if (content[0] === 0xFF && content[1] === 0xFE) {
		return content.subarray(2).toString('utf16le');
	}

	if (content[0] === 0xFE && content[1] === 0xFF) {
		return swapped(content.subarray(2));
	}

	if (UTF16LE.has(charset)) {
		return content.toString('utf16le');
	}

	return UTF16BE.has(charset) ? swapped(content) : content.toString('utf8');
}

// The HTML, SVG or XML document a data: URL holds (a browser renders one in an
// iframe or object), or null for other data
const DATA_DOCUMENT = /^\s*data:\s*(?:text\/html|application\/xhtml\+xml|image\/svg\+xml|text\/xml|application\/xml)\b([^,]*),/i;
function dataDocument(value) {
	const match = DATA_DOCUMENT.exec(value.slice(0, 1024));
	if (!match) {
		return null;
	}

	const bytes = percentDecoded(value.slice(match[0].length));
	const content = /;\s*base64\s*$/i.test(match[1]) ? Buffer.from(bytes.toString('latin1'), 'base64') : bytes;
	const charset = /;\s*charset\s*=\s*"?([^;"\s]+)/i.exec(match[1]);
	return decodeText(content, charset ? charset[1].toLowerCase() : '');
}

//
// Calendar invitations and contact cards, as their programs show them
//

// (line breaks as vCard and calendar readers find them, also a CR alone; and
//  a fold, a line break and a space or tab)
const LINE_BREAK = /\r\n?|\n/;
const FOLD = /(?:\r\n?|\n)[ \t]/g;
// (a property's parameters marking its value quoted-printable)
const QUOTED_PRINTABLE = /;\s*(?:encoding\s*=\s*)?"?quoted-printable"?\s*(?:;|$)/i;
// (properties whose binary value is a photo, logo, sound, key or file)
const MEDIA_PROPERTIES = new Set(['photo', 'logo', 'sound', 'key', 'attach']);
// (an invitation's descriptions in HTML)
const HTML_PROPERTIES = /^(?:x-alt-desc|styled-description|description|comment)[;:]/i;

// (in one pass, "\\n" is a backslash and "n"; `lenient`: a backslash before
//  any other character is that character; in linear time, joined in batches)
function readEscapes(text, lenient = false) {
	let index = text.indexOf('\\');
	if (index === -1) {
		return text;
	}

	let out = '';
	let parts = [];
	let start = 0;
	while (index !== -1 && index + 1 < text.length) {
		const next = text[index + 1];
		if (lenient || 'nN,;\\'.includes(next)) {
			parts.push(text.slice(start, index), next === 'n' || next === 'N' ? '\n' : next);
			start = index + 2;
			index = text.indexOf('\\', start);
			if (parts.length >= 65_536) {
				out += parts.join('');
				parts = [];
			}
		} else {
			index = text.indexOf('\\', index + 1);
		}
	}

	parts.push(text.slice(start));
	return out + parts.join('');
}

// (where a property line's value starts: after its first ":" outside a
//  quoted parameter value; in linear time however many quoted values it has)
function valueColon(line) {
	let colon = line.indexOf(':');
	let from = 0;
	for (;;) {
		const quote = line.indexOf('"', from);
		if (quote === -1 || colon === -1 || colon < quote) {
			return colon;
		}

		const end = line.indexOf('"', quote + 1);
		if (end === -1) {
			return -1;
		}

		from = end + 1;
		if (colon < from) {
			colon = line.indexOf(':', from);
		}
	}
}

function trimSpaceEnd(text) {
	let end = text.length;
	while (end > 0 && (text[end - 1] === ' ' || text[end - 1] === '\t')) {
		end--;
	}

	return end === text.length ? text : text.slice(0, end);
}

// (as bytes, "=XX" the byte it is, decoded once by its charset, else as UTF-8;
//  with other than ASCII not encoded, each run of "=XX" so)
function decodeQuotedPrintable(value, charset) {
	let decoder;
	try {
		decoder = new TextDecoder(charset || 'utf8');
	} catch {
		decoder = new TextDecoder('utf8');
	}

	if (!/[\u0080-\u{10FFFF}]/u.test(value)) {
		const bytes = Buffer.from(value, 'latin1');
		let length = 0;
		for (let index = 0; index < bytes.length; index++) {
			const hex = bytes[index] === 0x3D ? value.slice(index + 1, index + 3) : '';
			if (/^[\da-f]{2}$/i.test(hex)) {
				bytes[length++] = Number.parseInt(hex, 16);
				index += 2;
			} else {
				bytes[length++] = bytes[index];
			}
		}

		return decoder.decode(bytes.subarray(0, length));
	}

	return value.replaceAll(/(?:=[\da-f]{2})+/gi, run => decoder.decode(Buffer.from(run.replaceAll('=', ''), 'hex')));
}

// (a vCard 2.1 property line whose value is quoted-printable: its value
//  decoded by its CHARSET, with the lines it continues with a "=" at its end)
function quotedPrintableValues(text) {
	if (!/quoted-printable/i.test(text)) {
		return text;
	}

	const lines = text.split(LINE_BREAK);
	const out = [];
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		const colon = valueColon(line);
		const parameters = colon === -1 ? '' : line.slice(0, colon);
		if (colon === -1 || !QUOTED_PRINTABLE.test(parameters)) {
			out.push(line);
			continue;
		}

		const charset = /;\s*charset\s*=\s*"?([\w.:-]+)/i.exec(parameters)?.[1];
		const parts = [trimSpaceEnd(line.slice(colon + 1))];
		while (parts.at(-1).endsWith('=') && i + 1 < lines.length) {
			parts[parts.length - 1] = parts.at(-1).slice(0, -1);
			parts.push(trimSpaceEnd(lines[++i]));
		}

		out.push(line.slice(0, colon + 1) + decodeQuotedPrintable(parts.join(''), charset));
	}

	return out.join('\n');
}

// (whether a property line has a value in quoted-printable)
function hasQuotedPrintable(text) {
	const unfolded = text.replaceAll(FOLD, '');
	if (!/quoted-printable/i.test(unfolded)) {
		return false;
	}

	return unfolded.split(LINE_BREAK).some(line => {
		const colon = valueColon(line);
		return colon !== -1 && QUOTED_PRINTABLE.test(line.slice(0, colon));
	});
}

// An invitation's or a contact card's text as its programs show it: its lines
// unfolded and its escapes read (and with a backslash before any other
// character read as that character, "https\://"); with a vCard 2.1 value in
// quoted-printable decoded, by its charset, also with its folds kept; and as
// it is; one past MAX_SHOWN_BYTES (`full` false) not decoded
function shownText(text, full = true) {
	const unfolded = text.replaceAll(FOLD, '');
	const shown = new Set([text, readEscapes(unfolded)]);
	let decoded = unfolded;
	if (full) {
		decoded = quotedPrintableValues(unfolded);
		if (decoded !== unfolded) {
			shown.add(readEscapes(decoded));
			if (unfolded !== text) {
				shown.add(quotedPrintableValues(text));
			}
		}
	}

	if (/\\[^nN,;\\]/.test(decoded)) {
		shown.add(readEscapes(decoded, true));
	}

	return [...shown].reverse().join('\n');
}

// An invitation's descriptions in HTML: an X-ALT-DESC (Outlook),
// STYLED-DESCRIPTION (RFC 9073), or a DESCRIPTION or COMMENT with markup in it
// (Google Calendar), each unfolded with its escapes read; and the document an
// ALTREP parameter names, as a frame (Thunderbird)
function htmlDescriptions(text) {
	if (!/[<&]|altrep/i.test(text)) {
		return '';
	}

	const html = [];
	for (const line of text.replaceAll(FOLD, '').split(LINE_BREAK)) {
		const colon = valueColon(line);
		if (colon === -1) {
			continue;
		}

		const altrep = /;\s*altrep\s*=\s*"([^"]*)"/i.exec(line.slice(0, colon))?.[1];
		if (altrep) {
			html.push(`<iframe src="${altrep.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;')}"></iframe>`);
		}

		if (!HTML_PROPERTIES.test(line)) {
			continue;
		}

		const value = readEscapes(line.slice(colon + 1));
		if (/[<&]/.test(value)) {
			html.push(value);
		}
	}

	return html.join('\n');
}

// A card's or an invitation's text without the base64 values of its binary
// properties, photos and the like, which its programs never show as text (with
// a vCard 2.1 reader's lines of base64 after it, up to a blank line); one of
// another property decoded, as a reader may show it; a value marked so that is
// not base64, a link, as it is
const BINARY = /;\s*(?:(?:encoding\s*=\s*)?"?(?:b|base64)"?|value\s*=\s*"?binary"?)\s*(?:;|$)/i;
function withoutBinaryValues(text) {
	if (!/base64|binary|encoding\s*=\s*"?b|;\s*b\s*[;:]/i.test(text)) {
		return text;
	}

	const lines = text.split(LINE_BREAK);
	const out = [];
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i];
		const colon = valueColon(line);
		if (colon === -1 || !BINARY.test(line.slice(0, colon))) {
			out.push(line);
			continue;
		}

		const value = [line.slice(colon + 1)];
		let next = i + 1;
		while (next < lines.length && (lines[next].startsWith(' ') || lines[next].startsWith('\t'))) {
			value.push(lines[next++]);
		}

		if (!value.every(part => /^[\w+/=\s]*$/.test(part))) {
			for (let index = i; index < next; index++) {
				out.push(lines[index]);
			}

			i = next - 1;
			continue;
		}

		while (next < lines.length && lines[next] !== '' && /^[\w+/=]+$/.test(lines[next])) {
			value.push(lines[next++]);
		}

		if (next < lines.length && lines[next] === '') {
			next++;
		}

		i = next - 1;
		const name = line.slice(0, colon).split(';')[0].split('.').pop().trim().toLowerCase();
		out.push(MEDIA_PROPERTIES.has(name)
			? line.slice(0, colon + 1)
			: line.slice(0, colon + 1) + Buffer.from(value.join('').replaceAll(/\s/g, ''), 'base64').toString('utf8'));
	}

	return out.join('\n');
}

//
// The documents a message carries, read for their links
//

// what a browser renders as HTML: by content type or file name (XML as XHTML
// or SVG by its namespace)
const HTML_TYPES = new Set(['text/html', 'application/xhtml+xml', 'image/svg+xml', 'text/xml', 'application/xml']);
const HTML_EXTENSIONS = new Set(['html', 'htm', 'shtml', 'xhtml', 'xht', 'svg', 'xml']);
// Invitations and contact cards, whose URL fields a mail client shows as
// links, by type and by name
const CARD_TYPES = new Set(['text/calendar', 'text/x-vcalendar', 'application/ics', 'text/vcard', 'text/x-vcard', 'text/directory']);
const CARD_EXTENSIONS = new Set(['ics', 'ical', 'ifb', 'vcs', 'vcf', 'vcard']);
const MESSAGE_TYPES = new Set(['message/rfc822', 'message/global']);

// The extension of a name, lowercased, after the dots and spaces at its end
function extensionOf(filename) {
	let end = filename.length;
	while (end > 0 && (filename[end - 1] === '.' || filename[end - 1] === ' ')) {
		end--;
	}

	const name = filename.slice(0, end).trim().toLowerCase();
	const index = name.lastIndexOf('.');
	return index !== -1 && index < name.length - 1 ? name.slice(index + 1) : null;
}

// The extensions of the names an attachment goes by: mailparser's, and its
// Content-Type "name" and Content-Disposition "filename", which a mail client
// may show instead; each also as Windows saves it ("page.html::$DATA",
// direction controls removed), see the attachment checks
function extensionsOf(attachment) {
	const names = [];
	if (typeof attachment.filename === 'string') {
		names.push(attachment.filename);
	}

	const {headers} = attachment;
	if (headers && typeof headers.get === 'function') {
		for (const [field, parameter] of [['content-type', 'name'], ['content-disposition', 'filename']]) {
			const value = headers.get(field)?.params?.[parameter];
			if (typeof value === 'string' && value !== '') {
				names.push(value);
			}
		}
	}

	return new Set(names.flatMap(name => [extensionOf(name), savedExtensionOf(name)]).filter(Boolean));
}

function charsetOf(attachment) {
	const {headers} = attachment;
	const charset = headers && typeof headers.get === 'function' ? headers.get('content-type')?.params?.charset : null;
	return typeof charset === 'string' ? charset.toLowerCase() : '';
}

// The documents of attachments a mail client shows, or opens in a browser:
// HTML, SVG and XML files, text files, and invitations and contact cards
// (`tooComplex`: more of them than are read, or of more bytes, or a card past
//  what is read with a value in quoted-printable; `incomplete`: one was left
//  unread past the time they are read for)
function documentsOf(attachments, until) {
	const documents = [];
	let bytes = 0;
	let opened = 0;
	for (const attachment of attachments) {
		const {content} = attachment ?? {};
		if (!Buffer.isBuffer(content) || content.length === 0) {
			continue;
		}

		const type = typeof attachment.contentType === 'string' ? attachment.contentType.toLowerCase() : '';
		const extensions = extensionsOf(attachment);
		const has = set => [...extensions].some(name => set.has(name));
		if (MESSAGE_TYPES.has(type) || extensions.has('eml') || extensions.has('u8msg')) {
			continue;
		}

		const isHtml = HTML_TYPES.has(type) || has(HTML_EXTENSIONS);
		const isCard = !isHtml && (CARD_TYPES.has(type) || has(CARD_EXTENSIONS));
		const isText = isCard || (!isHtml && type === 'text/plain');
		if (!isHtml && !isText) {
			continue;
		}

		if ((!isText && ++opened > MAX_ATTACHED) || bytes + content.length > MAX_ATTACHED_BYTES) {
			documents.tooComplex = true;
			return documents;
		}

		if (Date.now() > until) {
			documents.incomplete = true;
			return documents;
		}

		bytes += content.length;
		const text = decodeText(content, charsetOf(attachment));
		if (isHtml) {
			documents.push({html: text});
			continue;
		}

		if (!isCard) {
			documents.push({text});
			continue;
		}

		const readable = withoutBinaryValues(text);
		const full = readable.length <= MAX_SHOWN_BYTES;
		// (its links not all read; what follows is read)
		if (!full && hasQuotedPrintable(readable)) {
			documents.tooComplex = true;
			continue;
		}

		documents.push({text: shownText(readable, full)});
		const html = htmlDescriptions(readable);
		if (html !== '') {
			documents.push({html});
		}
	}

	return documents;
}

/**
 * The link hosts of a message and of what it carries, as they are looked up
 * (see lookupName; an address as it is), in the order they are found, up to
 * `maxHosts`; names with no "/" after them come last, as far as there is
 * room, as text that is not a link may read as one.
 * @param {object} mail - the message, as mailparser parsed it
 * @param {object} [options]
 * @param {object[]} [options.mails] - the messages attached to it, opened (see expandAttachments)
 * @param {object[]} [options.attachments] - its attachments and theirs (see expandAttachments)
 * @param {number} [options.maxHosts]
 * @param {boolean} [options.hostsInText] - also names with no "/" after them, "evil.example", as mail clients make links of them
 * @returns {{hosts: string[], more: boolean, tooComplex: boolean, incomplete: boolean}} `more`: it has more hosts, so not every link was read; `tooComplex`: a link whose host was never read whole (it runs past where the text is cut to be read, it is wrapped deeper than unwrapLink unwraps, or in more documents than are read); `incomplete`: an attachment was left unread for time
 */
export function carriedLinkHosts(mail, {
	mails = [], attachments = [], maxHosts = 250, hostsInText = false,
} = {}) {
	const hosts = new Set();
	const loose = new Set();
	const seen = new Set();
	const seenBare = new Set();
	const seenLoose = new Set();
	let more = false;
	let tooComplex = false;
	const done = () => more;
	const looseDone = () => more || loose.size > maxHosts;
	const addLoose = host => {
		if (!looseDone()) {
			loose.add(host);
		}
	};

	// (all of it read for at most MAX_READ_TIME: past it, the rest is not)
	const until = Date.now() + MAX_READ_TIME;
	let incomplete = false;
	const late = () => {
		if (!incomplete && Date.now() > until) {
			incomplete = true;
		}

		return incomplete;
	};

	const carried = documentsOf(attachments, until);
	tooComplex = Boolean(carried.tooComplex);
	incomplete = Boolean(carried.incomplete);
	const queue = [mail, ...mails, ...carried].map(document => ({document, depth: 0}));
	let depth = 0;
	let embedded = 0;
	let embeddedLength = 0;
	const embed = html => {
		if (depth >= MAX_EMBED_DEPTH || embedded >= MAX_EMBEDDED || embeddedLength + html.length > MAX_EMBEDDED_LENGTH) {
			tooComplex = true;
			return;
		}

		embedded++;
		embeddedLength += html.length;
		queue.push({document: {html}, depth: depth + 1});
	};

	const add = value => {
		// (once there are more hosts than are looked up, the rest need not be read)
		if (more || typeof value !== 'string' || value === '' || seen.has(value)) {
			return;
		}

		if (seen.size < MAX_SEEN) {
			seen.add(value);
		}

		// (a document a data: URL holds, read as HTML of its own)
		if (/^\s*data:/i.test(value)) {
			const html = dataDocument(value);
			if (html !== null) {
				embed(html);
			}

			return;
		}

		const found = hostsOf(value);
		if (found.unresolved) {
			tooComplex = true;
		}

		for (const host of found) {
			if (hosts.has(host)) {
				continue;
			}

			if (hosts.size >= maxHosts) {
				more = true;
				return;
			}

			hosts.add(host);
		}
	};

	const readText = (source, {cutStart = false, cutEnd = false} = {}) => {
		for (const match of source.matchAll(URL_START)) {
			if (more) {
				break;
			}

			// (not one a part starts within: read in the part before it)
			if (cutStart && match.index === 0) {
				continue;
			}

			// (one cut at the end of a part: read here when its host ends before
			//  the cut, else whole in the next part, which overlaps it; one whose
			//  host runs further is never read whole)
			if (cutEnd && match.index + match[0].length === source.length) {
				const value = match[0];
				const at = /^www\./i.test(value) ? 0 : value.indexOf('//') + 2;
				if (/[/?#\\]/.test(value.slice(at))) {
					add(value);
				} else if (source.length - match.index > CHUNK_OVERLAP) {
					tooComplex = true;
				}

				continue;
			}

			add(match[0]);
		}

		const from = cutStart ? 1 : 0;
		bareHosts(source, add, {
			done, seen: seenBare, from, cutEnd,
		});
		if (hostsInText && !looseDone()) {
			looseHosts(source, addLoose, {
				from, cutEnd, seen: seenLoose, done: looseDone,
			});
		}
	};

	for (const element of queue) {
		if (more || late()) {
			break;
		}

		({depth} = element);
		const {document} = element;
		const html = withoutNul(typeof document?.html === 'string' ? document.html : '');
		const text = withoutNul(typeof document?.text === 'string' ? document.text : '');
		for (const [name, value] of attributesOf(html)) {
			if (more) {
				break;
			}

			if (LINK_ATTRIBUTES.has(name)) {
				linksOf(name, value, add, embed);
			}
		}

		lenientLinks(html, add, done, embed);
		for (const pattern of [CSS_URL, CSS_IMPORT]) {
			for (const [, link] of html.matchAll(pattern)) {
				if (more) {
					break;
				}

				add(decodeEntities(link, {attribute: true}));
			}
		}

		if (!more) {
			readText(text);
		}

		for (const chunk of chunksOf(html)) {
			if (more || late()) {
				break;
			}

			readText(decodeEntities(chunk.text), chunk);
		}
	}

	// (then the names with no "/" after them, as far as there is room)
	if (!more && !incomplete) {
		for (const name of loose) {
			if (hosts.size >= maxHosts) {
				break;
			}

			const [host] = hostsOf(`http://${name}/`);
			if (host) {
				hosts.add(host);
			}
		}
	}

	return {
		hosts: [...hosts], more, tooComplex, incomplete,
	};
}
