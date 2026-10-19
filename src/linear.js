import {createRequire} from 'node:module';

/**
 * Regular expressions for message content.
 *
 * A message can be made of anything, so every pattern used on its content is
 * written to match in linear time as a JavaScript regular expression: no two
 * quantifiers that can match the same text in a row, and repetition bounded
 * where a run of characters could otherwise be scanned again from every
 * position in it. When the optional re2 package is installed, the patterns
 * run on RE2, which guarantees linear time (and every pattern here is valid
 * RE2: no backreferences, no lookaround, repetition counts up to 1000). A
 * pattern finds the same text on either engine, but for a bounded run of a
 * class of Unicode properties, which is unbounded on RE2 (see BOUNDED).
 */

/**
 * The RE2 class from the re2 package, or null when it is not installed (or
 * cannot load, as in a single executable binary).
 * @param {Function} [load] - require()
 * @returns {Function|null}
 */
export function loadRe2(load = createRequire(import.meta.url)) {
	try {
		return load('re2');
	} catch {
		return null;
	}
}

const RE2 = loadRe2();

/**
 * Whether patterns run on RE2.
 * @type {boolean}
 */
export const usesRe2 = RE2 !== null;

// Repetition bounded so that JavaScript stays linear ({0,n} or {1,n}, n of 10
// or more). RE2 compiles each repetition separately, so a bounded class of
// Unicode properties ("[\p{L}]{1,64}") can exceed its size limit: that one
// is unbounded on RE2, which then finds a longer run of letters than
// JavaScript does. The local parts and host labels of email addresses
// (EMAIL_SOURCE and ADDRESS_SOURCE in tokenizer.js) are such classes: past 64
// and 63 characters, RE2 reads an address JavaScript reads only the end of,
// or not at all (in any script). Every other bound stays, so both engines
// find the same links and host names outside addresses (bounds that are
// those of DNS anyway).
const BOUNDED = /^{([01]),\d{2,}}/;

// JavaScript's \s (RE2's is ASCII only, without the no-break space that
// mailparser makes of "&nbsp;", or the ideographic space)
const WHITESPACE = String.raw`\t\n\x0B\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`;

/**
 * A JavaScript pattern for RE2, matching the same text: \s and \S as in
 * JavaScript, and a bounded repetition of a class of Unicode properties made
 * unbounded (see BOUNDED).
 * @param {string} source
 * @returns {string}
 */
export function re2Source(source) {
	let out = '';
	let inClass = false;
	// (whether the class read last has a Unicode property, and whether it is
	//  what a repetition after it repeats)
	let unicodeClass = false;
	let afterClass = false;
	for (let i = 0; i < source.length; i++) {
		const char = source[i];
		const repeats = afterClass;
		afterClass = false;
		if (char === '{' && !inClass && repeats && unicodeClass) {
			const bound = BOUNDED.exec(source.slice(i, i + 16));
			if (bound) {
				out += bound[1] === '0' ? '*' : '+';
				i += bound[0].length - 1;
				continue;
			}
		}

		if (char === '\\') {
			const next = source[++i] ?? '';
			if (inClass && (next === 'p' || next === 'P')) {
				unicodeClass = true;
			}

			if (next === 's') {
				out += inClass ? WHITESPACE : `[${WHITESPACE}]`;
			} else if (next === 'S') {
				if (inClass) {
					throw new TypeError(String.raw`\S inside a character class has no RE2 equivalent here`);
				}

				out += `[^${WHITESPACE}]`;
			} else {
				out += `\\${next}`;
			}

			continue;
		}

		if (char === '[' && !inClass) {
			inClass = true;
			unicodeClass = false;
		} else if (char === ']' && inClass) {
			inClass = false;
			afterClass = true;
		}

		out += char;
	}

	return out;
}

/**
 * A regular expression on RE2 when it is installed, otherwise a JavaScript
 * one (written to run in linear time either way).
 * @param {string} source
 * @param {string} [flags]
 * @param {Function|null} [Engine] - the RE2 class, or null for JavaScript
 * @returns {RegExp}
 */
export function linear(source, flags = '', Engine = RE2) {
	return Engine ? new Engine(re2Source(source), flags) : new RegExp(source, flags);
}

/**
 * Each match of a global pattern in text, found with exec from the start
 * (String.prototype.matchAll makes a copy of the pattern for each call, which
 * on RE2 compiles it again). A match of empty text moves on a character, so
 * the search always ends.
 * @param {RegExp} pattern - a pattern with the g flag
 * @param {string} text
 * @returns {Generator<RegExpExecArray>}
 */
export function * matchesOf(pattern, text) {
	pattern.lastIndex = 0;
	let match;
	while ((match = pattern.exec(text)) !== null) {
		if (match[0] === '') {
			pattern.lastIndex++;
		}

		yield match;
	}
}

/**
 * The string without any of `characters` at its end, by scanning back from
 * the end (a pattern such as /[).,]+$/ is tried at every position of a long
 * run of those characters).
 * @param {string} value
 * @param {string} characters
 * @returns {string}
 */
export function trimEndOf(value, characters) {
	let end = value.length;
	while (end > 0 && characters.includes(value[end - 1])) {
		end--;
	}

	return value.slice(0, end);
}

/**
 * Every tag replaced by `replacement`, as `html.replace(/<[^>]*>/g, ...)`
 * does: from each "<" to the next ">".  Found with indexOf, which reads each
 * character once: once no ">" follows, no later "<" has one either (the
 * regular expression would read the rest again from every "<").
 * @param {string} html
 * @param {string} [replacement]
 * @returns {string}
 */
export function replaceTags(html, replacement = ' ') {
	let out = '';
	let from = 0;
	let open = html.indexOf('<');
	while (open !== -1) {
		const close = html.indexOf('>', open + 1);
		if (close === -1) {
			break;
		}

		out += `${html.slice(from, open)}${replacement}`;
		from = close + 1;
		open = html.indexOf('<', from);
	}

	return out + html.slice(from);
}

/**
 * A pattern for a word of ASCII letters in either case, ASCII only.  (RE2
 * folds case as Unicode does, where "\u017F" is an "s" and "\u212A" a "k";
 * JavaScript does only with the u flag.)
 * @param {string} word
 * @returns {string}
 */
export function caseless(word) {
	return [...word].map(letter => `[${letter}${letter.toUpperCase()}]`).join('');
}

const FOLDS_TO_ASCII = /[\u017F\u212A]/g;

/**
 * Text with the two characters outside ASCII that fold to ASCII letters,
 * "\u017F" and "\u212A", as "s" and "k", as host names map them (UTS #46),
 * so that case-insensitive patterns read them alike on either engine.  (Each
 * is one UTF-16 unit, so positions in the text stay.)
 * @param {string} text
 * @returns {string}
 */
export function foldToAscii(text) {
	return text.replaceAll(FOLDS_TO_ASCII, character => character === '\u017F' ? 's' : 'k');
}

// (tag names: as browsers read them, "<\u017Fcript>" is no script)
const OPENER = linear(String.raw`<(${caseless('script')}|${caseless('style')})\b`, 'g');
const CLOSERS = {
	script: linear(String.raw`<\/${caseless('script')}\s*>`, 'g'),
	style: linear(String.raw`<\/${caseless('style')}\s*>`, 'g'),
};

/**
 * HTML without its script and style elements (their content included), with
 * every tag replaced by `replacement`.
 * @param {string} html
 * @param {string} [replacement]
 * @returns {string}
 */
export function stripTags(html, replacement = ' ') {
	if (typeof html !== 'string' || html === '') {
		return '';
	}

	// Once an element has no closing tag, no later one of its kind has, so
	// the rest is not searched again.
	const unclosed = new Set();
	let out = '';
	let from = 0;
	OPENER.lastIndex = 0;
	let match;
	while ((match = OPENER.exec(html)) !== null) {
		const name = match[1].toLowerCase();
		if (unclosed.has(name)) {
			continue;
		}

		const closer = CLOSERS[name];
		closer.lastIndex = match.index + match[0].length;
		const close = closer.exec(html);
		if (close === null) {
			unclosed.add(name);
			continue;
		}

		out += `${html.slice(from, match.index)}${replacement}`;
		from = close.index + close[0].length;
		OPENER.lastIndex = from;
	}

	out += html.slice(from);
	return replaceTags(out, replacement);
}
