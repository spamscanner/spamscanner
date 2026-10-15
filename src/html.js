import {caseless, linear} from './linear.js';

// Named character references for the characters of Latin-1 (160 to 255, in
// order) and the other ones mail commonly uses, as browsers read them (the
// names are case-sensitive: "&Eacute;" is "É", "&eacute;" is "é")
const LATIN1 = 'nbsp iexcl cent pound curren yen brvbar sect uml copy ordf laquo not shy reg macr deg plusmn sup2 sup3 acute micro para middot cedil sup1 ordm raquo frac14 frac12 frac34 iquest Agrave Aacute Acirc Atilde Auml Aring AElig Ccedil Egrave Eacute Ecirc Euml Igrave Iacute Icirc Iuml ETH Ntilde Ograve Oacute Ocirc Otilde Ouml times Oslash Ugrave Uacute Ucirc Uuml Yacute THORN szlig agrave aacute acirc atilde auml aring aelig ccedil egrave eacute ecirc euml igrave iacute icirc iuml eth ntilde ograve oacute ocirc otilde ouml divide oslash ugrave uacute ucirc uuml yacute thorn yuml'.split(' ');
const ENTITIES = new Map([
	...LATIN1.map((name, index) => [name, String.fromCodePoint(160 + index)]),
	['amp', '&'],
	['lt', '<'],
	['gt', '>'],
	['quot', '"'],
	['apos', '\''],
	['AMP', '&'],
	['LT', '<'],
	['GT', '>'],
	['QUOT', '"'],
	['COPY', '©'],
	['REG', '®'],
	['OElig', 'Œ'],
	['oelig', 'œ'],
	['Scaron', 'Š'],
	['scaron', 'š'],
	['Yuml', 'Ÿ'],
	['fnof', 'ƒ'],
	['circ', 'ˆ'],
	['tilde', '˜'],
	['ensp', ' '],
	['emsp', ' '],
	['thinsp', ' '],
	['zwnj', '‌'],
	['zwj', '‍'],
	['lrm', '‎'],
	['rlm', '‏'],
	['ndash', '–'],
	['mdash', '—'],
	['lsquo', '‘'],
	['rsquo', '’'],
	['sbquo', '‚'],
	['ldquo', '“'],
	['rdquo', '”'],
	['bdquo', '„'],
	['dagger', '†'],
	['Dagger', '‡'],
	['bull', '•'],
	['hellip', '…'],
	['permil', '‰'],
	['prime', '′'],
	['Prime', '″'],
	['lsaquo', '‹'],
	['rsaquo', '›'],
	['euro', '€'],
	['trade', '™'],
	['larr', '←'],
	['uarr', '↑'],
	['rarr', '→'],
	['darr', '↓'],
	['hearts', '♥'],
	['check', '✓'],
]);
// The names browsers also read without a ";" ("&nbsp", "&amp"), longest
// first, for reading the longest at the start of a name ("&notit" is "¬it")
const LEGACY = [...LATIN1, 'amp', 'lt', 'gt', 'quot', 'AMP', 'LT', 'GT', 'QUOT', 'COPY', 'REG'].sort((a, b) => b.length - a.length);
// Windows-1252 for the references to C1 controls, as browsers read them
// ("don&#146;t" is "don’t")
const WINDOWS_1252 = [0x20_AC, 0x81, 0x20_1A, 0x1_92, 0x20_1E, 0x20_26, 0x20_20, 0x20_21, 0x2_C6, 0x20_30, 0x1_60, 0x20_39, 0x1_52, 0x8D, 0x1_7D, 0x8F, 0x90, 0x20_18, 0x20_19, 0x20_1C, 0x20_1D, 0x20_22, 0x20_13, 0x20_14, 0x2_DC, 0x21_22, 0x1_61, 0x20_3A, 0x1_53, 0x9D, 0x1_7E, 0x1_78];
const REFERENCE = /&(?:#([xX])([\da-fA-F]+)|#(\d+)|([a-zA-Z][a-zA-Z\d]{0,31}))(;?)/g;

function fromCode(code) {
	if (code === 0 || code > 0x10_FF_FF || (code >= 0xD8_00 && code <= 0xDF_FF)) {
		return '�';
	}

	if (code >= 0x80 && code <= 0x9F) {
		return String.fromCodePoint(WINDOWS_1252[code - 0x80]);
	}

	return String.fromCodePoint(code);
}

/**
 * Text with its character references decoded, as browsers decode them: by
 * number, also without a ";", and by name (the names of Latin-1 and those
 * mail commonly uses; also without a ";" for the names browsers read so,
 * except in an attribute where a letter, digit or "=" follows, as in a link
 * "?a=1&copy=2"). An unknown name stays as it is.
 * @param {string} value
 * @param {object} [options]
 * @param {boolean} [options.attribute] - the value of an attribute
 * @returns {string}
 */
export function decodeEntities(value, {attribute = false} = {}) {
	return value.replaceAll(REFERENCE, (...found) => {
		const [match, , hex, decimal, name, semicolon, offset] = found;
		if (hex !== undefined || decimal !== undefined) {
			return fromCode(hex === undefined ? Number.parseInt(decimal, 10) : Number.parseInt(hex, 16));
		}

		if (semicolon) {
			// (a name this table does not have may still be one browsers know:
			//  left as it is)
			return ENTITIES.get(name) ?? match;
		}

		const legacy = LEGACY.find(known => name.startsWith(known));
		if (!legacy) {
			return match;
		}

		const rest = match.slice(legacy.length + 1);
		const next = rest[0] ?? value[offset + match.length] ?? '';
		if (attribute && /[\da-zA-Z=]/.test(next)) {
			return match;
		}

		return ENTITIES.get(legacy) + rest;
	});
}

// Elements whose content is not shown (raw text up to their end tag, which is
// searched for once), and those whose content is shown as raw text
const UNSHOWN = new Set(['script', 'style', 'title', 'noembed', 'noframes', 'iframe']);
const RAW_SHOWN = new Set(['textarea', 'xmp']);
const RAW_END = Object.fromEntries([...UNSHOWN, ...RAW_SHOWN].map(name => [name, linear(String.raw`<\/${caseless(name)}[\s/>]`, 'g')]));
// Elements whose tags break a word: blocks, and what takes a place of its own
// (an image, a field); the others, also unknown ones (`<o:p>`, custom
// elements), are shown in the line, so their tags join a word
// ("Free Sp<span>ins</span>" reads "Free Spins", as a browser shows it)
const BREAKS = new Set(['address', 'applet', 'area', 'article', 'aside', 'audio', 'blockquote', 'body', 'br', 'button', 'canvas', 'caption', 'center', 'col', 'colgroup', 'dd', 'details', 'dialog', 'dir', 'div', 'dl', 'dt', 'embed', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'frame', 'frameset', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html', 'iframe', 'image', 'img', 'input', 'keygen', 'legend', 'li', 'listing', 'main', 'marquee', 'math', 'menu', 'meter', 'nav', 'object', 'ol', 'optgroup', 'option', 'p', 'picture', 'plaintext', 'pre', 'progress', 'section', 'select', 'summary', 'svg', 'table', 'tbody', 'td', 'textarea', 'tfoot', 'th', 'thead', 'tr', 'ul', 'video', 'xmp']);
// Elements an end tag of another name does not close through, as browsers
// read it ("<span hidden><div>a</span>b</div>": the </span> does nothing),
// and those it closes through when they are open
const SPECIAL = new Set(['address', 'applet', 'area', 'article', 'aside', 'base', 'blockquote', 'body', 'button', 'caption', 'center', 'col', 'colgroup', 'dd', 'details', 'dir', 'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'frameset', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'html', 'iframe', 'li', 'listing', 'main', 'marquee', 'menu', 'nav', 'object', 'ol', 'p', 'plaintext', 'pre', 'section', 'select', 'summary', 'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'tr', 'ul', 'xmp']);
const FORMATTING = new Set(['a', 'b', 'big', 'code', 'em', 'font', 'i', 'nobr', 's', 'small', 'strike', 'strong', 'tt', 'u']);
// Elements that break a line (the others break a word)
const LINE = new Set(['br', 'p', 'div', 'tr', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'blockquote', 'pre']);
// Elements without content
const VOID = new Set(['area', 'base', 'basefont', 'bgsound', 'br', 'col', 'command', 'embed', 'frame', 'hr', 'image', 'img', 'input', 'keygen', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
// Elements a browser closes by itself when another starts: a paragraph at a
// block, a list item at the next, a cell at the next cell or row, and so on
// (each with the elements that end the search for it)
const CLOSES_PARAGRAPH = new Set(['address', 'article', 'aside', 'blockquote', 'center', 'dd', 'details', 'dialog', 'dir', 'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'li', 'main', 'menu', 'nav', 'ol', 'p', 'pre', 'section', 'table', 'ul', 'xmp']);
const PARAGRAPH = [new Set(['p']), new Set(['button', 'table', 'td', 'th', 'caption', 'marquee', 'object', 'applet', 'html'])];
const IMPLIED = {
	li: [new Set(['li']), new Set(['ul', 'ol', 'menu'])],
	dt: [new Set(['dt', 'dd']), new Set(['dl'])],
	dd: [new Set(['dt', 'dd']), new Set(['dl'])],
	td: [new Set(['td', 'th']), new Set(['tr', 'table'])],
	th: [new Set(['td', 'th']), new Set(['tr', 'table'])],
	tr: [new Set(['tr']), new Set(['table', 'tbody', 'thead', 'tfoot'])],
	tbody: [new Set(['tbody', 'thead', 'tfoot']), new Set(['table'])],
	thead: [new Set(['tbody', 'thead', 'tfoot']), new Set(['table'])],
	tfoot: [new Set(['tbody', 'thead', 'tfoot']), new Set(['table'])],
	option: [new Set(['option']), new Set(['select', 'datalist', 'optgroup'])],
	optgroup: [new Set(['optgroup', 'option']), new Set(['select'])],
};
// (open elements kept, and how far down a search for an implied end goes:
// bounds the work on markup that never closes what it opens)
const MAX_OPEN = 1024;
const MAX_SEARCH = 64;
const MAX_ATTRIBUTES = 64;
const MAX_STYLE = 10_000;
// (the nearest end of a comment, searched for once)
const COMMENT_END = linear('--!?>', 'g');
const WHITESPACE = new Set([' ', '\t', '\n', '\r', '\f']);

//
// The tag that starts at `start` (a "<" and a letter, or "</" and a letter):
// its end (just after its ">", or -1 when the input ends inside it), its name
// and its attributes (the first of each name), read as browsers read them: a
// quote opens a value only after "=", and a quoted value may hold ">"
//
function readTag(html, start) {
	const closing = html[start + 1] === '/';
	let i = start + (closing ? 2 : 1);
	const nameStart = i;
	while (i < html.length && !WHITESPACE.has(html[i]) && html[i] !== '/' && html[i] !== '>') {
		i++;
	}

	const name = html.slice(nameStart, Math.min(i, nameStart + 64)).toLowerCase();
	const attributes = new Map();
	// (a "/" on its own just before the ">", not one ending a value)
	let slash = false;
	while (i < html.length) {
		const char = html[i];
		if (char === '>') {
			return {
				end: i + 1, name, closing, attributes, selfClosing: slash,
			};
		}

		if (WHITESPACE.has(char) || char === '/') {
			slash = char === '/' || (slash && WHITESPACE.has(char));
			i++;
			continue;
		}

		slash = false;

		const attributeStart = i++;
		while (i < html.length && !WHITESPACE.has(html[i]) && html[i] !== '/' && html[i] !== '>' && html[i] !== '=') {
			i++;
		}

		const attribute = html.slice(attributeStart, i).toLowerCase();
		while (WHITESPACE.has(html[i])) {
			i++;
		}

		let value = '';
		if (html[i] === '=') {
			i++;
			while (WHITESPACE.has(html[i])) {
				i++;
			}

			if (html[i] === '"' || html[i] === '\'') {
				const close = html.indexOf(html[i], i + 1);
				if (close === -1) {
					break;
				}

				value = html.slice(i + 1, close);
				i = close + 1;
			} else {
				const valueStart = i;
				while (i < html.length && !WHITESPACE.has(html[i]) && html[i] !== '>') {
					i++;
				}

				value = html.slice(valueStart, i);
			}
		}

		if (!attributes.has(attribute) && attributes.size < MAX_ATTRIBUTES) {
			attributes.set(attribute, value);
		}
	}

	return {end: -1};
}

// The declarations of a style, the last of each property winning (an
// important one over one that is not), without comments
function declarations(style) {
	let css = '';
	let from = 0;
	const text = style.slice(0, MAX_STYLE);
	while (from < text.length) {
		const open = text.indexOf('/*', from);
		if (open === -1) {
			css += text.slice(from);
			break;
		}

		css += text.slice(from, open);
		const close = text.indexOf('*/', open + 2);
		if (close === -1) {
			break;
		}

		from = close + 2;
	}

	const found = new Map();
	for (const declaration of css.split(';')) {
		const colon = declaration.indexOf(':');
		if (colon === -1) {
			continue;
		}

		const property = declaration.slice(0, colon).trim().toLowerCase();
		let value = declaration.slice(colon + 1).trim().toLowerCase();
		const important = /!\s*important$/.test(value);
		if (important) {
			value = value.replace(/!\s*important$/, '').trim();
		}

		const before = found.get(property);
		if (!before || important || !before.important) {
			found.set(property, {value, important});
		}
	}

	return found;
}

// (a value longer than any real one is not read: the numbers are read by a
//  regular expression)
const MAX_VALUE = 64;
const LENGTH = /^([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?)(px|pt|pc|in|cm|mm|q|em|rem|%|ex|ch|)$/;
const UNITS = {
	px: 1, pt: 4 / 3, pc: 16, in: 96, cm: 96 / 2.54, mm: 96 / 25.4, q: 96 / 101.6, rem: 16,
};
const SIZE_KEYWORDS = {
	'xx-small': 9, 'x-small': 10, small: 13, medium: 16, large: 18, 'x-large': 24, 'xx-large': 32, 'xxx-large': 48,
};

// A length in pixels, given the font size it is relative to, or null for one
// that is not valid (a number without a unit counts as pixels, as in mail,
// which is read in quirks mode)
function pixels(value, parent) {
	const length = value.length > MAX_VALUE ? null : LENGTH.exec(value);
	if (!length) {
		return null;
	}

	const number = Number(length[1]);
	if (!Number.isFinite(number)) {
		return null;
	}

	const unit = length[2];
	if (unit === 'em') {
		return number * parent;
	}

	if (unit === '%') {
		return number * parent / 100;
	}

	if (unit === 'ex' || unit === 'ch') {
		return number * parent / 2;
	}

	return number * (UNITS[unit] ?? 1);
}

// A font size in pixels, or null for none (or one not valid)
function fontSize(value, parent) {
	if (Object.hasOwn(SIZE_KEYWORDS, value)) {
		return SIZE_KEYWORDS[value];
	}

	if (value === 'smaller') {
		return parent / 1.2;
	}

	if (value === 'larger') {
		return parent * 1.2;
	}

	const size = pixels(value, parent);
	return size === null || size < 0 ? null : size;
}

// The font size in the "font" shorthand ("bold 12px/1.4 Arial", "0/0 a")
function shorthandSize(value, parent) {
	for (const token of value.slice(0, MAX_STYLE).split(/\s+/)) {
		// (a size has a unit or is a keyword, or comes before a "/" and the
		//  line height; a number alone is a weight: "400 0px Arial")
		const [size, lineHeight] = token.split('/');
		if (lineHeight === undefined && /^[+-]?[\d.]+$/.test(size)) {
			continue;
		}

		const pixelSize = fontSize(size, parent);
		if (pixelSize !== null) {
			return pixelSize;
		}
	}

	return null;
}

// Whether a colour is transparent: "transparent", or an alpha of 0
function isTransparent(color) {
	if (color === 'transparent') {
		return true;
	}

	const hex = /^#(?:[\da-f]{3}(0)|[\da-f]{6}(00))$/.exec(color);
	if (hex) {
		return true;
	}

	const functional = /^(?:rgb|hsl)a?\((.*)\)$/.exec(color);
	if (!functional) {
		return false;
	}

	// (the alpha after a "/", or as a fourth value)
	const slash = functional[1].lastIndexOf('/');
	const parts = functional[1].split(',');
	if (slash === -1 && parts.length < 4) {
		return false;
	}

	const alpha = (slash === -1 ? parts.at(-1) : functional[1].slice(slash + 1)).trim();
	return ZERO_NUMBER.test(alpha);
}

// (a number that is zero: "0", "0.0", ".0", "0%")
const ZERO_NUMBER = /^[+-]?(?:0+(?:\.0*)?|\.0+)%?$/;

const isZero = value => {
	const size = pixels(value, 16);
	return size !== null && size <= 0;
};

//
// What an element's style does to the text it holds, given its parent's
// state: whether it hides all of it (display, opacity, a clipped box of no
// size, or text moved off the page), and the visibility, transparency and
// font size its content has (inherited: a child can set them again)
//
function styleState(style, parent) {
	const css = declarations(style);
	const value = property => css.get(property)?.value;
	const opacity = value('opacity');
	const overflow = [value('overflow'), value('overflow-x'), value('overflow-y')].some(item => item === 'hidden' || item === 'clip');
	const noHeight = (isZero(value('height') ?? '1') || isZero(value('max-height') ?? '1')) && isZero(value('min-height') ?? '0');
	const noWidth = (isZero(value('width') ?? '1') || isZero(value('max-width') ?? '1')) && isZero(value('min-width') ?? '0');
	const indent = pixels(value('text-indent') ?? '0', parent.size);
	const offPage = ['absolute', 'fixed'].includes(value('position')) && ['left', 'top'].some(side => (pixels(value(side) ?? '0', parent.size) ?? 0) <= -999);
	const hides = value('display') === 'none'
		|| (opacity !== undefined && (ZERO_NUMBER.test(opacity) || (opacity.length <= MAX_VALUE && Number.parseFloat(opacity) < 0)))
		|| (overflow && (noHeight || noWidth))
		|| (indent !== null && indent <= -999)
		|| offPage;

	const visibility = value('visibility');
	const color = value('color');
	const size = value('font-size') === undefined ? (value('font') === undefined ? null : shorthandSize(value('font'), parent.size)) : fontSize(value('font-size'), parent.size);
	return {
		hides,
		display: value('display'),
		visible: visibility === 'hidden' || visibility === 'collapse' ? false : (visibility === 'visible' ? true : parent.visible),
		transparent: color === undefined ? parent.transparent : isTransparent(color),
		size: size ?? parent.size,
	};
}

const ROOT = {
	visible: true, transparent: false, size: 16, hides: false,
};

/**
 * The text of HTML as a mail client shows it, read in linear time: without
 * tags, comments, scripts, styles and the title, with character references
 * decoded, without a break inside a word at an inline tag
 * ("Free Sp<span>ins</span>" is "Free Spins") but with one between blocks
 * ("<td>a</td><td>b</td>" is "a" and "b"), and without text that is hidden:
 * by an element that hides what it holds (display, opacity, the hidden
 * attribute, a clipped box of no size, text moved off the page), or that is
 * invisible, transparent or in a font of a pixel or less where it is (which
 * an element inside can set again). Not colours on a background, or classes
 * of a style sheet: text hidden so is read as shown.
 * @param {string} html
 * @returns {{text: string, hidden: number}} the text, and how many
 * characters of text were hidden
 */
export function visibleText(html) {
	if (typeof html !== 'string' || html === '') {
		return {text: '', hidden: 0};
	}

	const parts = [];
	let hidden = 0;
	// (the open elements with their state, how many of each name are open,
	//  and how many of them hide all they hold)
	const stack = [];
	const open = new Map();
	let hiding = 0;
	// (and how many closed <details> are open, less the summaries in them)
	let collapsed = 0;
	const state = () => stack.at(-1) ?? ROOT;
	const shown = () => hiding === 0 && collapsed === 0 && state().visible && !state().transparent && state().size > 1;
	const write = text => {
		if (text === '') {
			return;
		}

		if (shown()) {
			parts.push(text);
		} else {
			hidden += text.replaceAll(/\s+/g, '').length;
		}
	};

	const popTo = index => {
		while (stack.length > index) {
			const element = stack.pop();
			open.set(element.name, open.get(element.name) - 1);
			if (element.hides) {
				hiding--;
			}

			collapsed -= (element.collapses ? 1 : 0) - (element.reveals ? 1 : 0);
		}
	};

	// (an implied end: the nearest of `names`, not past one of `limits`)
	const closeImplied = ([names, limits]) => {
		for (let i = stack.length - 1; i >= Math.max(0, stack.length - MAX_SEARCH); i--) {
			if (names.has(stack[i].name)) {
				popTo(i);
				return;
			}

			if (limits.has(stack[i].name)) {
				return;
			}
		}
	};

	let from = 0;
	while (from < html.length) {
		const lt = html.indexOf('<', from);
		if (lt === -1) {
			write(decodeEntities(html.slice(from)));
			break;
		}

		write(decodeEntities(html.slice(from, lt)));
		from = lt + 1;
		const next = html[lt + 1] ?? '';

		// Comments, as browsers end them ("<!-->" and "--!>" too); other
		// markup declarations and processing instructions end at a ">"
		if (html.startsWith('<!--', lt)) {
			if (html.startsWith('>', lt + 4) || html.startsWith('->', lt + 4)) {
				from = html.indexOf('>', lt + 4) + 1;
				continue;
			}

			COMMENT_END.lastIndex = lt + 4;
			const end = COMMENT_END.exec(html);
			from = end === null ? html.length : end.index + end[0].length;
			continue;
		}

		const closingTag = next === '/';
		const letter = /[a-zA-Z]/.test(closingTag ? (html[lt + 2] ?? '') : next);
		if (!letter) {
			if (closingTag && lt + 2 >= html.length) {
				// (a "</" the input ends with is text)
				write('</');
				break;
			}

			if (next === '!' || next === '?' || (closingTag && html[lt + 2] !== '>')) {
				const end = html.indexOf('>', lt + 2);
				from = end === -1 ? html.length : end + 1;
			} else if (closingTag) {
				// ("</>" is nothing)
				from = lt + 3;
			} else {
				// (a "<" before anything else is text)
				write('<');
			}

			continue;
		}

		const tag = readTag(html, lt);
		if (tag.end === -1) {
			break;
		}

		from = tag.end;
		const {name} = tag;
		if (tag.closing) {
			// (closing what it closes, as browsers do: an end tag of a block
			//  or a formatting element closes it with all inside it; another
			//  one only when no block is open inside it)
			const through = SPECIAL.has(name) || FORMATTING.has(name);
			const limit = through ? 0 : Math.max(0, stack.length - MAX_SEARCH);
			for (let i = stack.length - 1; open.get(name) > 0 && i >= limit; i--) {
				if (stack[i].name === name) {
					popTo(i);
					break;
				}

				if (!through && SPECIAL.has(stack[i].name)) {
					break;
				}
			}
		} else {
			if (CLOSES_PARAGRAPH.has(name)) {
				closeImplied(PARAGRAPH);
			}

			if (IMPLIED[name]) {
				closeImplied(IMPLIED[name]);
			}

			// (an element is opened unless it has no content, or closes
			//  itself in an <svg> or <math>)
			const foreign = (open.get('svg') ?? 0) + (open.get('math') ?? 0) > 0;
			if (!VOID.has(name) && !(foreign && tag.selfClosing)) {
				// (past the most kept, the innermost is closed: the element goes
				//  in beside it, as deep elements do in browsers)
				if (stack.length >= MAX_OPEN) {
					popTo(stack.length - 1);
				}

				const style = tag.attributes.get('style');
				const parent = state();
				const element = {
					...(style === undefined
						? {
							visible: parent.visible, transparent: parent.transparent, size: parent.size, hides: false,
						}
						: styleState(decodeEntities(style, {attribute: true}), parent)),
					name,
				};
				// (the hidden attribute, unless a style shows the element; a
				//  template's content, which is not shown; a closed <details>,
				//  but for its summary)
				if ((tag.attributes.has('hidden') && (element.display === undefined || element.display === 'none')) || name === 'template') {
					element.hides = true;
				}

				element.collapses = name === 'details' && !tag.attributes.has('open');
				element.reveals = name === 'summary' && parent.collapses === true;
				stack.push(element);
				open.set(name, (open.get(name) ?? 0) + 1);
				if (element.hides) {
					hiding++;
				}

				collapsed += (element.collapses ? 1 : 0) - (element.reveals ? 1 : 0);
			}

			if (name === 'plaintext') {
				// (all after it is shown as it is)
				parts.push('\n');
				write(html.slice(tag.end));
				break;
			}

			if ((UNSHOWN.has(name) || RAW_SHOWN.has(name)) && !(foreign && tag.selfClosing)) {
				const closer = RAW_END[name];
				closer.lastIndex = tag.end;
				const close = closer.exec(html);
				const end = close === null ? html.length : close.index;
				if (RAW_SHOWN.has(name)) {
					const raw = html.slice(tag.end, end);
					write(name === 'textarea' ? decodeEntities(raw) : raw);
				}

				from = end;
			}
		}

		if (BREAKS.has(name)) {
			parts.push(LINE.has(name) ? '\n' : ' ');
		}
	}

	return {text: parts.join(''), hidden};
}
