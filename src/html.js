import {NAMED_REFERENCES} from './entities.js';
import {caseless, linear} from './linear.js';

// The names of the characters of Latin-1 (160 to 255, in order), which
// browsers also read without a ";" (names are case-sensitive: "&Eacute;" is
// "É", "&eacute;" is "é")
const LATIN1 = 'nbsp iexcl cent pound curren yen brvbar sect uml copy ordf laquo not shy reg macr deg plusmn sup2 sup3 acute micro para middot cedil sup1 ordm raquo frac14 frac12 frac34 iquest Agrave Aacute Acirc Atilde Auml Aring AElig Ccedil Egrave Eacute Ecirc Euml Igrave Iacute Icirc Iuml ETH Ntilde Ograve Oacute Ocirc Otilde Ouml times Oslash Ugrave Uacute Ucirc Uuml Yacute THORN szlig agrave aacute acirc atilde auml aring aelig ccedil egrave eacute ecirc euml igrave iacute icirc iuml eth ntilde ograve oacute ocirc otilde ouml divide oslash ugrave uacute ucirc uuml yacute thorn yuml'.split(' ');
// The names browsers also read without a ";" ("&nbsp", "&amp"), the longest
// at the start of a name ("&notit" is "¬it", "Vi&shyagra;" is "Vi­agra" in
// text); a name with a ";" is read whole by every name browsers know
// ("&notin;" is "∉", "&iopf;" is "𝕚"), see NAMED_REFERENCES
const LEGACY = new Set([...LATIN1, 'amp', 'lt', 'gt', 'quot', 'AMP', 'LT', 'GT', 'QUOT', 'COPY', 'REG']);
const LEGACY_LONGEST = Math.max(...[...LEGACY].map(name => name.length));
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
 * number, also without a ";", and by name (every name browsers know; also
 * without a ";" for the names browsers read so,
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

		if (semicolon && NAMED_REFERENCES.has(name)) {
			return NAMED_REFERENCES.get(name);
		}

		// (the longest name read without a ";" that the name starts with; an
		//  unknown name stays as it is)
		let legacy;
		for (let length = Math.min(name.length, LEGACY_LONGEST); length >= 2 && legacy === undefined; length--) {
			legacy = LEGACY.has(name.slice(0, length)) ? name.slice(0, length) : undefined;
		}

		if (legacy === undefined) {
			return match;
		}

		const rest = match.slice(legacy.length + 1);
		const next = rest[0] ?? value[offset + match.length] ?? '';
		if (attribute && /[\da-zA-Z=]/.test(next)) {
			return match;
		}

		return NAMED_REFERENCES.get(legacy) + rest;
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
const BREAKS = new Set(['address', 'applet', 'area', 'article', 'aside', 'audio', 'blockquote', 'body', 'br', 'button', 'canvas', 'caption', 'center', 'col', 'colgroup', 'dd', 'details', 'dialog', 'dir', 'div', 'dl', 'dt', 'embed', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'frame', 'frameset', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html', 'iframe', 'image', 'img', 'input', 'keygen', 'legend', 'li', 'listing', 'main', 'marquee', 'math', 'menu', 'meter', 'nav', 'object', 'ol', 'optgroup', 'option', 'p', 'picture', 'plaintext', 'pre', 'progress', 'search', 'section', 'select', 'summary', 'svg', 'table', 'tbody', 'td', 'textarea', 'tfoot', 'th', 'thead', 'tr', 'ul', 'video', 'xmp']);
// Elements an end tag of another name does not close through, as browsers
// read it ("<span hidden><div>a</span>b</div>": the </span> does nothing),
// and those it closes through when they are open
const SPECIAL = new Set(['address', 'applet', 'area', 'article', 'aside', 'base', 'blockquote', 'body', 'button', 'caption', 'center', 'col', 'colgroup', 'dd', 'details', 'dir', 'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'frameset', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'html', 'iframe', 'li', 'listing', 'main', 'marquee', 'menu', 'nav', 'object', 'ol', 'p', 'plaintext', 'pre', 'search', 'section', 'select', 'summary', 'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'tr', 'ul', 'xmp']);
// (and the elements an end tag of a block or a formatting element does not
// close through: "<div hidden><table><tr><td></div>x": "x" is in the cell)
const SCOPE = new Set(['applet', 'caption', 'html', 'marquee', 'object', 'table', 'td', 'template', 'th']);
const FORMATTING = new Set(['a', 'b', 'big', 'code', 'em', 'font', 'i', 'nobr', 's', 'small', 'strike', 'strong', 'tt', 'u']);
// Elements that break a line (the others break a word)
const LINE = new Set(['br', 'p', 'div', 'tr', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'blockquote', 'pre']);
// (of those, the ones that take a place of their own however a style shows
//  them; the others break only shown as blocks, see displayKind)
const OWN_PLACE = new Set(['applet', 'area', 'audio', 'br', 'button', 'canvas', 'embed', 'frame', 'iframe', 'image', 'img', 'input', 'keygen', 'marquee', 'math', 'meter', 'object', 'picture', 'progress', 'select', 'svg', 'textarea', 'video']);
// Elements without content
const VOID = new Set(['area', 'base', 'basefont', 'bgsound', 'br', 'col', 'command', 'embed', 'frame', 'hr', 'image', 'img', 'input', 'keygen', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
// Elements a browser closes by itself when another starts: a paragraph at a
// block, a list item at the next, a cell at the next cell or row, and so on
// (each with the elements that end the search for it)
const CLOSES_PARAGRAPH = new Set(['address', 'article', 'aside', 'blockquote', 'center', 'dd', 'details', 'dialog', 'dir', 'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'li', 'listing', 'main', 'menu', 'nav', 'ol', 'p', 'plaintext', 'pre', 'search', 'section', 'summary', 'table', 'ul', 'xmp']);
const PARAGRAPH = [['p'], ['button', 'table', 'td', 'th', 'caption', 'marquee', 'object', 'applet', 'html']];
// (a list item at the next one not past a block other than an address, a
//  <div> or a <p>)
// (without a prototype: tag names such as "constructor" are looked up in it)
const IMPLIED = {
	__proto__: null,
	li: [['li']],
	dt: [['dt', 'dd']],
	dd: [['dt', 'dd']],
	td: [['td', 'th'], ['tr', 'table']],
	th: [['td', 'th'], ['tr', 'table']],
	tr: [['tr'], ['table', 'tbody', 'thead', 'tfoot']],
	tbody: [['tbody', 'thead', 'tfoot'], ['table']],
	thead: [['tbody', 'thead', 'tfoot'], ['table']],
	tfoot: [['tbody', 'thead', 'tfoot'], ['table']],
	option: [['option'], ['select', 'datalist', 'optgroup']],
	optgroup: [['optgroup', 'option'], ['select']],
};
// Elements whose text and other content a browser puts in front of the table
// they are written in, in the table's parent ("foster parenting"), and those
// it keeps in the table
// (and the parts of a table, nothing outside one)
const TABLE_PARTS = new Set(['table', 'tbody', 'thead', 'tfoot', 'tr']);
// (the parts of a table that grow to their content in a table laid out
//  automatically, whatever their width, height and overflow)
const TABLE_BOXES = new Set(['table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr']);
const HEADINGS = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
// (elements whose end a browser implies before an end tag such as </form>)
const IMPLIED_END = new Set(['dd', 'dt', 'li', 'optgroup', 'option', 'p', 'rb', 'rp', 'rt', 'rtc']);
const PARTS_OF_TABLE = new Set(['caption', 'col', 'colgroup', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr']);
const TABLE_STRUCTURE = [...PARTS_OF_TABLE, 'table', 'template'];
const IN_TABLE = new Set(['caption', 'col', 'colgroup', 'form', 'input', 'script', 'style', 'table', 'tbody', 'td', 'template', 'tfoot', 'th', 'thead', 'tr']);
// Elements a browser opens again in the next text when something else closed
// them ("<p><b>a</p>b": "b" is bold too), and those that begin a new list of
// them; the elements before which it does not do so. (Browsers keep at most
// three alike after the last marker, and no bound in all; at most this many
// are kept here, so that opening them again takes a bounded time.)
const MAX_FORMATTING = 12;
const MARKERS = new Set(['applet', 'caption', 'marquee', 'object', 'td', 'template', 'th']);
const FOSTERED_MARKERS = new Set(['applet', 'marquee', 'object']);
const NOT_REOPENING = new Set([...CLOSES_PARAGRAPH, 'base', 'basefont', 'bgsound', 'body', 'caption', 'col', 'colgroup', 'frame', 'frameset', 'head', 'html', 'iframe', 'link', 'meta', 'noembed', 'noframes', 'script', 'style', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'title', 'tr']);
// Elements that end an <svg> or <math> they are written in, in a browser, and
// the elements of these that hold HTML; and those of an <svg> not shown
const LEAVES_FOREIGN = new Set(['b', 'big', 'blockquote', 'body', 'br', 'center', 'code', 'dd', 'div', 'dl', 'dt', 'em', 'embed', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'hr', 'i', 'img', 'li', 'listing', 'menu', 'meta', 'nobr', 'ol', 'p', 'pre', 'ruby', 's', 'small', 'span', 'strike', 'strong', 'sub', 'sup', 'table', 'tt', 'u', 'ul', 'var']);
const HOLDS_HTML = {svg: new Set(['foreignobject', 'desc', 'title']), math: new Set(['mi', 'mo', 'mn', 'ms', 'mtext'])};
const SVG_UNSHOWN = new Set(['desc', 'metadata', 'script', 'style', 'title']);
// (open elements kept)
const MAX_OPEN = 1024;
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
	const spans = new Map();
	// (a "/" on its own just before the ">", not one ending a value)
	let slash = false;
	while (i < html.length) {
		const char = html[i];
		if (char === '>') {
			return {
				end: i + 1, name, closing, attributes, spans, selfClosing: slash,
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
		let valueStart = i;
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

				valueStart = i + 1;
				value = html.slice(valueStart, close);
				i = close + 1;
			} else {
				valueStart = i;
				while (i < html.length && !WHITESPACE.has(html[i]) && html[i] !== '>') {
					i++;
				}

				value = html.slice(valueStart, i);
			}
		}

		if (!attributes.has(attribute) && attributes.size < MAX_ATTRIBUTES) {
			attributes.set(attribute, value);
			spans.set(attribute, [valueStart, valueStart + value.length]);
		}
	}

	return {end: -1};
}

// Attributes whose values hold no words a reader or a program is given, but
// an address or a style: every other attribute may (the text of an image, a
// tooltip, a field's value, name or hint, a meta tag's content, a class, an
// id, data of any name, and attributes of no known name)
const NO_WORD_ATTRIBUTES = new Set(['href', 'src', 'srcset', 'style', 'action', 'formaction', 'background', 'poster', 'cite', 'codebase', 'longdesc', 'usemap', 'xmlns']);

// The tags of an HTML document in order, each with where it starts: not
// those in comments or in the raw text of scripts and styles, and none after
// a tag the input ends inside, as browsers read them
function eachTag(html, visit) {
	let from = 0;
	while (from < html.length) {
		const lt = html.indexOf('<', from);
		if (lt === -1) {
			break;
		}

		from = lt + 1;
		// (comments as browsers end them, "<!-->" and "<!--->" at once)
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

		if (!/[a-zA-Z]/.test(html[lt + 1] ?? '')) {
			continue;
		}

		const tag = readTag(html, lt);
		if (tag.end === -1) {
			break;
		}

		from = tag.end;
		visit(tag, lt);
		// (the raw text of a script, a style, a title or a text area)
		const closer = Object.hasOwn(RAW_END, tag.name) ? RAW_END[tag.name] : null;
		if (closer) {
			closer.lastIndex = tag.end;
			const close = closer.exec(html);
			from = close === null ? html.length : close.index;
		}
	}
}

// What a form shows to help fill it in, a few words and no more: a field's
// hint, its label for a screen reader, its tooltip and the value it shows
// (not that of a hidden field, which no one is shown), a hint on any element,
// and the text of a <label>
const FIELDS = new Set(['input', 'textarea', 'select', 'option', 'button']);
const FIELD_HELP = new Set(['placeholder', 'aria-placeholder', 'aria-label', 'aria-description', 'title', 'value']);
const HINTS = new Set(['placeholder', 'aria-placeholder']);
const MAX_HELP = 300;
const LABEL_END = linear(String.raw`<\/${caseless('label')}[\s/>]`);
const isHelp = (tag, name, value) => value.length <= MAX_HELP
	&& (HINTS.has(name) || (FIELDS.has(tag.name) && FIELD_HELP.has(name) && !(tag.name === 'input' && tag.attributes.get('type')?.trim().toLowerCase() === 'hidden')));

/**
 * The values of the attributes of an HTML document that may hold words (see
 * NO_WORD_ATTRIBUTES), with their character references decoded, where the
 * tag that holds each starts and ends, and whether it is a form's help text
 * (see FIELD_HELP), in order: not
 * those in comments or in the raw text of scripts and styles, and none after
 * a tag the input ends inside, as browsers read them. In time linear in the
 * input.
 * @param {string} html
 * @returns {Array<{text: string, start: number, end: number, help: boolean}>}
 */
export function attributeText(html) {
	const values = [];
	eachTag(html, (tag, lt) => {
		for (const [name, value] of tag.attributes) {
			if (value && !NO_WORD_ATTRIBUTES.has(name)) {
				values.push({
					text: decodeEntities(value, {attribute: true}), start: lt, end: tag.end, help: isHelp(tag, name, value),
				});
			}
		}
	});

	return values;
}

/**
 * Where a form's help text is in an HTML document (see FIELD_HELP): the
 * values of those attributes and the text of each <label> of at most
 * MAX_HELP characters, as places in the input, in order of where they start
 * (a label's text may hold another's). In time linear in the input.
 * @param {string} html
 * @returns {Array<{from: number, to: number}>}
 */
export function formHelp(html) {
	const places = [];
	eachTag(html, tag => {
		if (tag.name === 'label' && !tag.closing) {
			const close = LABEL_END.exec(html.slice(tag.end, tag.end + MAX_HELP + 8));
			if (close !== null && close.index <= MAX_HELP) {
				places.push({from: tag.end, to: tag.end + close.index});
			}
		}

		for (const [name, value] of tag.attributes) {
			if (value && isHelp(tag, name, value)) {
				const [from, to] = tag.spans.get(name);
				places.push({from, to});
			}
		}
	});

	return places;
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

// Whether a display shows an element as a block, which breaks the line
// ("block", "flex", "table-cell", "list-item"), or in the line ("inline",
// "inline-block", "contents"); undefined for a value browsers do not know,
// which leaves the element as it is. (Read in one or two keywords.)
const DISPLAY_INLINE = /^(?:inline(?:-[a-z]+)?|contents|ruby(?:-[a-z]+)?)$/;
const DISPLAY_BLOCK = /^(?:block|flex|grid|flow|flow-root|list-item|run-in|table(?:-[a-z]+)?)$/;
function displayKind(display) {
	const keywords = display.length <= MAX_VALUE ? display.split(/\s+/) : ['?'];
	if (!keywords.every(keyword => DISPLAY_INLINE.test(keyword) || DISPLAY_BLOCK.test(keyword))) {
		return undefined;
	}

	return keywords.some(keyword => DISPLAY_INLINE.test(keyword)) ? 'inline' : 'block';
}

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
// (the declarations of the styles one document repeats, read once: opening
// formatting elements again reads theirs before every text)
let declarationCache = new Map();
function styleState(style, parent, name) {
	let css = declarationCache.get(style);
	if (css === undefined) {
		css = declarations(style);
		declarationCache.set(style, css);
	}

	const value = property => css.get(property)?.value;
	// (a size, overflow and indent apply to a box, not to text in the line:
	//  to a block, or an element shown as one, or taken out of the line)
	const display = value('display');
	const position = value('position');
	const boxed = display === undefined ? BREAKS.has(name) : !['inline', 'contents'].includes(display);
	const box = boxed || ['absolute', 'fixed'].includes(position) || ['left', 'right'].includes(value('float'));
	// (a part of a table shown as one, and not taken out of it, is no box
	//  that clips: it grows to what it holds)
	const tablePart = (display === undefined ? TABLE_BOXES.has(name) : /^(?:inline-)?table(?!-caption)/.test(display)) && !['absolute', 'fixed'].includes(position) && value('float') === undefined;
	const opacity = value('opacity');
	const overflow = [value('overflow'), value('overflow-x'), value('overflow-y')].some(item => item === 'hidden' || item === 'clip');
	const noHeight = (isZero(value('height') ?? '1') || isZero(value('max-height') ?? '1')) && isZero(value('min-height') ?? '0');
	const noWidth = (isZero(value('width') ?? '1') || isZero(value('max-width') ?? '1')) && isZero(value('min-width') ?? '0');
	const indent = pixels(value('text-indent') ?? '0', parent.size);
	const offPage = ['absolute', 'fixed'].includes(position) && ['left', 'top'].some(side => (pixels(value(side) ?? '0', parent.size) ?? 0) <= -999);
	const hides = display === 'none'
		|| (opacity !== undefined && (ZERO_NUMBER.test(opacity) || (opacity.length <= MAX_VALUE && Number.parseFloat(opacity) < 0)))
		|| (box && !tablePart && overflow && (noHeight || noWidth))
		|| (box && indent !== null && indent <= -999)
		|| offPage;

	const visibility = value('visibility');
	const color = value('color');
	const size = value('font-size') === undefined ? (value('font') === undefined ? null : shorthandSize(value('font'), parent.size)) : fontSize(value('font-size'), parent.size);
	return {
		hides,
		display,
		kind: display === undefined ? undefined : displayKind(display),
		// (an element taken out of the line, where it takes no place)
		outOfFlow: ['absolute', 'fixed'].includes(position) || ['left', 'right'].includes(value('float')),
		visible: visibility === 'hidden' || visibility === 'collapse' ? false : (visibility === 'visible' ? true : parent.visible),
		transparent: color === undefined ? parent.transparent : isTransparent(color),
		size: size ?? parent.size,
	};
}

const ROOT = {
	name: '', namespace: 'html', visible: true, transparent: false, size: 16, hides: false, hiding: 0, gone: 0, collapsed: 0,
};

// Whether a document is read in quirks mode, where a paragraph holds a table
// rather than ending at it: without a doctype, or with one of the old ones
// mail is written with ("-//W3C//DTD HTML 4.01 Transitional//EN", without
// its address); with "<!doctype html>", an XHTML one or another, not
const DOCTYPE = /^\s*<!doctype\s+([^\s>]+)(?:\s+public\s*(?:"([^"]*)"|'([^']*)')\s*(?:"[^"]*"|'[^']*')?)?/i;
const QUIRKS_PUBLIC = /^-\/\/(?:w3c\/\/dtd html (?:[23]|4\.0 (?:transitional|frameset)|3\.2)|ietf\/\/|netscape|microsoft|sq|o'reilly|webtechs|spyglass|softquad|sun microsystems|metrius|advasoft|as\/\/|w30)/i;
const QUIRKS_IF_NO_SYSTEM = /^-\/\/w3c\/\/dtd html 4\.01 (?:transitional|frameset)\/\//i;

function isQuirks(html) {
	const doctype = DOCTYPE.exec(html.slice(0, 1000));
	if (!doctype) {
		return true;
	}

	const publicId = doctype[2] ?? doctype[3];
	const system = /["'][^"']*["']\s*["']/.test(doctype[0]);
	return doctype[1].toLowerCase() !== 'html' || (publicId !== undefined && (QUIRKS_PUBLIC.test(publicId) || (QUIRKS_IF_NO_SYSTEM.test(publicId) && !system)));
}

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

	const quirks = isQuirks(html);
	declarationCache = new Map();
	const decodedStyles = new Map();
	const parts = [];
	let hidden = 0;
	// (the open elements, each with its state: whether it and those around
	//  it hide what they hold, counted, and how many closed <details> it is
	//  in, less the summaries; for each name the places of those open, and
	//  the places of the elements an end tag of another name stops at)
	const stack = [];
	const places = new Map();
	const specials = [];
	const blocks = [];
	const scopes = [];
	// (the formatting elements a browser opens again, and markers)
	const formatting = [];
	// (the form a browser has open, outside a template: no other starts in
	//  it, and its end tag ends it wherever it is)
	let form = null;
	const state = () => stack.at(-1) ?? ROOT;
	const latest = name => places.get(name)?.at(-1) ?? -1;
	const nearest = names => {
		let index = -1;
		for (const name of names) {
			index = Math.max(index, latest(name));
		}

		return index;
	};

	// (the break an element's tag makes in the text, if any: of an element
	//  that takes a place on the page, a block, as its name or a style shows
	//  it, or what takes a place of its own, as an image)
	const breakOf = at => {
		if (at.gone > 0 || at.box > 0) {
			return '';
		}

		const kind = OWN_PLACE.has(at.name) || at.namespace !== 'html' ? undefined : at.kind;
		if (kind === undefined) {
			return BREAKS.has(at.name) ? (LINE.has(at.name) ? '\n' : ' ') : '';
		}

		return kind === 'block' ? (LINE.has(at.name) || !BREAKS.has(at.name) ? '\n' : ' ') : '';
	};

	const shown = at => at.hiding === 0 && at.collapsed === 0 && at.visible && !at.transparent && at.size > 1;
	// (where a browser puts text and elements: in front of a table they are
	//  written in, in the table's parent; but in a template inside the table,
	//  or with no table, in the template's content, which is not shown)
	const fostering = () => state().namespace === 'html' && TABLE_PARTS.has(state().name) && latest('table') > latest('template');
	const parentOf = () => (fostering() ? stack[latest('table') - 1] ?? ROOT : state());
	const write = (text, at = state()) => {
		if (shown(at)) {
			parts.push(text);
		} else {
			hidden += text.replaceAll(/\s+/g, '').length;
		}
	};

	// (and the elements a browser took out of the middle of the open ones,
	//  as a </form> does, once those after them are closed; when closing
	//  back to a table, the markers of what was put in front of it are kept,
	//  as browsers keep them; and with `breaks`, a break where each block
	//  ends, which an end tag of a formatting element does not make: a
	//  browser moves the block out of it, and keeps it open)
	const popTo = (index, toTable = false, breaks = true) => {
		while (stack.length > index || stack.at(-1)?.removed) {
			const element = stack.pop();
			element.open = false;
			places.get(element.name).pop();
			// (a block ends here, also where a browser ends it by itself: "<p>a<div
			//  hidden></div>b" shows "a" and "b" on lines of their own)
			if (breaks) {
				parts.push(breakOf(element));
			}

			if (specials.at(-1) === stack.length) {
				specials.pop();
			}

			if (blocks.at(-1) === stack.length) {
				blocks.pop();
			}

			if (scopes.at(-1) === stack.length) {
				scopes.pop();
			}

			if (MARKERS.has(element.name) && !(toTable && FOSTERED_MARKERS.has(element.name))) {
				formatting.length = Math.max(0, formatting.findLastIndex(entry => entry.marker === element));
			}
		}
	};

	// (an implied end: the nearest of `names`, not past one of `limits`,
	//  or for a list item a block)
	const closeImplied = ([names, limits]) => {
		const index = nearest(names);
		if (index !== -1 && index >= (limits ? nearest(limits) + 1 : blocks.at(-1))) {
			popTo(index);
		}
	};

	// The state of an element opened in `parent`
	const elementOf = (name, attributes, parent, namespace) => {
		const style = attributes.get('style');
		const element = style === undefined
			? {
				visible: parent.visible, transparent: parent.transparent, size: parent.size, hides: false,
			}
			: styleState(decodedStyles.get(style) ?? decodedStyles.set(style, decodeEntities(style, {attribute: true})).get(style), parent, name);
		element.name = name;
		element.namespace = namespace;
		element.attributes = attributes;
		element.open = true;
		// (the hidden attribute, unless a style shows the element; a
		//  template's content, which is not shown; what an <svg> does not
		//  show; a closed <details>, but for its summary)
		const unshown = (attributes.has('hidden') && (element.display === undefined || element.display === 'none')) || (name === 'template' && namespace === 'html') || (namespace === 'svg' && SVG_UNSHOWN.has(name));
		if (unshown) {
			element.hides = true;
		}

		element.hiding = parent.hiding + (element.hides ? 1 : 0);
		// (and whether it or one around it takes no place on the page, so
		//  breaks nothing: not shown at all, or hidden out of the line; an
		//  element hidden in its place, as by its opacity, still breaks the
		//  line where it is a block)
		element.gone = parent.gone + (unshown || (element.hides && (element.display === 'none' || element.outOfFlow)) ? 1 : 0);
		const collapses = namespace === 'html' && name === 'details' && !attributes.has('open');
		const reveals = namespace === 'html' && name === 'summary' && parent.collapses === true;
		element.collapses = collapses;
		// (whether the element itself is shown, and what it holds)
		element.box = parent.collapsed - (reveals ? 1 : 0);
		element.collapsed = element.box + (collapses ? 1 : 0);
		return element;
	};

	const push = element => {
		// (past the most kept, the innermost is closed: the element goes in
		//  beside it, as deep elements do in browsers)
		if (stack.length >= MAX_OPEN) {
			popTo(stack.length - 1);
		}

		if (!places.has(element.name)) {
			places.set(element.name, []);
		}

		places.get(element.name).push(stack.length);
		// (where the <svg> or <math> an element is in starts)
		element.run = element.namespace === 'html' ? -1 : (state().namespace === 'html' ? stack.length : state().run);
		if (element.namespace === 'html' ? SPECIAL.has(element.name) : HOLDS_HTML[element.namespace]?.has(element.name)) {
			specials.push(stack.length);
			if (!['address', 'div', 'p'].includes(element.name)) {
				blocks.push(stack.length);
			}

			if (element.namespace !== 'html' || SCOPE.has(element.name)) {
				scopes.push(stack.length);
			}
		}

		stack.push(element);
	};

	// (the formatting elements closed by something else, opened again with
	//  their attributes, as browsers do before text and most elements)
	const reopen = () => {
		let first = formatting.length;
		while (first > 0 && !formatting[first - 1].marker && !formatting[first - 1].element.open) {
			first--;
		}

		if (first === formatting.length) {
			return;
		}

		for (const entry of formatting.slice(first)) {
			entry.element = elementOf(entry.element.name, entry.element.attributes, parentOf(), 'html');
			push(entry.element);
		}
	};

	// (closing what an end tag closes, as browsers do: an end tag of a block
	//  or a formatting element closes it with all inside it; another one
	//  only when no block is open inside it; in an <svg> or <math>, the
	//  element of the name in it. A formatting element something else
	//  closed is no longer opened again. The element closed, or the state
	//  where nothing is.)
	const close = name => {
		// (a </p> or </br> ends an <svg> or <math>, as a start tag that
		//  leaves it does)
		if ((name === 'p' || name === 'br') && inForeign()) {
			leaveForeign();
		}

		// (an end tag of a heading ends any heading)
		const index = HEADINGS.includes(name) ? nearest(HEADINGS) : latest(name);
		if (name === 'form' && latest('template') === -1 && !(state().namespace !== 'html' && index >= state().run)) {
			return closeForm();
		}

		const entry = FORMATTING.has(name) ? formatting.findLast(item => item.element?.name === name) : undefined;
		if (entry) {
			formatting.splice(formatting.indexOf(entry), 1);
		}

		// (a block or formatting element in scope: not past a table, a cell
		//  and the like, also a <button> for a paragraph and a list for a
		//  list item; a part of a table not past a table)
		const scope = TABLE_STRUCTURE.includes(name) ? nearest(['table', 'template']) : Math.max(scopes.at(-1) ?? -1, name === 'p' ? latest('button') : -1, name === 'li' ? nearest(['ol', 'ul']) : -1);
		if (index !== -1 && ((state().namespace !== 'html' && index >= state().run) || ((SPECIAL.has(name) || FORMATTING.has(name)) && index >= scope) || index >= (specials.at(-1) ?? -1))) {
			const element = stack[index];
			popTo(index, false, !FORMATTING.has(name));
			return element;
		}

		return state();
	};

	// (a </form> ends the form open, also when other elements are open in it:
	//  they stay open, and the form is taken out from under them; or does
	//  nothing when it is not open, or not in scope)
	const closeForm = () => {
		const element = form;
		form = null;
		const place = element?.open ? places.get('form').findLast(at => stack[at] === element) : -1;
		if (place === -1 || place < (scopes.at(-1) ?? -1)) {
			return state();
		}

		// (the elements whose end a browser implies, closed first)
		while (stack.length - 1 > place && IMPLIED_END.has(state().name) && state().namespace === 'html') {
			popTo(stack.length - 1);
		}

		if (place === stack.length - 1) {
			popTo(place);
		} else {
			// (no longer an element the others stop at: a <li> after it
			//  closes the <li> it is in, as in a browser)
			element.removed = true;
			for (const list of [specials, blocks, scopes]) {
				const at = list.indexOf(place);
				if (at !== -1) {
					list.splice(at, 1);
				}
			}
		}

		return element;
	};

	// What a browser closes and opens again before an HTML element starts,
	// or false for one it leaves out: a part of a table outside one; in one,
	// it closes what was put in front of the table. A link ends the link
	// open, and a table in a table that table.
	const prepare = name => {
		if (PARTS_OF_TABLE.has(name)) {
			if (latest('table') === -1 && latest('template') === -1) {
				return false;
			}

			// (a caption ends at any part of a table, and a cell, with its
			//  row, at a caption or a column)
			const structure = nearest(TABLE_STRUCTURE);
			const ends = stack[structure].name === 'caption' || (['caption', 'col', 'colgroup'].includes(name) && ['td', 'th'].includes(stack[structure].name));
			popTo((ends ? nearest(['table', 'template']) : structure) + 1, true);
		}

		if (name === 'a' && formatting.slice(formatting.findLastIndex(item => item.marker) + 1).some(item => item.element.name === 'a')) {
			close('a');
		}

		if (name === 'table' && latest('table') !== -1 && TABLE_PARTS.has(stack[nearest(TABLE_STRUCTURE)].name)) {
			popTo(latest('table'));
		}

		if (CLOSES_PARAGRAPH.has(name) && !(name === 'table' && quirks)) {
			closeImplied(PARAGRAPH);
		}

		// (a heading ends a heading it starts in, and a button a button open)
		if (HEADINGS.includes(name) && state().namespace === 'html' && HEADINGS.includes(state().name)) {
			popTo(stack.length - 1);
		}

		if (name === 'button' && latest('button') !== -1 && latest('button') > (scopes.at(-1) ?? -1)) {
			popTo(latest('button'));
		}

		if (IMPLIED[name]) {
			closeImplied(IMPLIED[name]);
		}

		if (!NOT_REOPENING.has(name)) {
			reopen();
			// (a <nobr> ends the one open, when no block is open in it, and
			//  the others are opened again)
			if (name === 'nobr' && latest('nobr') > (specials.at(-1) ?? -1)) {
				close('nobr');
				reopen();
			}
		}

		return true;
	};

	// (whether elements opened now are in an <svg> or <math>, and whether in
	//  a column group)
	const inForeign = () => state().namespace !== 'html' && !HOLDS_HTML[state().namespace].has(state().name);
	const inColumnGroup = () => state().namespace === 'html' && state().name === 'colgroup';
	// (ending an <svg> or <math> and what it holds)
	const leaveForeign = () => {
		while (inForeign()) {
			popTo(stack.length - 1);
		}
	};

	// (and whether in a table, not in a cell or caption of it: also in what
	//  was put in front of it)
	const inTable = () => {
		const structure = nearest(TABLE_STRUCTURE);
		return structure !== -1 && TABLE_PARTS.has(stack[structure].name) && latest('table') > latest('template');
	};

	// (what a start tag ends before its element: a column group, which holds
	//  only columns; an <svg> or <math>, at an element that leaves it, with
	//  what it holds, unless in an element of theirs that holds HTML)
	const endBefore = tag => {
		if (inColumnGroup() && tag.name !== 'col' && tag.name !== 'template') {
			popTo(stack.length - 1);
		}

		if (inForeign() && (LEAVES_FOREIGN.has(tag.name) || (tag.name === 'font' && ['color', 'face', 'size'].some(attribute => tag.attributes.has(attribute))))) {
			leaveForeign();
		}
	};

	// (how a form starts: left out in a form open outside a template; empty
	//  in a table, where a browser closes it at once, or leaves it out in a
	//  template, which shows nothing either way; or opened)
	const startsForm = () => {
		if (form && latest('template') === -1) {
			return 'none';
		}

		return inTable() ? 'empty' : 'open';
	};

	// (a formatting element or a marker added to those opened again: at most
	//  three alike after the last marker, as browsers keep, and at most
	//  MAX_FORMATTING in all)
	const remember = (element, foreign) => {
		const {name, attributes} = element;
		if (!foreign && FORMATTING.has(name)) {
			const alike = formatting.filter(item => item.element?.name === name && item.element.attributes.get('style') === attributes.get('style') && item.element.attributes.has('hidden') === attributes.has('hidden'));
			const marker = formatting.findLastIndex(item => item.marker);
			if (alike.length >= 3 && formatting.indexOf(alike.at(-3)) > marker) {
				formatting.splice(formatting.indexOf(alike.at(-3)), 1);
			}

			formatting.push({element});
		} else if (!foreign && MARKERS.has(name)) {
			formatting.push({marker: element});
		}

		if (formatting.length > MAX_FORMATTING) {
			formatting.shift();
		}
	};

	let from = 0;
	while (from < html.length) {
		const lt = html.indexOf('<', from);
		const text = lt === from ? '' : decodeEntities(html.slice(from, lt === -1 ? html.length : lt));
		if (text !== '') {
			if (inColumnGroup() && /\S/.test(text)) {
				popTo(stack.length - 1);
			}

			if (state().namespace === 'html') {
				reopen();
			}

			write(text, fostering() && /\S/.test(text) ? parentOf() : state());
		}

		if (lt === -1) {
			break;
		}

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
		// (whether the tag's element and what is around it are hidden: a
		//  hidden element breaks no word)
		let at = state();
		if (tag.closing) {
			at = close(name);
		} else {
			endBefore(tag);
			// (read as HTML, also an <svg> or <math> that starts in HTML, before
			//  which a browser opens formatting elements again)
			const readAsHtml = !inForeign();
			const namespace = readAsHtml ? (name === 'svg' || name === 'math' ? name : 'html') : state().namespace;
			const foreign = namespace !== 'html';
			const formStart = name === 'form' && !foreign ? startsForm() : 'open';
			if (formStart === 'none' || (readAsHtml && formStart === 'open' && !prepare(name))) {
				continue;
			}

			const parent = (foreign && state().namespace !== 'html') || IN_TABLE.has(name) ? state() : parentOf();
			const element = elementOf(name, tag.attributes, parent, namespace);
			at = element;
			if (name === 'form' && !foreign && latest('template') === -1) {
				form = element;
				element.open = formStart === 'open';
			}

			// (an element is opened unless it has no content, or closes
			//  itself in an <svg> or <math>)
			if (foreign ? !tag.selfClosing : !VOID.has(name) && formStart === 'open') {
				push(element);
				remember(element, foreign);
			}

			if (name === 'plaintext' && !foreign) {
				// (all after it is shown as it is)
				parts.push('\n');
				write(html.slice(tag.end));
				break;
			}

			if ((UNSHOWN.has(name) || RAW_SHOWN.has(name)) && !foreign) {
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

		// (a start tag breaks as its element does, and an end tag that closed
		//  nothing as one of its name: a stray "</p>" or "</br>" breaks the
		//  line; one that closed an element broke where it ended)
		if (!tag.closing) {
			parts.push(breakOf(at));
		} else if (at.open !== false && BREAKS.has(name) && at.gone === 0 && (at.box ?? at.collapsed) <= 0) {
			parts.push(LINE.has(name) ? '\n' : ' ');
		}
	}

	return {text: parts.join(''), hidden};
}
