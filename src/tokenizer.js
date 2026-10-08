import {parse as parseDomain} from 'tldts';
import {scriptOf, detectLanguage} from './language.js';

/**
 * A regular expression matching any character in the given ranges of code
 * points, each [first] or [first, last]. Built from numbers so invisible
 * characters never appear in the source.
 * @param {number[][]} ranges
 * @param {string} [flags]
 * @returns {RegExp}
 */
export function characterClass(ranges, flags = 'gu') {
	const hex = code => `\\u{${code.toString(16)}}`;
	return new RegExp(`[${ranges.map(([first, last]) => (last ? `${hex(first)}-${hex(last)}` : hex(first))).join('')}]`, flags);
}

// Invisible characters spammers put inside words to break filters: zero width
// space, word joiner, byte order mark, soft hyphen and bidirectional overrides.
// Joiners (U+200C, U+200D) are legitimate in Persian, Indic scripts and emoji,
// so they are removed without counting as obfuscation.
const OBFUSCATING = characterClass([[0xAD], [0x3_4F], [0x11_5F, 0x11_60], [0x17_B4, 0x17_B5], [0x18_0E], [0x20_0B], [0x20_0E, 0x20_0F], [0x20_2A, 0x20_2E], [0x20_60, 0x20_64], [0x20_66, 0x20_69], [0x31_64], [0xFE_FF], [0xFF_A0]]);
const JOINERS = characterClass([[0x20_0C, 0x20_0D], [0xFE_00, 0xFE_0F]]);

// Mathematical, enclosed and fullwidth letters that NFKC folds to plain ones.
const STYLED_LETTERS = characterClass([[0x1_D4_00, 0x1_D7_FF], [0x1_F1_30, 0x1_F1_89], [0x24_60, 0x24_FF], [0xFF_21, 0xFF_3A], [0xFF_41, 0xFF_5A]], 'u');

// Cyrillic and Greek letters that look like Latin ones. Applied only inside a
// word that mixes scripts ("pаypal" with a Cyrillic "а"), never to a word that
// is entirely Cyrillic or Greek.
const LOOKALIKES = {
	а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x', ѕ: 's', і: 'i', ї: 'i', ј: 'j', ԁ: 'd', ԛ: 'q', ԝ: 'w', һ: 'h', ӏ: 'l', ɡ: 'g', ь: 'b', п: 'n', г: 'r',
	α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ω: 'w', γ: 'y', μ: 'u',
};

// Digits used as letters ("fr33", "v1agra").
const LEET = {
	0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b',
};

// Scripts written without spaces between words: single characters are words.
const UNSPACED = new Set(['Han', 'Hiragana', 'Katakana', 'Thai', 'Lao', 'Khmer', 'Myanmar']);

const URL_PATTERN = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+|\b[a-z\d][a-z\d-]*(?:\.[a-z\d-]+)*\.[a-z]{2,24}\/[^\s<>"'`]*/giu;
const EMAIL_PATTERN = /[\p{L}\p{N}._%+-]+@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)*\.\p{L}{2,24}/gu;
const PHONE_PATTERN = /(?:\+|0{2})\d[\d\s().-]{7,}\d|\(\d{3}\)\s?\d{3}[\s.-]\d{4}|\b(?:\d{3}[.-]){2}\d{4}\b/g;
const IP_PATTERN = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
const MONEY_PATTERN = /[$€£¥₹₽₩₺₦]\s?\d|\d\s?(?:[$€£¥₹₽₩₺₦]|usd|eur|gbp|dollars?|euros?)\b/giu;
const BITCOIN_PATTERN = /\b(?:bc1[ac-hj-np-z02-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const CARD_PATTERN = /\b(?:\d[ -]?){13,19}\b/g;

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bit.do', 'v.gd', 's.id', 't.ly', 'lnkd.in', 'qrco.de', 'shorturl.asia', 'urlz.fr']);

const FREEMAIL = new Set(['gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com', 'outlook.com', 'live.com', 'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mail.com', 'gmx.com', 'gmx.de', 'gmx.net', 'web.de', 'yandex.ru', 'yandex.com', 'mail.ru', 'qq.com', '163.com', '126.com', 'proton.me', 'protonmail.com', 'zoho.com', 'naver.com', 'daum.net', 'rediffmail.com', 'libero.it', 'orange.fr', 'laposte.net', 'wp.pl', 'o2.pl', 'seznam.cz', 'rambler.ru', 'tutanota.com', 'tuta.com']);

const segmenters = new Map();
function segmenter(key = 'und') {
	if (!segmenters.has(key)) {
		let instance;
		try {
			instance = new Intl.Segmenter(key, {granularity: 'word'});
		} catch {
			instance = new Intl.Segmenter('und', {granularity: 'word'});
		}

		segmenters.set(key, instance);
	}

	return segmenters.get(key);
}

/**
 * Split text into pieces of at most `size` characters, at whitespace or
 * punctuation where possible.
 *
 * Intl.Segmenter takes quadratic time on long strings in Node.js 18 (158,000
 * characters take ten seconds), so text is segmented in short pieces.
 *
 * @param {string} text
 * @param {number} [size]
 * @returns {string[]}
 */
export function chunk(text, size = 1000) {
	const pieces = [];
	let start = 0;
	while (start < text.length) {
		let end = Math.min(start + size, text.length);
		if (end < text.length) {
			const window = text.slice(start, end);
			const cut = Math.max(window.lastIndexOf(' '), window.lastIndexOf('\n'), window.lastIndexOf('。'), window.lastIndexOf('，'), window.lastIndexOf('、'));
			if (cut > size / 4) {
				end = start + cut + 1;
			} else if (text.codePointAt(end - 1) > 0xFF_FF) {
				// Never split a surrogate pair (codePointAt at a high surrogate
				// reads the whole pair).
				end--;
			}
		}

		pieces.push(text.slice(start, end));
		start = end;
	}

	return pieces;
}

/**
 * Normalize text the way the classifier sees it: invisible characters
 * removed, compatibility forms folded (NFKC turns "ｆｒｅｅ" and "𝐅𝐑𝐄𝐄" into
 * "free"), lowercased.
 * @param {string} text
 * @returns {{text: string, invisible: number, styled: boolean}}
 */
export function normalizeText(text) {
	if (typeof text !== 'string' || text === '') {
		return {text: '', invisible: 0, styled: false};
	}

	let invisible = 0;
	const stripped = text.replaceAll(OBFUSCATING, () => {
		invisible++;
		return '';
	}).replaceAll(JOINERS, '');
	const styled = STYLED_LETTERS.test(stripped);
	return {text: stripped.normalize('NFKC').toLowerCase(), invisible, styled};
}

function mixedScripts(word) {
	const scripts = new Set();
	for (const char of word) {
		if (/\p{L}/u.test(char)) {
			const script = scriptOf(char);
			if (script === 'Latin' || script === 'Cyrillic' || script === 'Greek') {
				scripts.add(script);
			}
		}
	}

	return scripts.size > 1;
}

function foldLookalikes(word) {
	let out = '';
	for (const char of word) {
		out += LOOKALIKES[char] || char;
	}

	return out;
}

/**
 * Split text into words in any writing system.
 *
 * Uses the Unicode word boundary rules (Intl.Segmenter), with dictionaries for
 * Chinese, Japanese, Thai, Lao, Khmer and Burmese. Words are normalized with
 * normalizeText first. Returns the words and the obfuscation seen.
 *
 * @param {string} text
 * @param {object} [options]
 * @param {string} [options.locale] - hint for the segmenter, e.g. "ja"
 * @param {number} [options.maxLength] - characters of text to read
 * @returns {{words: string[], invisible: number, styled: boolean, mixed: number, leet: number}}
 */
export function segmentWords(text, options = {}) {
	const {locale, maxLength = 100_000} = options;
	const normalized = normalizeText(typeof text === 'string' ? text.slice(0, maxLength) : '');
	const words = [];
	let mixed = 0;
	let leet = 0;
	const seg = segmenter(locale);
	for (const piece of chunk(normalized.text)) {
		for (const {segment, isWordLike} of seg.segment(piece)) {
			if (!isWordLike || !/[\p{L}\p{N}]/u.test(segment)) {
				continue;
			}

			let word = segment;
			if (mixedScripts(word)) {
				mixed++;
				word = foldLookalikes(word);
			}

			if (/^\p{Script=Latin}+$/u.test(word.replaceAll(/\d/g, '')) && /\p{L}\d+\p{L}/u.test(word) && /[0134578]/.test(word)) {
				leet++;
				word = word.replaceAll(/\d/g, digit => LEET[digit] || digit);
			}

			const first = scriptOf([...word][0]);
			if ([...word].length === 1 && !UNSPACED.has(first) && !/\p{N}/u.test(word)) {
				continue;
			}

			words.push(word);
		}
	}

	return {
		words, invisible: normalized.invisible, styled: normalized.styled, mixed, leet,
	};
}

function bucket(n, steps) {
	let i = 0;
	while (i < steps.length && n > steps[i]) {
		i++;
	}

	return i;
}

/**
 * The registrable domain of a host name ("mail.example.co.uk" gives
 * "example.co.uk"), or the host itself for IP addresses and unknown suffixes.
 * @param {string} host
 * @returns {string}
 */
export function registrableDomain(host) {
	const parsed = parseDomain(host, {allowPrivateDomains: true});
	return parsed.domain || parsed.hostname || host;
}

/**
 * Find the links in plain text and HTML. For each link, the host, and for
 * HTML links the visible text when it is itself a web address.
 * @param {string} text
 * @param {string} html
 * @returns {Array<{url: string, host: string, text: string|null}>}
 */
export function extractLinks(text, html) {
	const links = [];
	const seen = new Set();
	const add = (raw, shown = null) => {
		let href = raw.trim().replace(/[).,;:!?'"\]]+$/, '');
		if (/^www\./i.test(href)) {
			href = `http://${href}`;
		}

		if (!/^[a-z][a-z\d+.-]*:/i.test(href)) {
			href = `http://${href}`;
		}

		let url;
		try {
			url = new URL(href);
		} catch {
			return;
		}

		if (url.protocol !== 'http:' && url.protocol !== 'https:') {
			return;
		}

		const key = `${url.href}\n${shown || ''}`;
		if (seen.has(key)) {
			return;
		}

		seen.add(key);
		links.push({url: url.href, host: url.hostname.toLowerCase().replace(/\.$/, ''), text: shown});
	};

	if (typeof html === 'string' && html) {
		const anchor = /<a\b[^>]{0,2000}?\bhref\s*=\s*(?:"([^"]{1,4000})"|'([^']{1,4000})'|([^\s>]{1,4000}))[^>]{0,2000}>([\s\S]{0,2000}?)<\/a\s*>/gi;
		for (const match of html.matchAll(anchor)) {
			const href = decodeEntities(match[1] || match[2] || match[3]);
			const inner = decodeEntities(match[4].replaceAll(/<[^>]*>/g, '')).trim();
			const shown = /^(?:https?:\/\/|www\.)\S+$|^[a-z\d-]+(?:\.[a-z\d-]+)+(?:\/\S*)?$/i.test(inner) ? inner : null;
			add(href, shown);
		}
	}

	for (const source of [text, typeof html === 'string' ? html.replaceAll(/<a\b[^>]*>/gi, ' ') : '']) {
		if (typeof source === 'string' && source) {
			for (const match of source.slice(0, 500_000).matchAll(URL_PATTERN)) {
				add(match[0]);
			}
		}
	}

	return links;
}

const ENTITIES = {
	amp: '&', lt: '<', gt: '>', quot: '"', apos: '\'', nbsp: ' ',
};
function decodeEntities(value) {
	return value.replaceAll(/&(#x[\da-f]+|#\d+|[a-z]+);/gi, (match, entity) => {
		if (entity[0] === '#') {
			const code = entity[1] === 'x' || entity[1] === 'X' ? Number.parseInt(entity.slice(2), 16) : Number.parseInt(entity.slice(1), 10);
			return code > 0 && code <= 0x10_FF_FF ? String.fromCodePoint(code) : match;
		}

		return ENTITIES[entity.toLowerCase()] ?? match;
	});
}

/**
 * Whether the visible text of a link names a different site than the link
 * goes to ("https://paypal.com" linking to another domain).
 * @param {{host: string, text: string|null}} link
 * @returns {boolean}
 */
export function isDeceptiveLink(link) {
	if (!link.text) {
		return false;
	}

	let shownHost;
	try {
		shownHost = new URL(/^https?:\/\//i.test(link.text) ? link.text : `http://${link.text}`).hostname.toLowerCase();
	} catch {
		return false;
	}

	if (!shownHost.includes('.')) {
		return false;
	}

	return registrableDomain(shownHost) !== registrableDomain(link.host);
}

function addressDomain(address) {
	const at = address.lastIndexOf('@');
	return at === -1 ? '' : address.slice(at + 1).toLowerCase().replace(/[>\s]+$/, '');
}

function firstAddress(field) {
	return field?.value?.find(entry => entry.address) || null;
}

function headerValue(mail, name) {
	const value = mail.headers?.get?.(name);
	if (value === undefined || value === null) {
		return '';
	}

	if (typeof value === 'string') {
		return value;
	}

	if (Array.isArray(value)) {
		return value.map(String).join(' ');
	}

	return value.value ?? value.text ?? String(value);
}

function addPatternFeatures(text, add) {
	// Links, addresses and numbers become features of their own and are taken
	// out of the text, so their fragments do not become words.
	let body = text;
	const patterns = [
		['url', URL_PATTERN],
		['email', EMAIL_PATTERN],
		['ip', IP_PATTERN],
		['btc', BITCOIN_PATTERN],
		['card', CARD_PATTERN],
		['phone', PHONE_PATTERN],
	];
	for (const [name, pattern] of patterns) {
		let count = 0;
		body = body.replace(pattern, () => {
			count++;
			return ' ';
		});
		if (count > 0) {
			add(`pat:${name}`);
			add(`pat:${name}:${bucket(count, [1, 3, 10])}`);
		}
	}

	MONEY_PATTERN.lastIndex = 0;
	if (MONEY_PATTERN.test(text)) {
		add('pat:money');
	}

	return body;
}

function addWordFeatures(words, maxBigrams, add) {
	for (const word of words) {
		const {length} = [...word];
		if (/^\p{N}+$/u.test(word)) {
			add(`num:${Math.min(length, 12)}`);
		} else if (length > 30) {
			add(`long:${scriptOf([...word][0])}:${Math.min(Math.floor(length / 10), 9)}`);
		} else {
			add(word);
		}
	}

	const pairs = Math.min(words.length - 1, maxBigrams);
	for (let i = 0; i < pairs; i++) {
		add(`${words[i]} ${words[i + 1]}`);
	}

	add(words.length === 0 ? 'body:empty' : `body:words:${bucket(words.length, [10, 50, 200, 1000])}`);
}

function addSubjectFeatures(subject, words, add) {
	for (const word of words) {
		add(`s:${word}`);
	}

	if (subject === '') {
		add('s:empty');
		return;
	}

	const letters = subject.match(/\p{L}/gu) || [];
	const upper = subject.match(/\p{Lu}/gu) || [];
	if (letters.length >= 8 && upper.length / letters.length > 0.6) {
		add('s:caps');
	}

	if (/[!?]{2,}/.test(subject)) {
		add('s:punct');
	}

	if (/\p{Extended_Pictographic}/u.test(subject)) {
		add('s:emoji');
	}

	if (/^\s*(?:re|fwd?|aw|wg|sv|tr|rv|ref)\s*:/i.test(subject)) {
		add('s:reply');
	}
}

function addObfuscationFeatures(parts, add) {
	const invisible = parts.reduce((sum, part) => sum + part.invisible, 0);
	if (invisible > 0) {
		add('obf:invisible');
		add(`obf:invisible:${bucket(invisible, [2, 10])}`);
	}

	if (parts.some(part => part.styled)) {
		add('obf:styled');
	}

	if (parts.some(part => part.mixed > 0)) {
		add('obf:mixed');
	}

	if (parts.some(part => part.leet > 0)) {
		add('obf:leet');
	}
}

function addLinkFeatures(links, add) {
	const hosts = new Set();
	for (const link of links) {
		const domain = registrableDomain(link.host);
		hosts.add(domain);
		add(`url:${domain}`);
		const tld = link.host.split('.').pop();
		if (/^\d+$/.test(tld) || link.host.includes(':')) {
			add('url:ip');
		} else {
			add(`url:tld:${tld}`);
		}

		if (SHORTENERS.has(domain)) {
			add('url:shortener');
		}

		if (link.host.split('.').some(label => label.startsWith('xn--'))) {
			add('url:punycode');
		}

		// "https://paypal.com@evil.example/" shows one name and goes elsewhere.
		if (new URL(link.url).username) {
			add('url:userinfo');
		}

		if (isDeceptiveLink(link)) {
			add('url:deceptive');
		}
	}

	if (links.length > 0) {
		add(`url:count:${bucket(links.length, [1, 3, 10, 30])}`);
		add(`url:domains:${bucket(hosts.size, [1, 3, 10])}`);
	}
}

function addSenderFeatures(mail, add) {
	const from = firstAddress(mail.from);
	if (!from) {
		add('from:none');
		return;
	}

	const domain = addressDomain(from.address);
	if (domain) {
		add(`from:${registrableDomain(domain)}`);
		add(`from:tld:${domain.split('.').pop()}`);
		if (FREEMAIL.has(domain)) {
			add('from:freemail');
		}
	}

	const name = typeof from.name === 'string' ? from.name : '';
	const named = name.match(/[\p{L}\p{N}._%+-]+@([\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)/u);
	if (named && registrableDomain(named[1].toLowerCase()) !== registrableDomain(domain)) {
		add('from:name_has_other_address');
	}

	for (const word of segmentWords(name).words) {
		add(`fn:${word}`);
	}

	const replyTo = firstAddress(mail.replyTo);
	if (replyTo && registrableDomain(addressDomain(replyTo.address)) !== registrableDomain(domain)) {
		add('replyto:other_domain');
		if (FREEMAIL.has(addressDomain(replyTo.address))) {
			add('replyto:freemail');
		}
	}
}

function addHtmlFeatures(mail, html, words, add) {
	if (!html) {
		return;
	}

	// Mailparser makes text from HTML when a message has no text part, so the
	// Content-Type tells whether the sender wrote any plain text.
	const contentType = mail.headers?.get?.('content-type');
	const htmlOnly = !(typeof mail.text === 'string' && mail.text) || (contentType?.value ?? contentType) === 'text/html';
	add(htmlOnly ? 'html:only' : 'html:alternative');
	if (/<form\b/i.test(html)) {
		add('html:form');
	}

	if (/<script\b/i.test(html)) {
		add('html:script');
	}

	if (/<(?:iframe|object|embed)\b/i.test(html)) {
		add('html:embed');
	}

	if (/display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*[01](?:\.\d+)?(?:px|pt)?\s*[;"']/i.test(html)) {
		add('html:hidden');
	}

	const images = (html.match(/<img\b/gi) || []).length;
	if (images > 0) {
		add(`html:img:${bucket(images, [1, 5, 20])}`);
		if (words.length < 20) {
			add('html:img_little_text');
		}
	}

	if (/<img\b[^>]*\b(?:width|height)\s*=\s*["']?[01]["'\s>]/i.test(html)) {
		add('html:pixel');
	}
}

function addAttachmentFeatures(mail, add) {
	const attachments = Array.isArray(mail.attachments) ? mail.attachments : [];
	for (const attachment of attachments) {
		const name = typeof attachment.filename === 'string' ? attachment.filename.toLowerCase() : '';
		const extension = name.includes('.') ? name.split('.').pop().slice(0, 10) : '';
		if (extension) {
			add(`att:ext:${extension}`);
		}

		if (typeof attachment.contentType === 'string') {
			add(`att:type:${attachment.contentType.toLowerCase().split(';')[0]}`);
		}
	}

	add(`att:count:${bucket(attachments.length, [0, 1, 3])}`);
}

function addHeaderFeatures(mail, add) {
	if (!mail.headers?.get) {
		return;
	}

	const mailer = headerValue(mail, 'x-mailer') || headerValue(mail, 'user-agent');
	if (mailer) {
		add(`hdr:mailer:${mailer.toLowerCase().split(/[\s/(;]/)[0].slice(0, 20)}`);
	}

	if (!mail.messageId) {
		add('hdr:no_message_id');
	}

	if (!mail.date) {
		add('hdr:no_date');
	}

	// Mailparser groups List-* headers under "list".
	const list = mail.headers.get('list') || {};
	if (list.unsubscribe || headerValue(mail, 'list-unsubscribe')) {
		add('hdr:list_unsubscribe');
	}

	if (list.id || headerValue(mail, 'list-id')) {
		add('hdr:list_id');
	}

	const precedence = headerValue(mail, 'precedence').toLowerCase().trim();
	if (precedence) {
		add(`hdr:precedence:${precedence.slice(0, 10)}`);
	}

	// Mailparser folds X-Priority, Importance and similar headers into "priority".
	if (headerValue(mail, 'priority') === 'high' || /^\s*[12]\b/.test(headerValue(mail, 'x-priority')) || /high|urgent/i.test(headerValue(mail, 'importance'))) {
		add('hdr:priority_high');
	}

	const received = mail.headers.get('received');
	const hops = Array.isArray(received) ? received.length : (received ? 1 : 0);
	add(`hdr:received:${bucket(hops, [0, 1, 3, 6])}`);
}

/**
 * Classifier features of a message parsed by mailparser.
 *
 * Every word of the body is a feature, every pair of neighbouring words is
 * another, and the subject's words are features of their own ("s:free").
 * The rest describe structure: link domains and tricks, the sender's domain,
 * HTML forms and hidden text, attachment types, headers, language and script,
 * and obfuscation. The same message always gives the same features.
 *
 * @param {object} mail - parsed message (text, html, subject, from, headers, attachments)
 * @param {object} [options]
 * @param {number} [options.maxLength] - characters of body text to read
 * @param {number} [options.maxBigrams] - word pairs to emit
 * @returns {{features: string[], words: string[], language: string|null, script: string|null, links: Array}}
 */
export function getFeatures(mail = {}, options = {}) {
	const {maxLength = 100_000, maxBigrams = 3000} = options;
	const features = new Set();
	const add = feature => features.add(feature);

	const html = typeof mail.html === 'string' ? mail.html : '';
	let text = typeof mail.text === 'string' ? mail.text : '';
	if (!text && html) {
		text = decodeEntities(html.replaceAll(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, ' ').replaceAll(/<[^>]*>/g, ' '));
	}

	text = text.slice(0, maxLength);
	const subject = typeof mail.subject === 'string' ? mail.subject : '';
	const links = extractLinks(text, html.slice(0, maxLength * 2));
	const body = addPatternFeatures(text, add);

	const detected = detectLanguage(`${subject}\n${body}`);
	if (detected.language) {
		add(`lang:${detected.language}`);
	}

	if (detected.script) {
		add(`script:${detected.script}`);
	}

	if (detected.scripts.length > 1) {
		add('script:mixed');
	}

	const locale = detected.language || undefined;
	const segmented = segmentWords(body, {locale, maxLength});
	const subjectWords = segmentWords(subject, {locale});
	addWordFeatures(segmented.words, maxBigrams, add);
	addSubjectFeatures(subject, subjectWords.words, add);
	addObfuscationFeatures([segmented, subjectWords], add);
	addLinkFeatures(links, add);
	addSenderFeatures(mail, add);
	addHtmlFeatures(mail, html, segmented.words, add);
	addAttachmentFeatures(mail, add);
	addHeaderFeatures(mail, add);

	return {
		features: [...features],
		words: segmented.words,
		language: detected.language,
		script: detected.script,
		links,
	};
}
