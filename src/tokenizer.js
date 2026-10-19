import {parse as parseDomain} from 'tldts';
import {BRANDS} from './homograph.js';
import {decodeEntities, visibleText} from './html.js';
import {scriptOf, detectLanguage} from './language.js';
import {
	foldToAscii, linear, matchesOf, trimEndOf,
} from './linear.js';

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
const INVISIBLE = [[0xAD], [0x3_4F], [0x11_5F, 0x11_60], [0x17_B4, 0x17_B5], [0x18_0E], [0x20_0B], [0x20_0E, 0x20_0F], [0x20_2A, 0x20_2E], [0x20_60, 0x20_64], [0x20_66, 0x20_69], [0x31_64], [0xFE_FF], [0xFF_A0]];
const OBFUSCATING = characterClass(INVISIBLE);
const JOINERS = characterClass([[0x20_0C, 0x20_0D], [0xFE_00, 0xFE_0F]]);
// Those characters and the joiners, as normalizeText reads them: a joiner
// counts only between Latin letters ("v\u200Ci\u200Cagra"), whose words never
// need one (not in Persian, Indic scripts or emoji sequences).
const INVISIBLE_OR_JOINER = characterClass([...INVISIBLE, [0x20_0C, 0x20_0D]]);
const ZERO_WIDTH_SPACE = '\u200B';
const ZERO_WIDTH_JOINERS = new Set(['\u200C', '\u200D']);
const LATIN_END = /\p{Script=Latin}$/u;
const LATIN_START = /^\p{Script=Latin}/u;
// Scripts written without spaces between words, which may separate them with
// zero width spaces (Thai, Lao, Khmer, Burmese and Tibetan): one between two
// of their letters (or marks) is a word break, no obfuscation.
const ZWSP_SCRIPTS = String.raw`\p{Script=Thai}\p{Script=Lao}\p{Script=Khmer}\p{Script=Myanmar}\p{Script=Tibetan}`;
const ZWSP_SCRIPT_END = new RegExp(`[${ZWSP_SCRIPTS}]$`, 'u');
const ZWSP_SCRIPT_START = new RegExp(`^[${ZWSP_SCRIPTS}]`, 'u');
// Of these, the ones that are no obfuscation: the soft hyphen, a hint where a
// long word may break (German writes "Garten\u00ADm\u00F6bel"), and the
// bidirectional marks, embeddings and isolates in text with Hebrew or Arabic
// letters, which need them around numbers and Latin words (not the overrides,
// U+202D and U+202E, which show letters in another order than they are
// written: "pay\u202Elap" reads "paypal").
const SOFT_HYPHEN = '\u00AD';
const BIDI = characterClass([[0x20_0E, 0x20_0F], [0x20_2A, 0x20_2C], [0x20_66, 0x20_69]], 'u');
const RIGHT_TO_LEFT = /[\p{Script=Hebrew}\p{Script=Arabic}]/u;
// A letter (or the mark of one) or a digit at the end or the start of a
// string, two code units for one outside the Basic Multilingual Plane.
const LETTER_END = /[\p{L}\p{M}\p{N}]$/u;
const LETTER_START = /^[\p{L}\p{M}\p{N}]/u;
const DIGIT_END = /\p{N}$/u;
const DIGIT_START = /^\p{N}/u;

// Mathematical letters and squared Latin letters, which NFKC folds to plain
// ones (not the negative circled and squared letters after them, "\u{1F150}"
// to "\u{1F189}", which NFKC keeps: emoji such as "\u{1F17F}\uFE0F" for
// parking).
const STYLED_LETTERS = characterClass([[0x1_D4_00, 0x1_D7_FF], [0x1_F1_30, 0x1_F1_49]], 'u');
// Fullwidth Latin letters and circled numbers and letters, also folded, but
// written as they are in Chinese, Japanese and Korean text ("\uFF30\uFF24\uFF26",
// "\u2460"): styled only in text without those scripts.
const WIDE_LETTERS = characterClass([[0x24_60, 0x24_FF], [0xFF_21, 0xFF_3A], [0xFF_41, 0xFF_5A]], 'u');
const CJK = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u;

// Cyrillic and Greek letters that look like Latin ones. Applied only inside a
// word that mixes scripts ("pаypal" with a Cyrillic "а"), never to a word that
// is entirely Cyrillic or Greek.
const LOOKALIKES = {
	а: 'a', в: 'b', е: 'e', ё: 'e', к: 'k', м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x', ѕ: 's', і: 'i', ї: 'i', ј: 'j', ԁ: 'd', ԛ: 'q', ԝ: 'w', һ: 'h', ӏ: 'l', ɡ: 'g', ь: 'b', п: 'n', г: 'r',
	α: 'a', β: 'b', ε: 'e', η: 'n', ι: 'i', κ: 'k', ν: 'v', ο: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ω: 'w', γ: 'y', μ: 'u',
};

// Greek letters of units, "\u00B5" and "\u2126" ("10 \u00B5g", "5 k\u2126"), as NFKC
// and lowercasing make them: a unit ("\u03BCg", "k\u03C9", "10\u03BCmol",
// "\u03BCm\u00B2", which NFKC makes "\u03BCm2") with
// no other Greek letter mixes no scripts (but "\u03BCpdate" does).
const UNIT_LETTERS = new Set(['\u03BC', '\u03C9']);
const UNIT_WORD = /^[\d.,]*[kmgμ]?[μω][a-z]{0,3}\d?$/u;

// Digits used as letters ("fr33dom", "v1agra").
const LEET = {
	0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b',
};
// One or two of those digits between letters, in a word of Latin letters (see
// isLeet).
const LEET_DIGITS = /\p{L}[0134578]{1,2}\p{L}/u;

// Scripts written without spaces between words: single characters are words.
const UNSPACED = new Set(['Han', 'Hiragana', 'Katakana', 'Thai', 'Lao', 'Khmer', 'Myanmar']);

// Patterns for message content (see linear.js). Host names and email
// addresses are bounded as DNS and SMTP bound them (63 characters a label,
// 64 a local part), so a long run of letters is not read again from each
// position in it (on RE2, which is linear anyway, the classes of letters of
// any script in addresses are not bounded: see BOUNDED in linear.js).
const URL_PATTERN = linear(String.raw`\b(?:https?:\/\/|www\.)[^\s<>"'\x60]+|\b[a-z\d][a-z\d-]{0,62}(?:\.[a-z\d-]{1,63}){0,10}\.[a-z]{2,24}\/[^\s<>"'\x60]*`, 'giu');
export const EMAIL_SOURCE = String.raw`[\p{L}\p{N}._%+-]{1,64}@([\p{L}\p{N}-]{1,63}(?:\.[\p{L}\p{N}-]{1,63}){0,10}\.\p{L}{2,24})`;
const EMAIL_PATTERN = linear(EMAIL_SOURCE, 'gu');
const PHONE_PATTERN = linear(String.raw`(?:\+|0{2})\d[\d\s().-]{7,}\d|\(\d{3}\)\s?\d{3}[\s.-]\d{4}|\b(?:\d{3}[.-]){2}\d{4}\b`, 'g');
const IP_PATTERN = linear(String.raw`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`, 'g');
const MONEY_PATTERN = linear(String.raw`[$€£¥₹₽₩₺₦]\s?\d|\d\s?(?:[$€£¥₹₽₩₺₦]|usd|eur|gbp|dollars?|euros?)\b`, 'giu');
const BITCOIN_PATTERN = linear(String.raw`\b(?:bc1[ac-hj-np-z02-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`, 'g');
const CARD_PATTERN = linear(String.raw`\b(?:\d[ -]?){13,19}\b`, 'g');
// An HTML link: the opening tag, then the href in it and the text up to
// "</a>" (see anchors).
// ("<a" then a space, "/" or ">", as browsers end a tag name: not "<a-b")
const ANCHOR_START = linear(String.raw`<a[\t\n\f\r />]`, 'gi');
// The most characters of HTML a link's text is read from (see anchors)
const MAX_LINK_TEXT = 2000;
// The most of a link's address kept (its host is always kept whole)
const MAX_URL = 16_384;
const SHOWN_URL = linear(String.raw`^(?:https?:\/\/|www\.)\S+$|^[a-z\d-]{1,63}(?:\.[a-z\d-]{1,63}){1,10}(?:\/\S*)?$`, 'i');
const IMG_PIXEL = linear(String.raw`<img\b[^<>]*\b(?:width|height)\s*=\s*["']?[01]["'\s>]`, 'i');
const IMG = linear(String.raw`<img\b`, 'gi');
// A host name written without "http://" ("paypa1-secure.example") or in an
// email address.
const BARE_HOST = linear(String.raw`\b[a-z\d][a-z\d-]{0,62}(?:\.[a-z\d-]{1,63}){0,9}\.[a-z]{2,24}\b`, 'gi');
const MAX_BARE_HOSTS = 50;
// A character of a name, at the end of a string (two code units for one
// outside the Basic Multilingual Plane).
const NAME_END = /[\p{L}\p{N}\p{M}_]$/u;

// Whether text[index] continues a longer name: after a letter, digit or mark,
// or after a "." or "-" that follows one ("nchen-ups.de" in "münchen-ups.de",
// not "paypa1.com" in "Go...paypa1.com"). Not after a letter or mark of a
// script written without spaces ("paypal-secure.com/login" in
// "\u8ACB\u8A2A\u554Fpaypal-secure.com/login").
function continuesName(text, index) {
	const before = text.slice(Math.max(0, index - 2), index);
	if (NAME_END.test(before)) {
		return !UNSPACED.has(scriptOf([...before].at(-1)));
	}

	return (text[index - 1] === '.' || text[index - 1] === '-') && NAME_END.test(text.slice(Math.max(0, index - 3), index - 1));
}

// Top-level domains that are also file extensions: a name with one dot and
// one of these ("report.zip", "notes.md", "build.sh") is taken for a file
// (not international names, "xn--...", which are not file names)
const FILE_TLDS = new Set(['ai', 'app', 'md', 'mov', 'pm', 'ps', 'py', 'rs', 'sh', 'so', 'zip']);
// Of these, those that name files far more often than sites in the text of a
// link ("README.md", "setup.sh"; not "linear.app" or "character.ai")
const LINK_FILE_TLDS = new Set(['md', 'mov', 'pm', 'ps', 'py', 'rs', 'sh', 'so', 'zip']);

// Hosts of email services that count each click on a link of a message and
// send the reader on to the address it shows, documented as their click
// tracking: SendGrid (*.ct.sendgrid.net), Mailchimp (*.list-manage.com),
// Mandrill (mandrillapp.com), Amazon SES (*.awstrack.me), Postmark
// (click.pstmrk.it), HubSpot (*.hubspotlinks.com), Constant Contact
// (r20.rs6.net), Klaviyo (trk.klclick.com), Mailjet (*.mjt.lu),
// Salesforce Marketing Cloud (click.exacttarget.com), Kit, formerly
// ConvertKit (click.convertkit-mail.com, click.convertkit-mail2.com,
// *.click.kit-mail3.com), Brevo, formerly Sendinblue (*.sendibt2.com,
// *.r.bh.d.sendibt3.com), Campaign Monitor (*.createsend1.com, cmail20.com),
// MailerLite (*.clicks.mlsend.com), ActiveCampaign (*.lt.acemlnb.com) and
// beehiiv (link.mail.beehiiv.com, bhclick.com); and Substack's
// substack.com/redirect/ (see isClickTracker). And the security gateways that
// rewrite each link of the mail they pass to check it when it is clicked, so
// a message forwarded from behind one shows the address it had: Microsoft
// Defender's Safe Links (*.safelinks.protection.outlook.com), Proofpoint
// (urldefense.com, urldefense.proofpoint.com), Mimecast
// (protect-*.mimecast.com, url.*.mimecastprotect.com), Barracuda
// (linkprotect.cudasvc.com) and Cisco (secure-web.cisco.com), whose address
// the original is read from where its form is known (see unwrapLink). A link
// through them that shows another address is deceptive only as
// isDeceptiveLink says.
const CLICK_TRACKERS = ['sendgrid.net', 'list-manage.com', 'mandrillapp.com', 'awstrack.me', 'pstmrk.it', 'hubspotlinks.com', 'rs6.net', 'klclick.com', 'mjt.lu', 'exacttarget.com', 'convertkit-mail.com', 'convertkit-mail2.com', 'kit-mail3.com', 'sendibt2.com', 'sendibt3.com', 'createsend1.com', 'cmail20.com', 'clicks.mlsend.com', 'acemlnb.com', 'link.mail.beehiiv.com', 'bhclick.com', 'safelinks.protection.outlook.com', 'urldefense.com', 'urldefense.proofpoint.com', 'mimecast.com', 'mimecastprotect.com', 'cudasvc.com', 'secure-web.cisco.com'];

// Whether a host is a domain or under it
const isUnder = (host, domain) => host === domain || host.endsWith(`.${domain}`);

// Whether a link goes through click tracking or a security gateway (see
// CLICK_TRACKERS)
function isClickTracker(url) {
	const host = url.hostname.toLowerCase();
	return CLICK_TRACKERS.some(domain => isUnder(host, domain)) || (host === 'substack.com' && url.pathname.startsWith('/redirect/'));
}

// The address a security gateway's link goes on to, as the gateway wrote it
// in the link (see CLICK_TRACKERS), or null: the "url" parameter of Safe
// Links, the "u" parameter of Proofpoint's second form ("https-3A__www.example.com_a",
// "-" and two hex digits for "%" and "_" for "/") and what is between "/v3/__"
// and "__;" in its third
function gatewayTarget(url) {
	const host = url.hostname.toLowerCase();
	if (isUnder(host, 'safelinks.protection.outlook.com')) {
		return url.searchParams.get('url');
	}

	if (host === 'urldefense.proofpoint.com' && url.pathname.startsWith('/v2/')) {
		try {
			return decodeURIComponent((url.searchParams.get('u') ?? '').replaceAll('_', '/').replaceAll(/-([\da-f]{2})/gi, '%$1'));
		} catch {
			return null;
		}
	}

	if (host === 'urldefense.com' && url.pathname.startsWith('/v3/__')) {
		const rest = url.href.slice(url.href.indexOf('/v3/__') + 6);
		const end = rest.indexOf('__;');
		return end === -1 ? null : rest.slice(0, end);
	}

	return null;
}

/**
 * The address a link goes to, as a URL: through a security gateway, the
 * address it goes on to (see gatewayTarget), as many as three wrapped in
 * one another; or null for an address that is no URL.
 * @param {string} address
 * @returns {URL|null}
 */
export function unwrapLink(address) {
	let url;
	try {
		url = new URL(address);
	} catch {
		return null;
	}

	for (let depth = 0; depth < 3; depth++) {
		const target = gatewayTarget(url);
		let next;
		try {
			next = new URL(target);
		} catch {
			break;
		}

		if (next.protocol !== 'http:' && next.protocol !== 'https:') {
			break;
		}

		url = next;
	}

	return url;
}

const BRAND_NAMES = new Set(BRANDS);

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
 * Text as a person reads it, for the language model: without the invisible
 * characters put inside words to break filters (not the joiners scripts and
 * emoji need), with compatibility forms folded ("𝐅𝐑𝐄𝐄" and "ＦＲＥＥ" are
 * "FREE"), case kept.
 * @param {string} text
 * @returns {string}
 */
export function readableText(text) {
	return typeof text === 'string' ? text.replaceAll(OBFUSCATING, '').normalize('NFKC') : '';
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

	// Invisible characters are counted only inside a word, between two
	// letters or a letter and a digit ("v\u200B1\u200Bagra"; not a byte order
	// mark at the start of the text, one at the end of a word, or one between
	// digits, which senders put in numbers so phones do not take them for
	// phone numbers): each run of them once it ends. (Read one by one: a
	// pattern for a run of them fails on a long one.)
	// Zero width spaces between two letters of a script that separates words
	// with them (see ZWSP_SCRIPTS) do not count, and joiners count only
	// between Latin letters (see INVISIBLE_OR_JOINER), but neither ends a run
	// ("v\u200D\u200Bi" has one between two letters).
	const rightToLeft = RIGHT_TO_LEFT.test(text);
	let invisible = 0;
	let run = 0;
	let spaces = 0;
	let joiners = 0;
	let runEnd = -1;
	let before = '';
	const settle = () => {
		const next = text.slice(runEnd, runEnd + 2);
		if (LETTER_END.test(before) && LETTER_START.test(next) && !(DIGIT_END.test(before) && DIGIT_START.test(next))) {
			const wordBreak = ZWSP_SCRIPT_END.test(before) && ZWSP_SCRIPT_START.test(next);
			invisible += run - (wordBreak ? spaces : 0) + (LATIN_END.test(before) && LATIN_START.test(next) ? joiners : 0);
		}

		run = 0;
		spaces = 0;
		joiners = 0;
	};

	const stripped = text.replaceAll(INVISIBLE_OR_JOINER, (char, offset) => {
		if (offset !== runEnd) {
			settle();
			before = text.slice(Math.max(0, offset - 2), offset);
		}

		runEnd = offset + 1;
		if (ZERO_WIDTH_JOINERS.has(char)) {
			joiners++;
		} else if (char !== SOFT_HYPHEN && !(rightToLeft && BIDI.test(char))) {
			run++;
			spaces += char === ZERO_WIDTH_SPACE ? 1 : 0;
		}

		return '';
	}).replaceAll(JOINERS, '');
	settle();
	const styled = STYLED_LETTERS.test(stripped) || (WIDE_LETTERS.test(stripped) && !CJK.test(stripped));
	return {text: stripped.normalize('NFKC').toLowerCase(), invisible, styled};
}

// The letters of Latin, Cyrillic and Greek in a word, counted by script
// (not a unit's Greek letter, see UNIT_WORD)
function scriptLetters(word) {
	const unit = UNIT_WORD.test(word);
	const scripts = new Map();
	for (const char of word) {
		if (/\p{L}/u.test(char) && !(unit && UNIT_LETTERS.has(char))) {
			const script = scriptOf(char);
			if (script === 'Latin' || script === 'Cyrillic' || script === 'Greek') {
				scripts.set(script, (scripts.get(script) ?? 0) + 1);
			}
		}
	}

	return scripts;
}

// Whether a word mixes Latin, Cyrillic or Greek letters, each part between
// apostrophes on its own: Russian writes case endings after a name in Latin
// letters so ("iPhone'\u044B", "MacBook\u2019\u0438")
function mixedScripts(word) {
	return word.split(/['\u2019]/).some(part => scriptLetters(part).size > 1);
}

// Whether a word of Latin letters writes some with digits ("v1agra",
// "fr33dom"): three letters or more and at most three digits, none in a run
// of three, one or two of those that look like letters between letters (not
// "ab12cd", "i18n", "k8s" or a tracking number such as "1z999aa10123456784")
function isLeet(word) {
	if (!/^\p{Script=Latin}+$/u.test(word.replaceAll(/\d/g, '')) || !LEET_DIGITS.test(word) || /\d{3}/.test(word)) {
		return false;
	}

	const digits = word.replaceAll(/\D/g, '').length;
	return digits <= 3 && word.length - digits >= 3;
}

// The lookalikes of Latin letters in Cyrillic and in Greek ("p" is "\u0440"),
// the first of each in LOOKALIKES
const LATIN_LOOKALIKES = {Cyrillic: {}, Greek: {}};
for (const [char, latin] of Object.entries(LOOKALIKES)) {
	const target = LATIN_LOOKALIKES[scriptOf(char)];
	if (target && !target[latin]) {
		target[latin] = char;
	}
}

// A word that mixes scripts with the lookalike letters of the others written
// in the script most of its letters are in: "pa\u0443pal" is "paypal", and
// "\u043Fp\u0438\u0432\u0435\u0442" (with a Latin "p") is
// "\u043F\u0440\u0438\u0432\u0435\u0442"; Latin when as many are Latin
function foldLookalikes(word) {
	let most = 'Latin';
	const counts = scriptLetters(word);
	for (const [script, count] of counts) {
		if (count > (counts.get(most) ?? 0)) {
			most = script;
		}
	}

	let out = '';
	for (const char of word) {
		const script = scriptOf(char);
		out += script === most ? char : ((most === 'Latin' ? LOOKALIKES[char] : script === 'Latin' && LATIN_LOOKALIKES[most][char]) || char);
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
	// (cut again: NFKC makes one character up to 18, "\uFDFA")
	for (const piece of chunk(normalized.text.slice(0, maxLength))) {
		for (const {segment, isWordLike} of seg.segment(piece)) {
			if (!isWordLike || !/[\p{L}\p{N}]/u.test(segment)) {
				continue;
			}

			let word = segment;
			if (mixedScripts(word)) {
				mixed++;
				word = foldLookalikes(word);
			}

			if (isLeet(word)) {
				leet++;
				word = word.replaceAll(/\d/g, digit => LEET[digit] || digit);
			}

			// (a single Latin letter is no word, but one ideograph is, and so is
			//  one Korean syllable: "\uB3C8" is "money")
			const first = scriptOf([...word][0]);
			if ([...word].length === 1 && !UNSPACED.has(first) && first !== 'Hangul' && !/\p{N}/u.test(word)) {
				continue;
			}

			words.push(word);
		}
	}

	return {
		words, invisible: normalized.invisible, styled: normalized.styled, mixed, leet,
	};
}

// Letters of the scripts a mixed-script word mixes (see mixedScripts).
const LATIN = /\p{Script=Latin}/u;
const CYRILLIC_OR_GREEK = /[\p{Script=Cyrillic}\p{Script=Greek}]/u;

/**
 * The obfuscation in text, as segmentWords counts it ({invisible, mixed,
 * styled}), segmenting into words only the parts of the text that could have
 * a word mixing scripts: those with Latin letters and Cyrillic or Greek ones.
 * @param {string} text
 * @param {object} [options]
 * @param {number} [options.maxLength] - characters of text to read
 * @returns {{invisible: number, mixed: number, styled: boolean}}
 */
export function obfuscationOf(text, options = {}) {
	const {maxLength = 100_000} = options;
	const normalized = normalizeText(typeof text === 'string' ? text.slice(0, maxLength) : '');
	// (by the pieces segmentWords reads, segmenting only those with both)
	let mixed = 0;
	for (const piece of chunk(normalized.text.slice(0, maxLength))) {
		if (!LATIN.test(piece) || !CYRILLIC_OR_GREEK.test(piece)) {
			continue;
		}

		for (const {segment, isWordLike} of segmenter().segment(piece)) {
			if (isWordLike && mixedScripts(segment)) {
				mixed++;
			}
		}
	}

	return {invisible: normalized.invisible, mixed, styled: normalized.styled};
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

// The string without C0 control characters and spaces at either end, as the
// URL parser reads an address (by index: a pattern such as /[\0- ]+$/ is
// tried at every position of a long run of them).
function trimControls(value) {
	let start = 0;
	let end = value.length;
	while (start < end && value.codePointAt(start) <= 0x20) {
		start++;
	}

	while (end > start && value.codePointAt(end - 1) <= 0x20) {
		end--;
	}

	return value.slice(start, end);
}

// Whether a name is a file name ("report.zip", "README.md"): one dot and a
// top-level domain that is also a file extension (FILE_TLDS, or those given)
function isFileName(name, extensions = FILE_TLDS) {
	const parsed = parseDomain(name.toLowerCase());
	return !parsed.subdomain && extensions.has(parsed.publicSuffix) && !name.toLowerCase().startsWith('xn--');
}

// Whether a link's text, written as a web address (see SHOWN_URL), is one:
// with "http://", "https://" or "www.", or a name under a real public suffix
// that is no file name ("paypal.com/signin", not "v2.0", "report.pdf" or
// "report.zip")
function isAddress(text) {
	if (/^(?:https?:\/\/|www\.)/i.test(text)) {
		return true;
	}

	const name = text.split('/')[0];
	return isHost(name) && !isFileName(name, LINK_FILE_TLDS);
}

// The address a link's text shows: all of it when it is one (as before), or
// else its first word written as one with "http://" or "https://" ("Sign in
// at https://www.paypal.com"), without punctuation around it; or null. A
// name in a sentence is none ("Read why Booking.com switched", "Weitere Infos
// unter www.firma.de": the name of a site, or of a file, not the address of
// the link).
function shownAddress(inner) {
	if (SHOWN_URL.test(inner)) {
		return isAddress(inner) ? inner : null;
	}

	for (const word of inner.split(' ')) {
		const address = trimEndOf(word.replace(/^[("'<[]+/, ''), ').,;:!?\'">]');
		if (/^https?:\/\/\S/i.test(address)) {
			return address;
		}
	}

	return null;
}

// Tags inside a line of text, which show no break or space where they are
// (and comments, "<!...>"): a name split by them reads as one.
const INLINE_TAG = /^<\/?(?:abbr|b|bdi|bdo|big|cite|code|data|del|dfn|em|font|i|ins|kbd|mark|nobr|q|s|samp|small|span|strike|strong|sub|sup|time|tt|u|var|wbr)(?=[\t\n\f\r />])|^<!/i;
// A character of a host name
const HOST_CHAR = /[\p{L}\p{N}.-]/u;

// Whether a name is a host under a real public suffix ("www.paypal.com",
// not "www" or "www.paypal")
function isHost(name) {
	const parsed = parseDomain(name.toLowerCase());
	return Boolean(parsed.isIcann && parsed.domain);
}

// Whether a link read from HTML ends inside its host name at tags after
// which the name goes on ("https://www." of
// "<b>https://www.</b>paypal<b>.com/</b>"): no link of its own (its text
// shown, read with the text, has the whole address). Only across tags inside
// a line ("<b>", "</span>", not "</p>", "<br>" or "</td>", after which the
// text is another line or cell), and only when its host is no host on its
// own ("https://www.") or the name it goes on to is another one
// ("https://www.pay<i></i>pal.com"), not a word after it
// ("<b>https://evil.example</b>Thanks"). Looks at most at four tags of 256
// characters and 253 characters of name after them.
function endsInsideTag(html, end, link) {
	const host = trimEndOf(link.replace(/^https?:\/\//i, ''), '.-');
	if (html[end] !== '<' || /[/?#:@]/.test(host)) {
		return false;
	}

	let i = end;
	for (let tags = 0; tags < 4 && html[i] === '<'; tags++) {
		const tag = html.slice(i, i + 256);
		const close = tag.indexOf('>');
		if (close === -1 || !INLINE_TAG.test(tag)) {
			return false;
		}

		i += close + 1;
	}

	let after = '';
	while (after.length < 253 && HOST_CHAR.test(html[i + after.length] ?? '')) {
		after += html[i + after.length];
	}

	const joined = trimEndOf(link.replace(/^https?:\/\//i, '') + after, '.-');
	return joined !== host && (!isHost(host) || (isHost(joined) && registrableDomain(joined) !== registrableDomain(host)));
}

/**
 * Find the links in plain text and HTML (in its markup, hidden text too, and
 * in the text it shows, see visibleText, where an address split by inline
 * tags reads as one). For each link, the host, whether
 * its address has a user name or password ("https://paypal.com@evil.example/"
 * shows one name and goes elsewhere), and for HTML links the address the
 * visible text shows, if any (see shownAddress). A link
 * written without "http://" or "www." ("example.com/page") counts only with
 * a real top-level domain (not "file.js/"), and not from the middle of a
 * word ("straße.de/" is no link to "e.de").
 * @param {string} text
 * @param {string} html
 * @param {object} [options]
 * @param {number} [options.maxLength] - characters of each read for links
 *   written in the text (500,000 by default)
 * @returns {Array<{url: string, host: string, text: string|null, userinfo: boolean}>}
 */
const MAX_SHOWN_HTML = 200_000;

export function extractLinks(text, html, {maxLength = 500_000} = {}) {
	// ("\u017F" and "\u212A" as browsers read them in host names, on
	// either engine)
	text = typeof text === 'string' ? foldToAscii(text) : text;
	html = typeof html === 'string' ? foldToAscii(html) : html;
	const links = [];
	const seen = new Set();
	// (whether each name of a link without "http://" is a host, read once)
	const names = new Map();
	const add = (raw, shown = null) => {
		// (as the URL parser reads it: without tabs and line breaks anywhere,
		//  "ht\ttps://evil.example/" is a link to evil.example)
		let href = trimEndOf(trimControls(raw.replaceAll(/[\t\n\r]/g, '')).trim(), ').,;:!?\'"]');
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
		// (an IPv6 address without its brackets, as other addresses are)
		const host = url.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[(.*)]$/, '$1');
		// (the address cut, so whether it has a user name or password is read
		//  before)
		links.push({
			url: url.href.slice(0, MAX_URL), host, text: shown, userinfo: Boolean(url.username || url.password),
		});
	};

	if (typeof html === 'string' && html) {
		for (const {href, inner} of anchors(html)) {
			add(href, shownAddress(inner));
		}
	}

	// (the text of HTML with its character references decoded, as it is shown:
	//  "https&#58;//example.com/" is a link, hidden text too; and the text the
	//  HTML shows, where a name split by tags inside a line reads as one,
	//  "https://www.pay<b></b>pa1.com/": read here, whatever text the caller
	//  gives, as a link of its own only with a host under a real public
	//  suffix, not "https://www.example.comThanks" of
	//  "<b>https://www.example.com</b>Thanks")
	const markup = typeof html === 'string' && html;
	// (the text shown read from as much HTML as the classifier reads: reading
	//  it costs more than finding links)
	const sources = [text, markup ? decodeEntities(withoutAnchorTags(html)) : '', markup ? visibleText(html.slice(0, Math.min(maxLength, MAX_SHOWN_HTML))).text : ''];
	for (const [index, source] of sources.entries()) {
		if (typeof source === 'string' && source) {
			const read = source.slice(0, maxLength);
			for (const match of matchesOf(URL_PATTERN, read)) {
				let [link] = match;
				if (index === 1 && endsInsideTag(read, match.index + link.length, link)) {
					continue;
				}

				if (index === 2 && !isHost(hostOf(link))) {
					continue;
				}

				// (a link in brackets, as mailparser writes the links of HTML in
				//  the text it makes of it: "here [https://example.com/]")
				if (source[match.index - 1] === '[' && link.includes(']')) {
					link = link.slice(0, link.indexOf(']'));
				}

				if (isBareLink(link) && !isBareHost(source, match.index, link, names)) {
					continue;
				}

				add(link);
			}
		}
	}

	return links;
}

// The host name of a link as URL_PATTERN finds it, without a user name, port
// or punctuation after it ("www.example.com" of "https://user@www.example.com:8080/a")
function hostOf(link) {
	const authority = link.replace(/^https?:\/\//i, '').split(/[/?#\\]/)[0];
	return trimEndOf(authority.slice(authority.lastIndexOf('@') + 1).replace(/:\d*$/, ''), ').,;:!?\'"]');
}

// A link written without "http://" or "www."
function isBareLink(link) {
	return !/^(?:https?:\/\/|www\.)/i.test(link);
}

// Whether a link written without "http://" ("example.com/page", at
// `index` in `text`) names a host: not from the middle of a word (see
// continuesName), and a name under a real public suffix ("studio.ai/login"
// and "update.zip/download" are links; "file.js/" is not)
function isBareHost(text, index, link, names = new Map()) {
	if (continuesName(text, index)) {
		return false;
	}

	const host = link.slice(0, link.indexOf('/')).toLowerCase();
	if (!names.has(host)) {
		const parsed = parseDomain(host);
		names.set(host, Boolean(parsed.isIcann && parsed.domain));
	}

	return names.get(host);
}

/**
 * The value of the first href attribute of a tag ("<a ...>"), or null:
 * read attribute by attribute, as browsers read them, so an "href=" inside
 * the value of another attribute is not taken for one. In one pass.
 * @param {string} tag
 * @returns {string|null}
 */
export function hrefOf(tag) {
	let i = tag.search(/[\t\n\f\r />]/);
	if (i === -1) {
		return null;
	}

	const space = char => char === ' ' || char === '\t' || char === '\n' || char === '\f' || char === '\r';
	while (i < tag.length && tag[i] !== '>') {
		if (space(tag[i]) || tag[i] === '/') {
			i++;
			continue;
		}

		let end = i + 1;
		while (end < tag.length && !space(tag[end]) && !'=/>'.includes(tag[end])) {
			end++;
		}

		const name = tag.slice(i, end).toLowerCase();
		while (end < tag.length && space(tag[end])) {
			end++;
		}

		if (tag[end] !== '=') {
			i = end;
			continue;
		}

		end++;
		while (end < tag.length && space(tag[end])) {
			end++;
		}

		let value;
		if (tag[end] === '"' || tag[end] === '\'') {
			const close = tag.indexOf(tag[end], end + 1);
			const stop = close === -1 ? tag.length : close;
			value = tag.slice(end + 1, stop);
			end = stop + 1;
		} else {
			const start = end;
			while (end < tag.length && !space(tag[end]) && tag[end] !== '>') {
				end++;
			}

			value = tag.slice(start, end);
		}

		if (name === 'href') {
			return value;
		}

		i = end;
	}

	return null;
}

/**
 * The end of the tag that starts at `start` (just after its ">"), or -1 when
 * no ">" follows. A quoted attribute may hold ">" ("?a=>b"); a "<" outside
 * quotes is part of the tag, as browsers read it. A quote opens a value only
 * after "=" (in `href=https://a.example/"x` it is part of the value). A quote
 * not closed within 6000 characters is not one: then the tag ends at the next
 * ">".
 * @param {string} html
 * @param {number} start
 * @returns {number}
 */
export function tagEnd(html, start) {
	const limit = Math.min(html.length, start + 6000);
	let quote = null;
	// (the last character outside quotes that is not a space)
	let last = '<';
	for (let i = start + 1; i < limit; i++) {
		const char = html[i];
		if (quote) {
			if (char === quote) {
				quote = null;
				last = char;
			}
		} else if (char === '>') {
			return i + 1;
		} else if ((char === '"' || char === '\'') && last === '=') {
			quote = char;
		} else if (char !== ' ' && char !== '\t' && char !== '\n' && char !== '\f' && char !== '\r') {
			last = char;
		}
	}

	const close = html.indexOf('>', start + 1);
	return close === -1 ? -1 : close + 1;
}

// HTML with its <a> tags replaced by a space (their hrefs are links already),
// as `html.replace(/<a\b[^>]*>/gi, ' ')` does: from each "<a" to the next
// ">" (once no ">" follows, no later "<a" has one either)
function withoutAnchorTags(html) {
	let out = '';
	let from = 0;
	ANCHOR_START.lastIndex = 0;
	let match;
	while ((match = ANCHOR_START.exec(html)) !== null) {
		const close = html.indexOf('>', match.index + 2);
		if (close === -1) {
			break;
		}

		out += `${html.slice(from, match.index)} `;
		from = close + 1;
		ANCHOR_START.lastIndex = from;
	}

	return out + html.slice(from);
}

export {decodeEntities, visibleText} from './html.js';

// Whether the tag at `index` is "<a" ("<a" and a space, "/" or ">") or, with
// `slash`, "</a"
function isAnchorTag(html, index, slash = false) {
	const at = slash ? index + 2 : index + 1;
	return (!slash || html[index + 1] === '/') && (html[at] === 'a' || html[at] === 'A') && '\t\n\f\r />'.includes(html[at + 1] ?? 'x');
}

// The text of a link whose tag ends at `end`, read tag by tag (so a "</a>" in
// the value of an attribute is none): {inner} up to its "</a>" or the next <a>
// tag, which ends it too, when either is within 2000 characters, else no
// inner; and `next`, where to look for the next <a> tag (any "<a" before it
// is in a tag read here).
function linkText(html, end) {
	let i = end;
	for (;;) {
		const open = html.indexOf('<', i);
		if (open === -1 || open - end > MAX_LINK_TEXT) {
			return {inner: null, next: open === -1 ? html.length : open};
		}

		if (isAnchorTag(html, open)) {
			return {inner: html.slice(end, open), next: open};
		}

		const after = tagEnd(html, open);
		if (after === -1) {
			// (no ">" after here: no tag at all, and no "</a>")
			return {inner: null, next: html.length};
		}

		if (isAnchorTag(html, open, true)) {
			return {inner: html.slice(end, open), next: after};
		}

		i = after;
	}
}

/**
 * The links of HTML: each <a> tag with an href, and the text it shows (see
 * visibleText: without hidden text, and here without invisible characters)
 * when "</a>" or another <a> tag follows within 2000 characters (otherwise
 * no text: a mail client shows a link never closed, or around a long image
 * or table, all the same).
 *
 * Read in about one pass: a tag is read up to its end, the tags of a link's
 * text up to its "</a>", and the next <a> tag looked for after them, so the
 * HTML is not read again for each tag. (A tag whose quote is not closed may
 * read up to 6000 characters, but another such tag within them needs the
 * other quote mark, so at most two do.)
 * @param {string} html
 * @returns {Array<{href: string, inner: string}>}
 */
export function anchors(html) {
	const found = [];
	ANCHOR_START.lastIndex = 0;
	let match;
	while ((match = ANCHOR_START.exec(html)) !== null) {
		const end = tagEnd(html, match.index);
		if (end === -1) {
			// (no ">" after here: no later tag ends either)
			break;
		}

		const value = hrefOf(html.slice(match.index, end));
		if (!value) {
			ANCHOR_START.lastIndex = end;
			continue;
		}

		// (folded again: a character reference may stand for "\u017F" or "\u212A")
		const href = foldToAscii(decodeEntities(value, {attribute: true}));
		const {inner, next} = linkText(html, end);
		ANCHOR_START.lastIndex = next;
		if (inner === null) {
			found.push({href, inner: ''});
			continue;
		}

		const shown = foldToAscii(visibleText(inner).text).replaceAll(OBFUSCATING, '').replaceAll(JOINERS, '').replaceAll(/\s+/g, ' ').trim();
		found.push({href, inner: shown});
	}

	return found;
}

/**
 * Host names in text that are not links: written without "http://"
 * ("paypa1-secure.example") or the domain of an email address. Only names
 * under a real public suffix count ("node.js" and "file.txt" do not), written
 * in lowercase as addresses are or all in capitals ("PAYPAL-VERIFY.COM", read
 * in lowercase; so "end.Click" in text missing a space is not taken for one),
 * not the local part of an address, and at most 50.
 * These are for lookalike checks, not classifier features.
 * @param {string} text
 * @param {Set<string>} [known] - hosts of the links already found
 * @returns {string[]}
 */
export function extractHosts(text, known = new Set()) {
	const hosts = new Set();
	if (typeof text !== 'string' || text === '') {
		return [];
	}

	text = foldToAscii(text);
	BARE_HOST.lastIndex = 0;
	let match;
	while ((match = BARE_HOST.exec(text)) !== null && hosts.size < MAX_BARE_HOSTS) {
		const [name] = match;
		const host = name.toLowerCase();
		const next = text[match.index + name.length];
		// (not part of a longer name with letters the pattern does not read,
		//  such as "nchen-ups.de" in "münchen-ups.de"; in lowercase, or all in
		//  capitals, "PAYPAL-VERIFY.COM", but not "end.Click")
		if (continuesName(text, match.index) || (name !== host && name !== name.toUpperCase()) || next === '@' || next === '+' || known.has(host) || hosts.has(host)) {
			continue;
		}

		if (isHost(host) && !isFileName(host)) {
			hosts.add(host);
		}
	}

	return [...hosts];
}

// Brands whose sites newsletters link to as a matter of course: social
// networks, media and marketplaces ("Follow us on https://www.facebook.com/").
// Through click tracking, their addresses are no sign of a hijacked account.
const LINKED_BRANDS = new Set(['airbnb', 'aliexpress', 'alibaba', 'bestbuy', 'booking', 'costco', 'discord', 'ebay', 'facebook', 'github', 'gitlab', 'instagram', 'linkedin', 'roblox', 'shopify', 'skype', 'spotify', 'steam', 'telegram', 'tiktok', 'twitter', 'uber', 'walmart', 'whatsapp', 'zoom']);
// A part of the path of an address that asks to sign in or pay ("signin",
// "ServiceLogin", "YourAccount", "oauth2", "accountverification",
// "updatepayment", "LoginHelp"), between "/", "?", "&", "=", ".", "_" or
// "-", in any case: not a product, a page or a map ("updates", "products")
const SIGN_IN_PART = /^(?:your|my|service|secure)?(?:login|logon|signin|signon|accounts?|verify|verification|security|secure|auth|authenticate|authorize|oauth2?|billing|password|recover|recovery|unlock|confirm|update|wallet|webscr)(?:verification|payment|info|help|page|\d{1,2})?$/;
// ("sign-in" and "log-on" are read as one part)
const signInPath = path => path.toLowerCase().replaceAll(/\b(log|sign)-(in|on)\b/g, '$1$2').split(/[/?&=._-]/).some(part => SIGN_IN_PART.test(part));
// The domains brands send from that hold their name and another word
// ("facebookmail.com"): only these, as the others are anyone's
// ("paypalmail.com", "chasemails.com", "facebookmail.top")
const SENDING_DOMAINS = new Map([
	['dropbox', ['dropboxmail.com']],
	['facebook', ['facebookmail.com']],
	['mcafee', ['mcafeemail.com']],
	['ups', ['upsemail.com']],
	['yahoo', ['yahoonews.com']],
]);

/**
 * Whether the visible text of a link names a different site than the link
 * goes to ("https://paypal.com" linking to another domain). A link through an
 * email service's click tracking (see CLICK_TRACKERS) goes elsewhere by
 * design, so it counts only when the sender is known (`from`, the domain of
 * the From address, or "" for none), the text shows a whole address with
 * "http://" or "https://" of a brand's own domain (see BRANDS; not one that
 * newsletters link to, see LINKED_BRANDS) with no path or one that asks to
 * sign in or pay, and the sender is not that brand (nor one of its sending
 * domains, "facebookmail.com", see SENDING_DOMAINS): a hijacked account of a mailing service
 * sending "https://www.paypal.com" to a phishing page, not a newsletter's
 * links. A link through a security gateway is read as the address the
 * gateway goes on to, where the gateway's link holds it (see unwrapLink).
 * @param {{host: string, text: string|null, url?: string}} link
 * @param {object} [options]
 * @param {string} [options.from] - the sender's domain
 * @returns {boolean}
 */
export function isDeceptiveLink(link, {from} = {}) {
	if (!link.text) {
		return false;
	}

	let shownUrl;
	try {
		shownUrl = new URL(/^https?:\/\//i.test(link.text) ? link.text : `http://${link.text}`);
	} catch {
		return false;
	}

	// (through a security gateway, the address it goes on to)
	const target = typeof link.url === 'string' ? unwrapLink(link.url) : null;
	const host = target ? target.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[(.*)]$/, '$1') : (typeof link.host === 'string' ? link.host : '');
	const shownHost = shownUrl.hostname.toLowerCase();
	const shown = registrableDomain(shownHost);
	if (!shownHost.includes('.') || shown === registrableDomain(host)) {
		return false;
	}

	if (!isClickTracker(target ?? {hostname: host, pathname: ''})) {
		return true;
	}

	const brand = parseDomain(shown).domainWithoutSuffix;
	const sender = parseDomain(from ?? '').domainWithoutSuffix ?? '';
	const path = `${shownUrl.pathname}${shownUrl.search}`;
	return typeof from === 'string'
		&& /^https?:\/\//i.test(link.text)
		&& BRAND_NAMES.has(brand) && !LINKED_BRANDS.has(brand)
		&& (path === '/' || signInPath(path))
		&& registrableDomain(from) !== shown && sender !== brand
		&& !SENDING_DOMAINS.get(brand)?.includes(registrableDomain(from));
}

function addressDomain(address) {
	const at = address.lastIndexOf('@');
	return at === -1 ? '' : trimEndOf(address.slice(at + 1).toLowerCase(), '> \t\r\n\f\v');
}

function firstAddress(field) {
	return field?.value?.find(entry => entry.address) || null;
}

// An email address and its domain, in a display name or any text.
export const ADDRESS_SOURCE = String.raw`[\p{L}\p{N}._%+-]{1,64}@([\p{L}\p{N}-]{1,63}(?:\.[\p{L}\p{N}-]{1,63}){1,10})`;
export const NAMED_ADDRESS = linear(ADDRESS_SOURCE, 'u');

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
	let body = foldToAscii(text);
	const patterns = [
		['url', URL_PATTERN],
		['email', EMAIL_PATTERN],
		['ip', IP_PATTERN],
		['btc', BITCOIN_PATTERN],
		['card', CARD_PATTERN],
		['phone', PHONE_PATTERN],
	];
	for (const [name, pattern] of patterns) {
		// (each match replaced by a space, found with matchesOf: re2 calls a
		//  replacement function in time growing with the square of the length
		//  of text outside ASCII)
		let count = 0;
		let out = '';
		let from = 0;
		for (const match of matchesOf(pattern, body)) {
			out += `${body.slice(from, match.index)} `;
			from = match.index + match[0].length;
			count++;
		}

		body = out + body.slice(from);
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

function addLinkFeatures(links, from, add) {
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

		// "https://paypal.com@evil.example/" shows one name and goes elsewhere
		// (read before the address was cut: see extractLinks).
		if (link.userinfo) {
			add('url:userinfo');
		}

		if (isDeceptiveLink(link, {from})) {
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
	const named = name.match(NAMED_ADDRESS);
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

// Whether a message has HTML and no plain text of its own (mailparser makes
// text from HTML when a message has no text part, so the Content-Type tells
// whether the sender wrote any plain text)
function isHtmlOnly(mail) {
	const contentType = mail.headers?.get?.('content-type');
	return !(typeof mail.text === 'string' && mail.text) || (contentType?.value ?? contentType) === 'text/html';
}

// HTML showing fewer words than this is read with its plain text part
const MIN_SHOWN_WORDS = 20;

// Words of text for comparing two parts: letters and digits, folded, the
// first 2000 at most
const PART_WORD = /[\p{L}\p{N}]{2,}/gu;
function partWords(text) {
	const words = new Set();
	for (const [word] of matchesOf(PART_WORD, normalizeText(text.slice(0, 50_000)).text)) {
		words.add(word);
		if (words.size >= 2000) {
			break;
		}
	}

	return words;
}

//
// Features of what the HTML hides, and of a plain text part that says
// something else than the HTML beside it (as a harmless text part beside
// spam does): `html:hidden_text`, and `html:text_mismatch` when the two
// parts, each of 20 different words or more, share fewer than a fifth of the
// smaller one's words
//
function addPartFeatures({visible, text, plain, alternative}, add) {
	if (visible.hidden > 0) {
		add('html:hidden_text');
		add(`html:hidden_text:${bucket(visible.hidden, [1, 50, 500])}`);
	}

	if (!alternative) {
		return;
	}

	const shown = partWords(text);
	const other = partWords(plain);
	if (shown.size < MIN_SHOWN_WORDS || other.size < MIN_SHOWN_WORDS) {
		return;
	}

	let shared = 0;
	for (const word of other) {
		if (shown.has(word)) {
			shared++;
		}
	}

	if (shared < Math.min(shown.size, other.size) / 5) {
		add('html:text_mismatch');
	}
}

function addHtmlFeatures(mail, html, words, add) {
	if (!html) {
		return;
	}

	add(isHtmlOnly(mail) ? 'html:only' : 'html:alternative');
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

	const images = (html.match(IMG) || []).length;
	if (images > 0) {
		add(`html:img:${bucket(images, [1, 5, 20])}`);
		if (words.length < 20) {
			add('html:img_little_text');
		}
	}

	if (IMG_PIXEL.test(html)) {
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
 * Every word of the text a mail client shows (see `visibleText`) is a
 * feature, every pair of neighbouring words is another, and the subject's
 * words are features of their own ("s:free").
 * The rest describe structure: link domains and tricks, the sender's domain,
 * HTML forms and hidden text, attachment types, headers, language and script,
 * and obfuscation. The same message always gives the same features.
 *
 * @param {object} mail - parsed message (text, html, subject, from, headers, attachments)
 * @param {object} [options]
 * @param {number} [options.maxLength] - characters of body text to read
 * @param {number} [options.maxBigrams] - word pairs to emit
 * @returns {{features: string[], words: string[], language: string|null, script: string|null, links: Array, hosts: string[], text: string, hidden: number}}
 */
export function getFeatures(mail = {}, options = {}) {
	const {maxLength = 100_000, maxBigrams = 3000} = options;
	const features = new Set();
	const add = feature => features.add(feature);

	const html = typeof mail.html === 'string' ? mail.html.slice(0, maxLength * 2) : '';
	const plain = typeof mail.text === 'string' ? mail.text.slice(0, maxLength) : '';
	// The words are those a mail client shows: of the HTML when there is any
	// (a plain text part beside it is shown only where HTML cannot be, so a
	// harmless one cannot speak for spam in the HTML, nor can text the HTML
	// hides), else of the plain text.  Links are read from both parts and
	// from hidden text too; host names written without a link from the
	// subject, the text read and a plain text part beside the HTML.
	const visible = html ? visibleText(html) : {text: plain, hidden: 0};
	const alternative = Boolean(html && plain && !isHtmlOnly(mail));
	let text = visible.text.slice(0, maxLength);
	// (but HTML that shows little text, such as an image of the message, is
	// read with its plain text part, which says what the image does)
	// (counted as words are, also in scripts written without spaces)
	if (alternative && segmentWords(text.slice(0, 4000)).words.length < MIN_SHOWN_WORDS) {
		text = `${text}\n${plain}`.slice(0, maxLength);
	}

	const subject = typeof mail.subject === 'string' ? mail.subject : '';
	const links = extractLinks(html ? `${plain}\n${text}` : text, html);
	const hosts = extractHosts(`${subject}\n${text}${alternative ? `\n${plain}` : ''}`, new Set(links.map(link => link.host)));
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
	addLinkFeatures(links, addressDomain(firstAddress(mail.from)?.address ?? ''), add);
	addSenderFeatures(mail, add);
	addHtmlFeatures(mail, html, segmented.words, add);
	addPartFeatures({
		visible, text, plain, alternative,
	}, add);
	addAttachmentFeatures(mail, add);
	addHeaderFeatures(mail, add);

	return {
		features: [...features],
		words: segmented.words,
		language: detected.language,
		script: detected.script,
		links,
		hosts,
		// (the text shown, as read for the words, and how many characters of
		//  text the HTML hides)
		text,
		hidden: visible.hidden,
	};
}
