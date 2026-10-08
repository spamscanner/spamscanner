import {franc} from 'franc';

// Writing systems Spam Scanner recognises, checked in this order. A letter
// belongs to the first script whose pattern matches it.
const SCRIPTS = [
	['Latin', /\p{Script=Latin}/u],
	['Cyrillic', /\p{Script=Cyrillic}/u],
	['Greek', /\p{Script=Greek}/u],
	['Han', /\p{Script=Han}/u],
	['Hiragana', /\p{Script=Hiragana}/u],
	['Katakana', /\p{Script=Katakana}/u],
	['Hangul', /\p{Script=Hangul}/u],
	['Arabic', /\p{Script=Arabic}/u],
	['Hebrew', /\p{Script=Hebrew}/u],
	['Thai', /\p{Script=Thai}/u],
	['Devanagari', /\p{Script=Devanagari}/u],
	['Bengali', /\p{Script=Bengali}/u],
	['Tamil', /\p{Script=Tamil}/u],
	['Telugu', /\p{Script=Telugu}/u],
	['Gujarati', /\p{Script=Gujarati}/u],
	['Gurmukhi', /\p{Script=Gurmukhi}/u],
	['Kannada', /\p{Script=Kannada}/u],
	['Malayalam', /\p{Script=Malayalam}/u],
	['Armenian', /\p{Script=Armenian}/u],
	['Georgian', /\p{Script=Georgian}/u],
	['Ethiopic', /\p{Script=Ethiopic}/u],
	['Khmer', /\p{Script=Khmer}/u],
	['Lao', /\p{Script=Lao}/u],
	['Myanmar', /\p{Script=Myanmar}/u],
	['Sinhala', /\p{Script=Sinhala}/u],
];

// Scripts used by a single major language: no statistical detection needed.
const SCRIPT_LANGUAGE = {
	Hangul: 'ko',
	Hebrew: 'he',
	Thai: 'th',
	Greek: 'el',
	Bengali: 'bn',
	Tamil: 'ta',
	Telugu: 'te',
	Gujarati: 'gu',
	Gurmukhi: 'pa',
	Kannada: 'kn',
	Malayalam: 'ml',
	Armenian: 'hy',
	Georgian: 'ka',
	Khmer: 'km',
	Lao: 'lo',
	Myanmar: 'my',
	Sinhala: 'si',
	Hiragana: 'ja',
	Katakana: 'ja',
};

// ISO 639-3 (what franc returns) to ISO 639-1, for the languages franc detects
// that have a two-letter code.
const ISO6393_TO_1 = {
	afr: 'af', aka: 'ak', amh: 'am', arb: 'ar', ara: 'ar', azj: 'az', azb: 'az', aze: 'az', bel: 'be', ben: 'bn', bos: 'bs', bul: 'bg', cat: 'ca', ceb: 'ceb', ces: 'cs', ckb: 'ku', cmn: 'zh', zho: 'zh', cym: 'cy', dan: 'da', deu: 'de', ell: 'el', eng: 'en', epo: 'eo', est: 'et', ekk: 'et', eus: 'eu', fin: 'fi', fra: 'fr', fuv: 'ff', gax: 'om', gle: 'ga', glg: 'gl', guj: 'gu', hat: 'ht', hau: 'ha', heb: 'he', hin: 'hi', hrv: 'hr', hun: 'hu', hye: 'hy', ibo: 'ig', ilo: 'ilo', ind: 'id', isl: 'is', ita: 'it', jav: 'jv', jpn: 'ja', kan: 'kn', kat: 'ka', kaz: 'kk', khm: 'km', kin: 'rw', kir: 'ky', kor: 'ko', lao: 'lo', lat: 'la', lit: 'lt', lvs: 'lv', lav: 'lv', mal: 'ml', mar: 'mr', mkd: 'mk', mlt: 'mt', mya: 'my', nep: 'ne', npi: 'ne', nld: 'nl', nno: 'nn', nob: 'nb', nor: 'no', nya: 'ny', ori: 'or', ory: 'or', pan: 'pa', pes: 'fa', fas: 'fa', pbu: 'ps', pol: 'pl', por: 'pt', ron: 'ro', run: 'rn', rus: 'ru', sin: 'si', slk: 'sk', slv: 'sl', sna: 'sn', som: 'so', spa: 'es', sqi: 'sq', als: 'sq', srp: 'sr', sun: 'su', swe: 'sv', swh: 'sw', swa: 'sw', tam: 'ta', tel: 'te', tgk: 'tg', tgl: 'tl', tha: 'th', tir: 'ti', tuk: 'tk', tur: 'tr', uig: 'ug', ukr: 'uk', urd: 'ur', uzn: 'uz', uzb: 'uz', vie: 'vi', xho: 'xh', yor: 'yo', zlm: 'ms', zsm: 'ms', msa: 'ms', zul: 'zu',
};

// Languages franc may answer with: those with tens of millions of speakers or
// an official national role. Without a list, franc picks rare relatives
// (Scots for English, for example) on short texts.
const FRANC_LANGUAGES = [
	'eng', 'spa', 'fra', 'deu', 'ita', 'por', 'nld', 'pol', 'ces', 'slk', 'slv', 'hrv', 'srp', 'bos', 'bul', 'mkd', 'rus', 'ukr', 'bel', 'ron', 'hun', 'fin', 'ekk', 'lvs', 'lit', 'swe', 'nob', 'dan', 'isl', 'tur', 'azj', 'kaz', 'uzn', 'kir', 'tgk', 'ind', 'zlm', 'vie', 'tgl', 'ceb', 'swh', 'hau', 'yor', 'ibo', 'amh', 'som', 'afr', 'zul', 'xho', 'cat', 'eus', 'gle', 'cym', 'als', 'arb', 'pes', 'urd', 'pbu', 'ckb', 'hin', 'mar', 'nep', 'jav', 'sun', 'mlt', 'run', 'kin', 'nya', 'sna', 'tir', 'gax', 'mlg', 'hat',
];

const LETTER = /\p{L}/u;

/**
 * Count letters per script in the first `limit` characters of a string.
 * @param {string} text
 * @param {number} [limit]
 * @returns {Map<string, number>} script name to letter count, most frequent first
 */
export function countScripts(text, limit = 4000) {
	const counts = new Map();
	let seen = 0;
	for (const char of text) {
		if (seen++ >= limit) {
			break;
		}

		if (!LETTER.test(char)) {
			continue;
		}

		const entry = SCRIPTS.find(([, pattern]) => pattern.test(char));
		const name = entry ? entry[0] : 'Other';
		counts.set(name, (counts.get(name) || 0) + 1);
	}

	return new Map([...counts].sort((a, b) => b[1] - a[1]));
}

/**
 * The script a single letter belongs to, or "Other".
 * @param {string} char
 * @returns {string}
 */
export function scriptOf(char) {
	const entry = SCRIPTS.find(([, pattern]) => pattern.test(char));
	return entry ? entry[0] : 'Other';
}

/**
 * Normalize a language code to ISO 639-1 where one exists: "eng" and "en-US"
 * both become "en". Unknown three-letter codes are returned lowercased.
 * @param {string} code
 * @returns {string|null}
 */
export function normalizeLanguageCode(code) {
	if (typeof code !== 'string' || code.trim() === '') {
		return null;
	}

	const lower = code.trim().toLowerCase().replace('_', '-');
	const base = lower.split('-')[0];
	if (base.length === 3 && ISO6393_TO_1[base]) {
		return ISO6393_TO_1[base];
	}

	return base;
}

// Letters that belong to one Cyrillic alphabet. Trigram statistics confuse
// Russian with Bulgarian on short texts; these letters do not.
function cyrillicLanguage(text) {
	if (/ў/i.test(text)) {
		return 'be';
	}

	if (/[іїєґ]/i.test(text)) {
		return 'uk';
	}

	if (/[ђћџ]/i.test(text)) {
		return 'sr';
	}

	if (/[ѓќѕ]/i.test(text)) {
		return 'mk';
	}

	if (/[ыэё]/i.test(text)) {
		return 'ru';
	}

	return null;
}

/**
 * Detect the language of a text.
 *
 * Scripts used by one language (Korean, Thai, Greek, Hebrew, Japanese kana and
 * others) decide directly. Otherwise franc's trigram model decides when there
 * is enough text; short texts fall back to the script alone.
 *
 * @param {string} text
 * @returns {{language: string|null, script: string|null, scripts: string[], confidence: number}}
 */
export function detectLanguage(text) {
	const result = {
		language: null, script: null, scripts: [], confidence: 0,
	};
	if (typeof text !== 'string' || text.trim() === '') {
		return result;
	}

	const sample = text.slice(0, 20_000);
	const counts = countScripts(sample);
	const total = [...counts.values()].reduce((sum, n) => sum + n, 0);
	if (total === 0) {
		return result;
	}

	const [[script, count]] = counts;
	result.script = script;
	result.scripts = [...counts.keys()].filter(name => counts.get(name) / total >= 0.1);
	result.confidence = count / total;

	// Japanese mixes Han with kana: any meaningful kana means Japanese.
	const kana = (counts.get('Hiragana') || 0) + (counts.get('Katakana') || 0);
	if (kana / total >= 0.05) {
		result.language = 'ja';
		return result;
	}

	if (SCRIPT_LANGUAGE[script]) {
		result.language = SCRIPT_LANGUAGE[script];
		return result;
	}

	if (script === 'Han') {
		result.language = 'zh';
		return result;
	}

	if (script === 'Cyrillic') {
		const cyrillic = cyrillicLanguage(sample);
		if (cyrillic) {
			result.language = cyrillic;
			return result;
		}
	}

	// Latin and Cyrillic alphabets are shared by many languages and need more
	// text to tell apart than scripts such as Devanagari or Arabic.
	if (total >= (script === 'Latin' || script === 'Cyrillic' ? 40 : 15)) {
		const code = franc(sample, {minLength: 20, only: FRANC_LANGUAGES});
		if (code !== 'und') {
			result.language = normalizeLanguageCode(code);
			return result;
		}
	}

	// Too short to tell languages of the same script apart.
	result.confidence = 0;
	return result;
}
