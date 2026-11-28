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
	afr: 'af', aka: 'ak', amh: 'am', arb: 'ar', ara: 'ar', azj: 'az', azb: 'az', aze: 'az', bel: 'be', ben: 'bn', bos: 'bs', bul: 'bg', cat: 'ca', ceb: 'ceb', ces: 'cs', ckb: 'ku', khk: 'mn', mlg: 'mg', plt: 'mg', cmn: 'zh', zho: 'zh', cym: 'cy', dan: 'da', deu: 'de', ell: 'el', eng: 'en', epo: 'eo', est: 'et', ekk: 'et', eus: 'eu', fin: 'fi', fra: 'fr', fuv: 'ff', gax: 'om', gle: 'ga', glg: 'gl', guj: 'gu', hat: 'ht', hau: 'ha', heb: 'he', hin: 'hi', hrv: 'hr', hun: 'hu', hye: 'hy', ibo: 'ig', ilo: 'ilo', ind: 'id', isl: 'is', ita: 'it', jav: 'jv', jpn: 'ja', kan: 'kn', kat: 'ka', kaz: 'kk', khm: 'km', kin: 'rw', kir: 'ky', kor: 'ko', lao: 'lo', lat: 'la', lit: 'lt', lvs: 'lv', lav: 'lv', mal: 'ml', mar: 'mr', mkd: 'mk', mlt: 'mt', mya: 'my', nep: 'ne', npi: 'ne', nld: 'nl', nno: 'nn', nob: 'nb', nor: 'no', nya: 'ny', ori: 'or', ory: 'or', pan: 'pa', pes: 'fa', fas: 'fa', pbu: 'ps', pol: 'pl', por: 'pt', ron: 'ro', run: 'rn', rus: 'ru', sin: 'si', slk: 'sk', slv: 'sl', sna: 'sn', som: 'so', spa: 'es', sqi: 'sq', als: 'sq', srp: 'sr', sun: 'su', swe: 'sv', swh: 'sw', swa: 'sw', tam: 'ta', tel: 'te', tgk: 'tg', tgl: 'tl', tha: 'th', tir: 'ti', tuk: 'tk', tur: 'tr', uig: 'ug', ukr: 'uk', urd: 'ur', uzn: 'uz', uzb: 'uz', vie: 'vi', xho: 'xh', yor: 'yo', zlm: 'ms', zsm: 'ms', msa: 'ms', zul: 'zu',
};

// Languages franc may answer with: those with tens of millions of speakers or
// an official national role. Without a list, franc picks rare relatives
// (Scots for English, for example) on short texts.
const FRANC_LANGUAGES = [
	'eng', 'spa', 'fra', 'deu', 'ita', 'por', 'nld', 'pol', 'ces', 'slk', 'slv', 'hrv', 'srp', 'bos', 'bul', 'mkd', 'rus', 'ukr', 'bel', 'ron', 'hun', 'fin', 'ekk', 'lvs', 'lit', 'swe', 'nob', 'dan', 'isl', 'tur', 'azj', 'kaz', 'uzn', 'kir', 'tgk', 'ind', 'zlm', 'vie', 'tgl', 'ceb', 'swh', 'hau', 'yor', 'ibo', 'amh', 'som', 'afr', 'zul', 'xho', 'cat', 'eus', 'gle', 'cym', 'als', 'arb', 'pes', 'urd', 'pbu', 'ckb', 'hin', 'mar', 'nep', 'jav', 'sun', 'mlt', 'run', 'kin', 'nya', 'sna', 'tir', 'gax', 'plt', 'hat', 'khk',
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

// Codes for the same language as one the detector answers with: Norwegian
// ("no", "nor") is written as Bokmål ("nb") almost always, Filipino as
// Tagalog, and "iw", "in" and "ji" are the codes Hebrew, Indonesian and
// Yiddish had before 1989, which Java and old systems still use.
const SAME_LANGUAGE = {
	no: 'nb', nor: 'nb', fil: 'tl', iw: 'he', in: 'id', ji: 'yi', yid: 'yi',
};

/**
 * Normalize a language code to ISO 639-1 where one exists: "eng" and "en-US"
 * both become "en", and a code of the same language as one detected becomes
 * that one ("no" is "nb", "fil" "tl", "iw" "he", "in" "id", "ji" "yi").
 * Unknown three-letter codes are returned lowercased.
 * @param {string} code
 * @returns {string|null}
 */
export function normalizeLanguageCode(code) {
	if (typeof code !== 'string' || code.trim() === '') {
		return null;
	}

	const lower = code.trim().toLowerCase().replace('_', '-');
	const base = lower.split('-')[0];
	if (Object.hasOwn(SAME_LANGUAGE, base)) {
		return SAME_LANGUAGE[base];
	}

	if (base.length === 3 && ISO6393_TO_1[base]) {
		return ISO6393_TO_1[base];
	}

	return base;
}

// Letters of Cyrillic alphabets of Turkic, Iranian and Mongolic languages
// (Kazakh, Uzbek, Kyrgyz, Tajik, Tatar, Bashkir, Mongolian), not Slavic ones
const NON_SLAVIC_CYRILLIC = /[әөүұқғңһҳҷӣӯҗҡҙҫ]/i;

// Letters that belong to one Cyrillic alphabet. Trigram statistics confuse
// Russian with Bulgarian on short texts; these letters do not. Not in text
// with letters of Kazakh, Uzbek, Kyrgyz, Mongolian and others (see
// NON_SLAVIC_CYRILLIC), whose alphabets have "і" (Kazakh), "ў"
// (Uzbek) or "ы" and "э" (Kyrgyz, Mongolian) too: franc tells those.
function cyrillicLanguage(text) {
	if (NON_SLAVIC_CYRILLIC.test(text)) {
		return null;
	}

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

// Slavic languages franc may name for Cyrillic text (Bosnian for Serbian)
const SLAVIC = new Set(['ru', 'uk', 'be', 'bg', 'mk', 'sr', 'bs']);

// Words with letters of a Turkic, Iranian or Mongolic alphabet, or with "і",
// which Kazakh has as well as Ukrainian and Belarusian
const NON_SLAVIC_WORD = /[әөүұқғңһҳҷӣӯҗҡҙҫі]/i;

// The words of a text but for names, words in title case other than at the
// start of a sentence or a line: the letters of a name ("Рыскулов",
// "Қарағанды") belong to the language of the person or place, not to that of
// the text; a word in capitals is no name ("ВАША ПОСЫЛКА ЗАДЕРЖАНА"). (Split
// at non-letters, not matched word by word, to stay linear on one long
// word.)
function words(text) {
	const kept = [];
	let sentence = true;
	for (const [index, part] of text.split(/([^\p{L}\p{M}]+)/u).entries()) {
		if (index % 2 === 1) {
			sentence = /[.!?…\n]/u.test(part);
		} else if (sentence || !/^\p{Lu}[\p{Ll}\p{M}]/u.test(part)) {
			kept.push(part);
		}
	}

	return kept;
}

// The language of Cyrillic text with letters of Kazakh, Uzbek and others,
// which franc reads as Slavic: a Russian, Bulgarian or Ukrainian text that
// names a Kazakh person or place, or has a Kazakh word or two. Its other
// words, but for names, decide as in a Slavic text ("ы" is Russian, never
// Bulgarian), else franc's answer stands.
function slavicLanguage(text, code) {
	return cyrillicLanguage(words(text).filter(word => !NON_SLAVIC_WORD.test(word)).join(' ')) || code;
}

// English that franc reads as another language of Latin letters: the names
// of products, prices and the links of a shop's mail hold few of the letter
// sequences franc tells English by ("Samsung 65\" Class 4K Smart TV. Free
// shipping. Price Match Guarantee."), and it answers French, Danish or
// Catalan. The words English text is held together by, and those its shops
// write, tell: none of them is a word of another language of Latin letters
// ("has" is Spanish, "all" Swedish, "see" German, "into" Finnish), so three
// of them, at least three in a hundred words, and more than the words that
// hold the language franc answered together (in small letters, as "ET" and
// "EST" are no French) and the words with letters English has none of ("ä",
// "ç", "ñ"), are a text in English. A text of two languages stays the one it
// has more of.
const ENGLISH_WORDS = new Set('the and you your with this that from our they their these those which would should could about what when where why how who there please because have are not were more but if she his its did does being them such very get buy save free new now here only each every while through other before after may out up off today shipping terms rights reserved learn apply available price prices deals items click'.split(' '));
const FUNCTION_WORDS = Object.fromEntries(Object.entries({
	fr: 'le la les des une un du pour vous votre vos nous notre que qui dans sur pas avec au aux ce cette ne se sont mais ou par et est être à',
	es: 'el la los las de del que en un una por para con se su sus es al lo como más pero y este esta le nos ha muy',
	pt: 'de que não o os um uma para em da dos das na nas nos por se mais ao como você seu sua é ou mas foi',
	it: 'il lo la gli le di del della dei delle da con tra che un una uno è sono ma se più questo questa al alla nel nella ha',
	de: 'der das und ist nicht ein eine zu den mit sich auf für von dem sie ich wir ihr ihre ihnen auch oder wird werden bei nach aus wenn dass sind einen einer des im zum zur',
	nl: 'de het een en van dat niet op te zijn voor als aan maar ook uw naar bij deze dit nog wel geen wij jij worden wordt heeft',
	da: 'og det er jeg ikke en til på med af har den de som du vi kan vil fra eller også din dit et',
	nb: 'og det er jeg ikke en til på med av har den de som du vi kan vil fra eller også din ditt et å',
	sv: 'och det är jag inte en till på med av har den de som du vi kan vill från eller också din ditt ett att för',
	fi: 'ja ei että se oli tai kun niin myös mutta ole hän olen sinä ovat tämä joka sekä kuin jos',
	pl: 'na nie się że jest za jak ale od dla czy lub oraz tak przez przy są tym tego jej ich',
	cs: 'se na je že ale jako za tak jsou nebo jsem podle od být ve tento tato které',
	hu: 'az és hogy nem egy ez csak már vagy még mint volt lesz ami aki ezt azt nagyon',
	ro: 'de și în la cu pe nu că un este se din pentru mai sau dar fost sunt prin către',
	tr: 've bir bu için ile de da gibi çok daha kadar ama veya olarak ben sen biz siz değil yok mı',
	vi: 'và của là có cho không được này các một những với trong đã để người khi tôi bạn',
	id: 'yang dan di untuk dengan ini itu dari tidak ke pada akan juga atau saya kami anda adalah oleh sudah bisa dalam',
	ca: 'el la els les de del que en un una amb és al més però aquest aquesta',
	af: 'van het nie wat vir op sy hy ek jy ons hulle dat',
}).map(([language, words]) => [language, new Set(words.split(' '))]));
// (the languages written much as another is: Malay as Indonesian, Slovak as
//  Czech)
const WRITTEN_AS = {ms: 'id', sk: 'cs'};
// (a word with the letters after an apostrophe in it: "you've" has no "ve",
//  the Turkish and Czech word)
const LATIN_WORD = /\p{Script=Latin}(?:[\p{Script=Latin}\p{M}]|['’](?=\p{Script=Latin}))*/gu;
const NOT_ENGLISH_LETTER = /[^a-z'’]/i;

function isEnglish(sample, language) {
	const own = FUNCTION_WORDS[WRITTEN_AS[language] ?? language];
	let words = 0;
	let english = 0;
	let others = 0;
	for (const [word] of sample.matchAll(LATIN_WORD)) {
		words++;
		if (ENGLISH_WORDS.has(word.toLowerCase())) {
			english++;
		} else if (own?.has(word) || NOT_ENGLISH_LETTER.test(word)) {
			others++;
		}
	}

	return english >= 3 && english >= 0.03 * words && english > others;
}

/**
 * Detect the language of a text.
 *
 * Scripts used by one language (Korean, Thai, Greek, Hebrew, Japanese kana and
 * others) decide directly. Otherwise franc's trigram model decides when there
 * is enough text, but for English it reads as another language of Latin
 * letters, which the words of English tell; short texts fall back to the
 * script alone.
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

	// (by the letters of words other than names; by those of names too only
	//  in a text too short for franc, which otherwise tells: a Bulgarian text
	//  that names "господин Рыскулов")
	if (script === 'Cyrillic') {
		const cyrillic = cyrillicLanguage(words(sample).join(' ')) ?? (total < 40 ? cyrillicLanguage(sample) : null);
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
			const language = normalizeLanguageCode(code);
			// (Cyrillic text with letters of Kazakh and others, which
			//  cyrillicLanguage leaves to franc, and franc reads as Slavic)
			if (script === 'Cyrillic' && SLAVIC.has(language) && NON_SLAVIC_CYRILLIC.test(sample)) {
				result.language = slavicLanguage(sample, language);
			} else {
				// (English that franc reads as another language of Latin letters)
				result.language = script === 'Latin' && language !== 'en' && isEnglish(sample, language) ? 'en' : language;
			}

			return result;
		}
	}

	// Too short to tell languages of the same script apart.
	result.confidence = 0;
	return result;
}
