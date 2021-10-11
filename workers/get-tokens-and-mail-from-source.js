const fs = require('fs');
const { parentPort, workerData, isMainThread } = require('worker_threads');
const { promisify } = require('util');

const RE2 = require('re2');
const bitcoinRegex = require('bitcoin-regex');
const contractions = require('expand-contractions');
const creditCardRegex = require('credit-card-regex');
const debug = require('debug')('spamscanner:worker:get-tokens-and-mail');
const emailRegexSafe = require('email-regex-safe');
const emojiPatterns = require('emoji-patterns');
const escapeStringRegexp = require('escape-string-regexp');
const floatingPointRegex = require('floating-point-regex');
const franc = require('franc');
const getSymbolFromCurrency = require('currency-symbol-map');
const hasha = require('hasha');
const hexaColorRegex = require('hexa-color-regex');
const isBuffer = require('is-buffer');
const isSANB = require('is-string-and-not-blank');
const isValidPath = require('is-valid-path');
const macRegex = require('mac-regex');
const natural = require('natural');
const phoneRegex = require('phone-regex');
const sanitizeHtml = require('sanitize-html');
const snowball = require('node-snowball');
const striptags = require('striptags');
const sw = require('stopword');
const toEmoji = require('gemoji/name-to-emoji');
const urlRegexSafe = require('url-regex-safe');
const { Iconv } = require('iconv');
const { codes } = require('currency-codes');
const { parse } = require('node-html-parser');
const { simpleParser } = require('mailparser');

const ISO_CODE_MAPPING = require('../iso-code-mapping.json');
const { locales } = require('../helpers');

const aggressiveTokenizer = new natural.AggressiveTokenizer();
const orthographyTokenizer = new natural.OrthographyTokenizer({
  language: 'fi'
});
const aggressiveTokenizerFa = new natural.AggressiveTokenizerFa();
const aggressiveTokenizerFr = new natural.AggressiveTokenizerFr();
const aggressiveTokenizerId = new natural.AggressiveTokenizerId();
const aggressiveTokenizerIt = new natural.AggressiveTokenizerIt();
const tokenizerJa = new natural.TokenizerJa();
const aggressiveTokenizerNo = new natural.AggressiveTokenizerNo();
const aggressiveTokenizerPl = new natural.AggressiveTokenizerPl();
const aggressiveTokenizerPt = new natural.AggressiveTokenizerPt();
const aggressiveTokenizerEs = new natural.AggressiveTokenizerEs();
const aggressiveTokenizerSv = new natural.AggressiveTokenizerSv();
const aggressiveTokenizerRu = new natural.AggressiveTokenizerRu();
const aggressiveTokenizerVi = new natural.AggressiveTokenizerVi();

const stopwordsEn = require('natural/lib/natural/util/stopwords').words;
const stopwordsEs = require('natural/lib/natural/util/stopwords_es').words;
const stopwordsFa = require('natural/lib/natural/util/stopwords_fa').words;
const stopwordsFr = require('natural/lib/natural/util/stopwords_fr').words;
const stopwordsId = require('natural/lib/natural/util/stopwords_id').words;
const stopwordsJa = require('natural/lib/natural/util/stopwords_ja').words;
const stopwordsIt = require('natural/lib/natural/util/stopwords_it').words;
const stopwordsNl = require('natural/lib/natural/util/stopwords_nl').words;
const stopwordsNo = require('natural/lib/natural/util/stopwords_no').words;
const stopwordsPl = require('natural/lib/natural/util/stopwords_pl').words;
const stopwordsPt = require('natural/lib/natural/util/stopwords_pt').words;
const stopwordsRu = require('natural/lib/natural/util/stopwords_ru').words;
const stopwordsSv = require('natural/lib/natural/util/stopwords_sv').words;
const stopwordsZh = require('natural/lib/natural/util/stopwords_zh').words;

const readFile = promisify(fs.readFile);

const MAIL_PHISHING_PROPS = ['subject', 'from', 'to', 'cc', 'bcc', 'text'];
const TOKEN_HEADERS = [...MAIL_PHISHING_PROPS, 'html'];

// <https://github.com/mathiasbynens/emoji-regex/issues/59#issuecomment-640418649>
const EMOJI_REGEX = new RE2(emojiPatterns.Emoji_All, 'gu');
const FLOATING_POINT_REGEX = new RE2(floatingPointRegex());
const CC_REGEX = new RE2(creditCardRegex());
const PHONE_REGEX = new RE2(phoneRegex());
const BITCOIN_REGEX = new RE2(bitcoinRegex());
const MAC_REGEX = new RE2(macRegex());
const HEXA_COLOR_REGEX = new RE2(hexaColorRegex());

// <https://github.com/yoshuawuyts/newline-remove>
const NEWLINE_REGEX = new RE2(/\r\n|\n|\r/gm);
// <https://stackoverflow.com/a/5917217>
const NUMBER_REGEX = new RE2(/\d[\d,.]*/g);

// NOTE: we use my package url-safe-regex instead
// of url-regex due to CVE advisory among other issues
// https://github.com/niftylettuce/url-regex-safe
const URL_REGEX = urlRegexSafe();

// NOTE: we use my package email-safe-regex instead
// of email-regex due to several issues
// https://github.com/niftylettuce/email-regex-safe
const EMAIL_REGEX = emailRegexSafe();

// <https://superuser.com/a/1182181>
const INITIALISM_REGEX = new RE2(/\b(?:[A-Z][a-z]*){2,}/g);
// <https://stackoverflow.com/q/35076016>
const ABBREVIATION_REGEX = new RE2(/\b(?:[a-zA-Z]\.){2,}/g);

const currencySymbols = [];
for (const code of codes()) {
  const symbol = getSymbolFromCurrency(code);
  if (
    typeof symbol === 'string' &&
    !currencySymbols.includes(symbol) &&
    !new RE2(/^[a-z]+$/i).test(symbol)
  )
    currencySymbols.push(escapeStringRegexp(symbol));
}

const CURRENCY_REGEX = new RE2(new RegExp(currencySymbols.join('|'), 'g'));

let config;
if (!isMainThread) {
  config = workerData.config;
}

function parseLocale(locale) {
  // convert `franc` locales here to their locale iso2 normalized name
  return locale.toLowerCase().split('-')[0].split('_')[0];
}

// <https://medium.com/analytics-vidhya/building-a-spam-filter-from-scratch-using-machine-learning-fc58b178ea56>
// <https://towardsdatascience.com/empirical-analysis-on-email-classification-using-the-enron-dataset-19054d558697>
// <https://blog.logrocket.com/natural-language-processing-for-node-js/>
// <https://github.com/NaturalNode/natural#stemmers>
// eslint-disable-next-line complexity
async function getTokens(string, locale, isHTML = false, c = null) {
  // c is to be able to pass config in tests
  if (c && isMainThread) {
    config = c;
  }

  // get the current email replacement regex
  const EMAIL_REPLACEMENT_REGEX = new RE2(config.replacements.email, 'g');

  //
  // parse HTML for <html> tag with lang attr
  // otherwise if that wasn't found then look for this
  // <meta http-equiv="Content-Language" content="en-us">
  //
  if (!locale && isHTML) {
    const root = parse(string);

    const metas = root.querySelectorAll('meta');

    for (const meta of metas) {
      if (
        meta.getAttribute('http-equiv') === 'Content-Language' &&
        isSANB(meta.getAttribute('content')) &&
        locales.has(parseLocale(meta.getAttribute('content')))
      ) {
        locale = parseLocale(meta.getAttribute('content'));
        break;
      }
    }

    const _metas = root.querySelectorAll('META');

    for (const meta of _metas) {
      if (
        meta.getAttribute('http-equiv') === 'Content-Language' &&
        isSANB(meta.getAttribute('content')) &&
        locales.has(parseLocale(meta.getAttribute('content')))
      ) {
        locale = parseLocale(meta.getAttribute('content'));
        break;
      }
    }

    if (!locale) {
      const html = root.querySelector('html') || root.querySelector('HTML');
      if (
        html &&
        isSANB(html.getAttribute('lang')) &&
        locales.has(parseLocale(html.getAttribute('lang')))
      )
        locale = parseLocale(html.getAttribute('lang'));
    }
  }

  if (isHTML) string = sanitizeHtml(string, config.sanitizeHtml);

  const replacementRegexes = [];
  for (const key of Object.keys(config.replacements)) {
    replacementRegexes.push(escapeStringRegexp(config.replacements[key]));
  }

  const REPLACEMENTS_REGEX = new RE2(
    new RegExp(replacementRegexes.join('|'), 'g')
  );

  string = striptags(string, [], ' ')
    .trim()
    // replace newlines
    .replace(NEWLINE_REGEX, ' ')
    //
    // attackers may try to inject our replacements into the message
    // therefore we should strip all of them before doing any replacements
    //
    .replace(REPLACEMENTS_REGEX, ' ');

  //
  // we should instead use language detection to determine
  // what language/locale this message is in (as opposed to relying on headers)
  // which could get arbitrarily modified by an attacker
  // <https://github.com/wooorm/franc/issues/86> (accurate with min length)
  // <https://github.com/FGRibreau/node-language-detect> (not too accurate)
  //
  const detectedLanguage = franc(string, config.franc);
  if (detectedLanguage !== 'und' && isSANB(ISO_CODE_MAPPING[detectedLanguage]))
    locale = ISO_CODE_MAPPING[detectedLanguage];

  locale = parseLocale(isSANB(locale) ? locale : config.locale);

  if (!locales.has(locale)) {
    debug(`Locale ${locale} was not valid and will use default`);
    locale = parseLocale(config.locale);
  }

  // TODO: add new languages <https://github.com/hthetiot/node-snowball/pull/21/commits/3871acf1f38b00960929545bc8ab5f591f50c024>
  // <https://github.com/hthetiot/node-snowball#supported-language-second-argument>
  // <https://github.com/NaturalNode/natural#tokenizers>
  let tokenizer = aggressiveTokenizer;
  let stopwords = stopwordsEn;
  let language = 'english';
  let stemword = 'default';
  switch (locale) {
    case 'ar':
      language = 'arabic';
      break;
    case 'da':
      language = 'danish';
      break;
    case 'nl':
      stopwords = stopwordsNl;
      language = 'dutch';
      break;
    case 'en':
      language = 'english';
      break;
    case 'fi':
      language = 'finnish';
      tokenizer = orthographyTokenizer;
      break;
    case 'fa':
      language = 'farsi';
      tokenizer = aggressiveTokenizerFa;
      stopwords = stopwordsFa;
      stemword = natural.PorterStemmerFa.stem.bind(natural.PorterStemmerFa);
      break;
    case 'fr':
      language = 'french';
      tokenizer = aggressiveTokenizerFr;
      stopwords = stopwordsFr;
      break;
    case 'de':
      language = 'german';
      break;
    case 'hu':
      language = 'hungarian';
      break;
    case 'in':
      language = 'indonesian';
      tokenizer = aggressiveTokenizerId;
      stopwords = stopwordsId;
      break;
    case 'it':
      language = 'italian';
      tokenizer = aggressiveTokenizerIt;
      stopwords = stopwordsIt;
      break;
    case 'ja':
      tokenizer = tokenizerJa;
      stopwords = stopwordsJa;
      stemword = natural.StemmerJa.stem.bind(natural.StemmerJa);
      break;
    case 'nb':
    case 'nn':
      language = 'norwegian';
      tokenizer = aggressiveTokenizerNo;
      stopwords = stopwordsNo;
      break;
    case 'po':
      language = 'polish';
      tokenizer = aggressiveTokenizerPl;
      stopwords = stopwordsPl;
      stemword = false;
      break;
    case 'pt':
      language = 'portuguese';
      tokenizer = aggressiveTokenizerPt;
      stopwords = stopwordsPt;
      break;
    case 'es':
      language = 'spanish';
      tokenizer = aggressiveTokenizerEs;
      stopwords = stopwordsEs;
      break;
    case 'sv':
      language = 'swedish';
      tokenizer = aggressiveTokenizerSv;
      stopwords = stopwordsSv;
      break;
    case 'ro':
      language = 'romanian';
      break;
    case 'ru':
      language = 'russian';
      tokenizer = aggressiveTokenizerRu;
      stopwords = stopwordsRu;
      break;
    case 'ta':
      language = 'tamil';
      break;
    case 'tr':
      language = 'turkish';
      break;
    case 'vi':
      language = 'vietnamese';
      tokenizer = aggressiveTokenizerVi;
      stemword = false;
      break;
    case 'zh':
      language = 'chinese';
      stopwords = stopwordsZh;
      stemword = false;
      break;
    default:
  }

  if (stemword === 'default') stemword = (t) => snowball.stemword(t, language);

  string =
    // handle emojis
    // - convert github emojis to unicode 13 emojis
    // - replace all unicode emojis
    string
      .split(' ')
      .map((_string) =>
        _string.startsWith(':') &&
        _string.endsWith(':') &&
        typeof toEmoji[_string.slice(1, -1)] === 'string'
          ? toEmoji[_string.slice(1, -1)]
          : _string
      )
      .join(' ')
      .replace(EMOJI_REGEX, ` ${config.replacements.emoji} `)

      // https://github.com/regexhq/mac-regex
      .replace(MAC_REGEX, ` ${config.replacements.mac} `)

      // https://github.com/kevva/credit-card-regex
      .replace(CC_REGEX, ` ${config.replacements.cc} `)

      // https://github.com/kevva/bitcoin-regex
      .replace(BITCOIN_REGEX, ` ${config.replacements.bitcoin} `)

      // https://github.com/regexhq/phone-regex
      .replace(PHONE_REGEX, ` ${config.replacements.phone} `)

      // handle hex colors
      // https://github.com/regexhq/hexa-color-regex
      .replace(HEXA_COLOR_REGEX, ` ${config.replacements.hexa} `)

      // handle initialism(e.g. "AFK" -> "abbrev$crypto$afk")
      .replace(
        INITIALISM_REGEX,
        (s) => ` ${config.replacements.initialism}${s} `
      )

      // handle abbreviations (e.g. "u.s." -> "abbrev$crypto$us")
      // (note we have to replace the periods here)
      .replace(
        ABBREVIATION_REGEX,
        (s) => ` ${config.replacements.abbreviation}${s.split('.').join('')} `
      )

      // NOTE: replacement of email addresses must come BEFORE urls
      // replace email addresses
      .replace(EMAIL_REGEX, config.replacements.email)

      // replace urls
      .replace(URL_REGEX, ` ${config.replacements.url} `)

      // now we ensure that URL's and EMAIL's are properly spaced out
      // (e.g. in case ?email=some@email.com was in a URL)
      .replace(EMAIL_REPLACEMENT_REGEX, ` ${config.replacements.email} `)

      // TODO: replace file paths, file dirs, dotfiles, and dotdirs

      // replace numbers
      // https://github.com/regexhq/floating-point-regex
      .replace(FLOATING_POINT_REGEX, ` ${config.replacements.number} `)
      .replace(NUMBER_REGEX, ` ${config.replacements.number} `)

      // TODO: may want to do more from this list (and others?)
      // <https://www.npmjs.com/package/f2e-tools#regexp>

      // replace currency
      .replace(CURRENCY_REGEX, ` ${config.replacements.currency} `);

  // expand contractions so "they're" -> [ they, are ] vs. [ they, re ]
  // <https://github.com/NaturalNode/natural/issues/533>
  if (locale === 'en') string = contractions.expand(string);

  // whitelist exclusions
  const whitelistedWords = Object.values(config.replacements);

  //
  // Future research:
  // - <https://github.com/NaturalNode/natural/issues/523>
  // - <https://github.com/mplatt/fold-to-ascii>
  // - <https://github.com/andrewrk/node-diacritics>)
  // - <https://www.elastic.co/guide/en/elasticsearch/reference/current/analysis-word-delimiter-tokenfilter.html>
  // - <https://www.elastic.co/guide/en/elasticsearch/reference/master/analysis-elision-tokenfilter.html>
  //
  const tokens = [];
  for (const token of tokenizer.tokenize(string.toLowerCase())) {
    // whitelist words from being stemmed (safeguard)
    if (
      whitelistedWords.includes(token) ||
      token.startsWith(config.replacements.initialism) ||
      token.startsWith(config.replacements.abbrevation)
    ) {
      tokens.push(token);
      continue;
    }

    if (
      stopwords.includes(token) ||
      (sw[locale] && sw[locale].includes(token)) ||
      (locale !== 'en' &&
        (stopwordsEn.includes(token) || sw.en.includes(token)))
    )
      continue;

    // locale specific stopwords to ignore
    let localeStem;
    if (typeof stemword === 'function') {
      localeStem = stemword(token);
      if (
        localeStem &&
        (stopwords.includes(localeStem) ||
          (sw[locale] && sw[locale].includes(localeStem)))
      )
        continue;
    }

    // always check against English stemwords
    let englishStem;
    if (locale !== 'en') {
      englishStem = snowball.stemword(token, 'english');
      if (
        englishStem &&
        (stopwordsEn.includes(englishStem) || sw.en.includes(englishStem))
      )
        continue;
    }

    tokens.push(
      localeStem && localeStem !== token ? localeStem : englishStem || token
    );
  }

  if (config.debug) return tokens;

  // we should sha256 all tokens with hasha if not in debug mode
  return Promise.all(tokens.map((token) => hasha.async(token, config.hasha)));
}

async function getTokensAndMailFromSource(string) {
  let source = string;
  if (isBuffer(string)) source = string.toString();
  else if (typeof string === 'string' && isValidPath(string))
    source = await readFile(string);

  const tokens = [];
  const mail = await simpleParser(
    source,
    config.simpleParser.Iconv ? { Iconv } : {}
  );

  await Promise.all(
    TOKEN_HEADERS.map(async (header) => {
      const string = isSANB(mail[header])
        ? mail[header]
        : typeof mail[header] === 'object' && isSANB(mail[header].text)
        ? mail[header].text
        : null;

      if (!string) return;

      const contentLanguage = mail.headers.get('content-language');
      const isHTML = header === 'html';
      const tokensFound = await getTokens(string, contentLanguage, isHTML);

      for (const token of tokensFound) {
        tokens.push(token);
      }
    })
  );

  return { tokens, mail };
}

if (!isMainThread) {
  parentPort.on('message', async (task) => {
    const res = await getTokensAndMailFromSource(task.string);
    parentPort.postMessage({ type: 'done', data: res });
  });
}

module.exports = {
  parseLocale,
  getTokens,
  getTokensAndMailFromSource
};
