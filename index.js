const dns = require('node:dns');
const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');
const { debuglog } = require('node:util');

// TODO: use lande instead of franc

const punycode = require('punycode/');

const autoBind = require('auto-bind');
const AFHConvert = require('ascii-fullwidth-halfwidth-convert');
const ClamScan = require('clamscan');
const NaiveBayes = require('@ladjs/naivebayes');
const RE2 = require('re2');
const arrayJoinConjunction = require('array-join-conjunction');
const bitcoinRegex = require('bitcoin-regex');
const creditCardRegex = require('credit-card-regex');
const emailRegexSafe = require('email-regex-safe');
// const emojiPatterns = require('emoji-patterns');
const escapeStringRegexp = require('escape-string-regexp');
const expandContractions = require('@stdlib/nlp-expand-contractions');
const fileExtension = require('file-extension');
const floatingPointRegex = require('floating-point-regex');
const franc = require('franc');
const getSymbolFromCurrency = require('currency-symbol-map');
const hasha = require('hasha');
const hexaColorRegex = require('hexa-color-regex');
const i18nLocales = require('i18n-locales');
const intoStream = require('into-stream');
const ipRegex = require('ip-regex');
const isBuffer = require('is-buffer');
const isSANB = require('is-string-and-not-blank');
const isStream = require('is-stream');
const isValidPath = require('is-valid-path');
const macRegex = require('mac-regex');
const macosVersion = require('macos-version');
const memoize = require('memoizee');
const mime = require('mime-types');
const ms = require('ms');
const natural = require('natural');
const normalizeUrl = require('normalize-url');
const phoneRegex = require('phone-regex');
const pWaitFor = require('p-wait-for');
// const regexParser = require('regex-parser');
const sanitizeHtml = require('sanitize-html');
const snowball = require('node-snowball');
const striptags = require('striptags');
const superagent = require('superagent');
const sw = require('stopword');
const toEmoji = require('gemoji/name-to-emoji');
const urlRegexSafe = require('url-regex-safe');
const validator = require('@forwardemail/validator');
const which = require('which');
const { Iconv } = require('iconv');
const { codes } = require('currency-codes');
const { fromUrl, NO_HOSTNAME } = require('parse-domain');
const { parse } = require('node-html-parser');
const { simpleParser } = require('mailparser');

// dynamically import file-type
let fileTypeFromBuffer;

import('file-type').then((obj) => {
  fileTypeFromBuffer = obj.fileTypeFromBuffer;
});

const debug = debuglog('spamscanner');

// all tokenizers combined
const GENERIC_TOKENIZER =
  /[^a-zá-úÁ-Úà-úÀ-Úñü\dа-яёæøåàáảãạăắằẳẵặâấầẩẫậéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵđäöëïîûœçążśźęćńł-]+/i;

const converter = new AFHConvert();

// <https://github.com/liyt96/is-japanese>
const japaneseRange = [
  [0x3041, 0x3096], // Hiragana
  [0x30a0, 0x30ff], // Katakana
  [0xff00, 0xffef], // Full-width roman characters and half-width katakana
  [0x4e00, 0x9faf], // Common and uncommon kanji
  [0xff01, 0xff5e], // Alphanumeric and Punctuation (Full Width)
  [0x3000, 0x303f], // Japanese Symbols and Punctuation
  [0x0020, 0x005c], // Basic Punctuation
  [0x2000, 0x206f], // General Punctuation
  [0x0030, 0x0039] // Number 0-9
];

const jpReStr = japaneseRange
  .map((range) => {
    if (!Array.isArray(range)) {
      return `\\u{${range.toString(16)}}`;
    }

    return `[\\u{${range[0].toString(16)}}-\\u{${range[1].toString(16)}}]`;
  })
  .join('|');

const JAPANESE_REGEX = new RE2(new RegExp(jpReStr, 'u'));

//
// NOTE: we periodically need to update this
//
// Source from: CC-CEDICT
// Licensed under Creative Commons Attribution-ShareAlike 4.0 International License
// <https://www.mdbg.net/chinese/dictionary?page=cc-cedict>
//
// <https://github.com/yishn/chinese-tokenizer>
//
const chineseTokenizer = require('chinese-tokenizer').loadFile(
  path.join(__dirname, 'cedict_1_0_ts_utf-8_mdbg.txt')
);

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

const stopwordsEn = new Set([
  ...require('natural/lib/natural/util/stopwords').words,
  ...sw.eng
]);
const stopwordsEs = new Set([
  ...require('natural/lib/natural/util/stopwords_es').words,
  ...sw.spa
]);
const stopwordsFa = new Set([
  ...require('natural/lib/natural/util/stopwords_fa').words,
  ...sw.fas
]);
const stopwordsFr = new Set([
  ...require('natural/lib/natural/util/stopwords_fr').words,
  ...sw.fra
]);
const stopwordsId = new Set([
  ...require('natural/lib/natural/util/stopwords_id').words,
  ...sw.ind
]);
const stopwordsJa = new Set([
  ...require('natural/lib/natural/util/stopwords_ja').words,
  ...sw.jpn
]);
const stopwordsIt = new Set([
  ...require('natural/lib/natural/util/stopwords_it').words,
  ...sw.ita
]);
const stopwordsNl = new Set([
  ...require('natural/lib/natural/util/stopwords_nl').words,
  ...sw.nld
]);
const stopwordsNo = new Set([
  ...require('natural/lib/natural/util/stopwords_no').words,
  ...sw.nob
]);
const stopwordsPl = new Set([
  ...require('natural/lib/natural/util/stopwords_pl').words,
  ...sw.pol
]);
const stopwordsPt = new Set([
  ...require('natural/lib/natural/util/stopwords_pt').words,
  ...sw.por,
  ...sw.porBr
]);
const stopwordsRu = new Set([
  ...require('natural/lib/natural/util/stopwords_ru').words,
  ...sw.rus
]);
const stopwordsSv = new Set([
  ...require('natural/lib/natural/util/stopwords_sv').words,
  ...sw.swe
]);
const stopwordsZh = new Set([
  ...require('natural/lib/natural/util/stopwords_zh').words,
  ...sw.zho
]);

const stopwordsRon = new Set(sw.ron);
const stopwordsTur = new Set(sw.tur);
const stopwordsVie = new Set(sw.vie);
const stopwordsDeu = new Set(sw.deu);
const stopwordsHun = new Set(sw.hun);
const stopwordsAra = new Set(sw.ara);
const stopwordsDan = new Set(sw.dan);
const stopwordsFin = new Set(sw.fin);

// TODO: add stopword pairing for these langs:
// afr
// ben
// bre
// bul
// cat
// ces
// ell
// epo
// est
// eus
// fra
// gle
// glg
// guj
// hau
// heb
// hin
// hrv
// hye
// kor
// kur
// lat
// lav
// lgg
// lggNd
// lit
// mar
// msa
// mya
// panGu
// slk
// slv
// som
// sot
// swa
// tgl
// tha
// ukr
// urd
// yor
// zul

// <https://stackoverflow.com/a/41353282>
// <https://www.ietf.org/rfc/rfc3986.txt>
const ENDING_RESERVED_REGEX = new RE2(
  `[${escapeStringRegexp(":/?#[]@!$&'()*+,;=")}]+$`
);

const PKG = require('./package.json');
const VOCABULARY_LIMIT = require('./vocabulary-limit.js');

// TODO: convert this into a Map
const ISO_CODE_MAPPING = require('./iso-code-mapping.json');

const ISO_CODE_MAPPING_KEYS = Object.keys(ISO_CODE_MAPPING);

// <https://kb.smarshmail.com/Article/23567>
const EXECUTABLES = new Set(require('./executables.json'));

const REPLACEMENT_WORDS = require('./replacement-words.json');

const locales = new Set(i18nLocales.map((l) => l.toLowerCase()));

const normalizeUrlOptions = {
  stripProtocol: true,
  stripWWW: false,
  removeQueryParameters: [],
  removeTrailingSlash: true,
  sortQueryParameters: false
};

// <https://stackoverflow.com/a/15926317>
// <https://github.com/uhop/node-re2#backreferences>
// <https://stackoverflow.com/a/26764609>
// <https://stackoverflow.com/a/9158444>
const ANCHOR_REGEX = new RE2(/<a.*?>.*?<\/a>/i);

// <https://stackoverflow.com/a/60626382>
// NOTE: we preserve Japanese characters and symbols
const EMOJI_REGEX = new RE2(
  /(\u00A9|\u00AE|[\u2000-\u3300]|\uD83C[\uD000-\uDFFF]|\uD83D[\uD000-\uDFFF]|\uD83E[\uD000-\uDFFF])/
);
const FLOATING_POINT_REGEX = new RE2(floatingPointRegex());
const CC_REGEX = new RE2(creditCardRegex());
const PHONE_REGEX = new RE2(phoneRegex());
const BITCOIN_REGEX = new RE2(bitcoinRegex());
const MAC_REGEX = new RE2(macRegex());
const HEXA_COLOR_REGEX = new RE2(hexaColorRegex());

// TODO: fix g flag  <https://medium.com/@nikjohn/regex-test-returns-alternating-results-bd9a1ae42cdd>
console.log(FLOATING_POINT_REGEX);
console.log(CC_REGEX);
console.log(PHONE_REGEX);
console.log(BITCOIN_REGEX);
console.log(MAC_REGEX);
console.log(HEXA_COLOR_REGEX);

console.log(PHONE_REGEX.match('123-444-5555 baz beep'));
console.log(PHONE_REGEX.match('123-444-5555 baz beep'));
console.log(PHONE_REGEX.match('123-444-5555 baz beep'));
console.log(PHONE_REGEX.match('beep baz 123-444-5555'));
console.log(PHONE_REGEX.match('beep baz 123-444-5555'));
console.log(PHONE_REGEX.match('123-444-5555 baz beep'));
console.log(PHONE_REGEX.match('123-444-5555 baz beep'));
console.log(PHONE_REGEX.match('beep baz 123-444-5555'));
console.log(PHONE_REGEX.match('beep baz 123-444-5555'));
console.log(PHONE_REGEX.match('123-444-5555 baz beep'));

// <https://github.com/NaturalNode/natural/issues/523#issuecomment-623287047>
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
    // eslint-disable-next-line unicorn/prefer-includes
    currencySymbols.indexOf(symbol) === -1 &&
    !new RE2(/^[a-z]+$/i).test(symbol)
  )
    currencySymbols.push(escapeStringRegexp(symbol));
}

const CURRENCY_REGEX = new RE2(new RegExp(currencySymbols.join('|'), 'g'));

// <https://spamassassin.apache.org/gtube/>
// <https://spamassassin.apache.org/gtube/gtube.txt>
const GTUBE =
  'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';

const MAIL_PHISHING_PROPS = ['subject', 'from', 'to', 'cc', 'bcc', 'text'];
const TOKEN_HEADERS = [...MAIL_PHISHING_PROPS, 'html'];

// <https://github.com/sindresorhus/ip-regex>
const IP_REGEX = new RE2(ipRegex());

// strip zero-width characters
// <https://github.com/peerigon/parse-domain/issues/116>
const ZERO_WIDTH_REGEX = new RE2(/[\u{200B}-\u{200D}]/gu);

// punctuation characters
// (need stripped from tokenization)
// <https://github.com/regexhq/punctuation-regex>
// NOTE: we prepended a normal "-" hyphen since it was missing
const PUNCTUATION_REGEX = new RE2(
  /[-‒–—―|$&~=\\/⁄@+*!?({[\]})<>‹›«».;:^‘’“”'",،、`·•†‡°″¡¿※#№÷×%‰−‱¶′‴§_‖¦]/g
);

const isURLOptions = {
  require_tld: false,
  require_protocol: false,
  require_host: false,
  require_valid_protocol: false
};

class SpamScanner {
  constructor(config = {}) {
    this.config = {
      debug:
        process.env.NODE_ENV === 'test' ||
        process.env.NODE_ENV === 'development',
      checkIDNHomographAttack: false,
      // note that if you attempt to train an existing `scanner.classifier`
      // then you will need to re-use these, so we suggest you store them
      replacements: config.replacements || require('./replacements.js'),
      // <https://nodemailer.com/extras/mailparser/>
      // NOTE: `iconv` package's Iconv cannot be used in worker threads
      // AND it can not also be shared in worker threads either (e.g. cloned)
      // <https://github.com/bnoordhuis/node-iconv/issues/211>
      // BUT we MUST use it because otherwise emails won't get parsed
      simpleParser: { Iconv },
      // <https://github.com/NaturalNode/natural#bayesian-and-logistic-regression>
      // (ham) + a few other datasets
      // `wget --mirror --passive-ftp ftp://ftp.ietf.org/ietf-mail-archive`
      // `wget --mirror --passive-ftp ftp://ftp.ietf.org/concluded-wg-ietf-mail-archive`
      // (spam dataset is private at the moment)
      classifier: config.classifier || require('./get-classifier.js'),
      // default locale validated against i18n-locales
      locale: 'en',
      // we recommend to use axe/cabin, see https://cabinjs.com
      logger: console,
      // <https://github.com/apostrophecms/sanitize-html#what-are-the-default-options>
      // <https://developer.mozilla.org/en-US/docs/Web/HTML/Element>
      sanitizeHtml: {
        allowedTags: [
          'address',
          'article',
          'aside',
          'footer',
          'header',
          'h1',
          'h2',
          'h3',
          'h4',
          'h5',
          'h6',
          'hgroup',
          'nav',
          'section',
          'blockquote',
          'dd',
          'div',
          'dl',
          'dt',
          'figcaption',
          'figure',
          'hr',
          'li',
          'main',
          'ol',
          'p',
          'pre',
          'ul',
          'a',
          'abbr',
          'b',
          'bdi',
          'bdo',
          'br',
          'cite',
          'code',
          'data',
          'dfn',
          'em',
          'i',
          'kbd',
          'mark',
          'q',
          'rp',
          'rt',
          'rtc',
          'ruby',
          's',
          'samp',
          'span',
          'strong',
          'sub',
          'sup',
          'time',
          'u',
          'var',
          'wbr',
          // area
          // audio
          // img
          // map
          // track
          // video
          // embed
          // iframe
          // object
          // param
          // picture
          // source
          // canvas
          // noscript
          // script
          'del',
          'ins',
          'caption',
          'col',
          'colgroup',
          'table',
          'tbody',
          'td',
          'tfoot',
          'th',
          'thead',
          'tr',
          // NO FORM STUFF
          'details',
          'dalog',
          'menu',
          'summary',
          // slot
          // template
          'center',
          'marquee',
          'strike'
        ],
        allowedAttributes: false
      },
      userAgent: `${PKG.name}/${PKG.version}`,
      timeout: ms('10s'),
      clamscan: {
        debugMode:
          process.env.NODE_ENV === 'test' ||
          process.env.NODE_ENV === 'development',
        clamscan: {
          path: which.sync('clamscan', { nothrow: true })
        },
        clamdscan: {
          timeout: ms('10s'),
          path: which.sync('clamdscan', { nothrow: true }),
          socket: macosVersion.isMacOS
            ? '/tmp/clamd.socket'
            : '/var/run/clamav/clamd.ctl'
        }
      },
      hasha: {
        algorithm: 'sha256'
      },
      vocabularyLimit: VOCABULARY_LIMIT,
      // <https://github.com/medikoo/memoizee#expire-cache-after-given-period-of-time>
      memoize: {
        ...config.memoize,
        // override always
        promise: true
      },
      // @ladjs/redis client instance
      client: false,
      cachePrefix: 'spamscanner',
      ttlMs: ms('1h'),
      // franc
      franc: {
        minLength: 5,
        only: ISO_CODE_MAPPING_KEYS
      },
      // if franc detects multiple languages that have >= % threshold
      // then if the locale detected was one of them, what is the probability
      // it must have in order to override all the other matches
      detectedLocaleOverrideProbability: 0.9,
      ...config
    };

    // ensure all replacements are there
    if (typeof this.config.replacements !== 'object')
      throw new Error('Replacements missing');

    for (const replacement of REPLACEMENT_WORDS) {
      if (!isSANB(this.config.replacements[replacement]))
        throw new Error(`Replacement for "${replacement}" missing`);
    }

    this.classifier =
      typeof this.config.classifier === 'object'
        ? this.config.classifier
        : typeof this.config.classifier === 'string'
        ? isValidPath(this.config.classifier)
          ? require(this.config.classifier)
          : JSON.parse(this.config.classifier)
        : false;

    this.classifier = NaiveBayes.fromJson(
      this.classifier,
      this.config.vocabularyLimit
    );
    // since we do tokenization ourselves
    this.classifier.tokenizer = function (tokens) {
      return tokens;
    };

    this.clamscan = this.config.clamscan === false ? false : new ClamScan();

    // memoized methods (either uses Redis or in-memory cache)
    if (this.config.client)
      this.memoizedIsCloudflareBlocked = async function (name) {
        const key = `${this.config.cachePrefix}:${name}`;
        try {
          const value = await this.config.client.get(key);
          if (value) {
            let array = value.split(':');
            if (array.length !== 2)
              throw new Error('Length was not exactly two');

            array = array.map((value_) => value_ === 'true');
            return { isAdult: array[0], isMalware: array[1] };
          }
        } catch (err) {
          this.config.logger.error(err);
        }

        const { isAdult, isMalware } = await this.isCloudflareBlocked(name);

        // cache in the background
        this.config.client
          .set(key, `${isAdult}:${isMalware}`, 'PX', this.config.ttlMs)
          .then(this.config.logger.info)
          .catch(this.config.logger.error);
        return { isAdult, isMalware };
      };
    else
      this.memoizedIsCloudflareBlocked = memoize(
        this.isCloudflareBlocked,
        this.config.memoize
      );

    if (!locales.has(this.parseLocale(this.config.locale)))
      throw new Error(
        `Locale of ${this.config.locale} was not valid according to locales list.`
      );

    //
    // set up regex helpers
    //
    this.EMAIL_REPLACEMENT_REGEX = new RE2(this.config.replacements.email, 'g');
    const replacementRegexes = [];
    for (const key of Object.keys(this.config.replacements)) {
      replacementRegexes.push(
        escapeStringRegexp(this.config.replacements[key])
      );
    }

    this.REPLACEMENTS_REGEX = new RE2(
      new RegExp(replacementRegexes.join('|'), 'g')
    );

    //
    // set up helper Map and Sets for fast lookup
    // (Set.has is 2x faster than includes, and 50% faster than indexOf)
    //
    this.WHITELISTED_WORDS = new Set(Object.values(this.config.replacements));

    autoBind(this);
  }

  getHostname(link) {
    link = link.trim().replace(/\.+$/, '').toLowerCase();

    // strip zero-width characters
    // <https://github.com/peerigon/parse-domain/issues/116>
    link = link.replace(ZERO_WIDTH_REGEX, '');

    // if it was not a valid URL then ignore it
    if (!validator.isURL(link, isURLOptions)) return;

    // <https://github.com/peerigon/parse-domain/issues/114>
    if (validator.isIP(link)) return link;

    // uses `new Url` (e.g. it adds http:// if it does not exist)
    let unicode = link;
    try {
      unicode = punycode.toUnicode(link);
    } catch (err) {
      /*
      Overflow: input needs wider integers to process
      RangeError: Overflow: input needs wider integers to process
         at error (punycode.js:42:8)
         at decode (punycode.js:241:5)
         at punycode.js:389:6
         at map (punycode.js:57:20)
         at mapDomain (punycode.js:84:18)
         at Object.toUnicode (punycode.js:387:9)
         at SpamScanner.getHostname
      */
      this.config.logger.warn(err);
    }

    // NOTE: IPv6 is not currently working with parse-domain and I already filed an issue
    // <https://github.com/peerigon/parse-domain/issues/114>
    const url = fromUrl(unicode);
    if (url === NO_HOSTNAME) {
      // use ipv4 and ipv6 regex to get just the value
      const matches = link.match(IP_REGEX) || [];
      if (matches.length > 0) {
        if (matches.length > 1)
          this.config.logger.error(
            new Error(
              `${link} had more than one match for IPv4/IPv6: ${matches.join(
                ', '
              )}`
            )
          );
        return matches[0];
      }

      // if there were still no matches, then check if it was a phone number
      if (new RE2(phoneRegex()).test(link)) return;

      // if it was a file path, then ignore it
      if (isValidPath(link)) return;

      // it was most likely invalid as it was just "foo" or it started with a slash like "/newsletter/unsubscribe"
      // this code should never be reached, but just in case we should know if something is weird
      this.config.logger.warn(
        new Error(`${link} was invalid and did not have a hostname`)
      );
      return;
    }

    return url;
  }

  getClassification(tokens) {
    return Promise.resolve(this.classifier.categorize(tokens, true));
  }

  async getVirusResults(mail) {
    const messages = [];

    if (!this.clamscan) {
      debug('clamscan disabled');
      return messages;
    }

    if (!Array.isArray(mail.attachments) || mail.attachments.length === 0)
      return messages;

    try {
      // if it was already loaded, clamscan won't reload itself
      // it has logic built-in to return early with the already initialized instance
      const clamscan = await this.clamscan.init(this.config.clamscan);

      await Promise.all(
        mail.attachments.map(async (attachment, i) => {
          try {
            const stream = isStream(attachment.content)
              ? attachment.content
              : intoStream(attachment.content);
            const { isInfected, viruses } = await clamscan.scanStream(stream);
            const name = isSANB(attachment.filename)
              ? `"${attachment.filename}"`
              : `#${i + 1}`;
            if (isInfected)
              messages.push(
                `Attachment ${name} was infected with ${arrayJoinConjunction(
                  viruses
                )}.`
              );
          } catch (err) {
            this.config.logger.error(err);
          }
        })
      );
    } catch (err) {
      this.config.logger.error(err);
    }

    return messages;
  }

  getArbitraryResults(mail) {
    const messages = [];

    let gtube = false;

    if (
      isSANB(mail.html) &&
      mail.html.replace(NEWLINE_REGEX, ' ').includes(GTUBE)
    )
      gtube = true;

    if (
      isSANB(mail.text) &&
      !gtube &&
      mail.text.replace(NEWLINE_REGEX, ' ').includes(GTUBE)
    )
      gtube = true;

    if (gtube)
      messages.push(
        'Message detected to contain the GTUBE test from https://spamassassin.apache.org/gtube/.'
      );

    return messages;
  }

  // pass this a DNS over HTTPS endpoint to lookup for 0.0.0.0 result
  async malwareLookup(endpoint, name) {
    try {
      const response = await superagent
        .get(endpoint)
        .query({
          name,
          type: 'A'
        })
        .timeout(this.config.timeout)
        .set('Accept', 'application/dns-json')
        .set('User-Agent', this.config.userAgent)
        .send();
      const body = JSON.parse(response.body);
      return (
        Array.isArray(body.Answer) &&
        body.Answer.length === 1 &&
        body.Answer[0].data === '0.0.0.0'
      );
    } catch (err) {
      this.config.logger.error(err);
      try {
        //
        // NOTE: note that in newer Node versions we will
        // be able to configure a DNS lookup timeout
        // and we should also support this DNS + fallback approach
        // in Forward Email at some point in the future
        // and additionally ensure that the DNS lookup fallback
        // uses DNS over TLS with DNSSEC (+ documentation for self hosting)
        //
        const records = await dns.promises.resolve4(name);
        return (
          Array.isArray(records) &&
          records.length === 1 &&
          records[0] === '0.0.0.0'
        );
      } catch (err) {
        this.config.logger.warn(err);
        return false;
      }
    }
  }

  //
  // DNS over HTTPS with Cloudflare for Family
  // <https://one.one.one.one/family/>
  // <https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families/setup-instructions/dns-over-https/>
  // <https://developers.cloudflare.com/1.1.1.1/dns-over-https/json-format/>
  //
  // curl -H 'accept: application/dns-json' 'https://family.cloudflare-dns.com/dns-query?name=phishing.example.com&type=A'
  // {"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"phishing.example.com","type":1}],"Answer":[{"name":"phishing.example.com","type":1,"TTL":60,"data":"0.0.0.0"}]}
  //
  async isCloudflareBlocked(name) {
    //
    // NOTE: this uses DNS over HTTPS with a fallback system-level DNS lookup
    // (which would assume you are using either 1.1.1.2 + 1.0.0.2 OR 1.1.1.3 + 1.0.0.3)
    // <https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families>
    //
    // However we don't recommend this and therefore have our servers set to standard Cloudflare DNS
    //
    const [isAdult, isMalware] = await Promise.all([
      this.malwareLookup('https://family.cloudflare-dns.com/dns-query', name),
      this.malwareLookup('https://security.cloudflare-dns.com/dns-query', name)
    ]);

    return { isAdult, isMalware };
  }

  //
  // due to this issue and the fact that PhishTank adds invalid URL's
  // we have to implement our own workaround to normalize a valid/invalid URL
  // <https://github.com/sindresorhus/normalize-url/issues/111>
  //
  getNormalizedUrl(url) {
    url = url.trim().replace(/\.+$/, '').toLowerCase();

    // strip zero-width characters
    // <https://github.com/peerigon/parse-domain/issues/116>
    url = url.replace(ZERO_WIDTH_REGEX, '');

    // don't return a URL if it was invalid after being trimmed
    if (!validator.isURL(url, isURLOptions)) return;

    let normalized = url;
    try {
      normalized = normalizeUrl(url, normalizeUrlOptions);
    } catch (err) {
      this.config.logger.error(err);
      // <https://stackoverflow.com/questions/6680825/return-string-without-trailing-slash#comment11853012_6680877>
      normalized = url
        .replace('http://', '')
        .replace('https://', '')
        .replace(/\/+$/, '');
    }

    // TODO: this is super slow to parse all the url's on a huge 15MB+ email
    const hostname = fromUrl(normalized);
    if (hostname === NO_HOSTNAME) {
      this.config.logger.error(
        new Error(`No hostname (URL: ${url}, NORMALIZED: ${normalized}`)
      );

      // if there were still no matches, then check if it was a phone number
      if (new RE2(phoneRegex()).test(normalized)) return;

      // if it was a file path, then ignore it
      if (isValidPath(normalized)) return;

      return normalized;
    }

    let unicode = hostname;

    try {
      unicode = punycode.toUnicode(hostname);
    } catch (err) {
      this.config.logger.warn(err);
    }

    try {
      const object = new URL(
        `http://${unicode}${normalized.slice(hostname.length)}`
      );

      //
      // NOTE: we must strip reserved characters from the end of the string
      // (even Gmail does this practice)
      // <https://github.com/kevva/url-regex/issues/71>
      const pathname = object.pathname.replace(ENDING_RESERVED_REGEX, '');

      //
      // NOTE: we strip querystring and hash here as we don't consider them
      // which may ultimately lead to false positives on mass emailing services
      // however we are taking this approach because these services should
      // be enforcing strict anti-spam policies and prevention measures anyways
      // (e.g. we will send them 429 retry or spam complaint status code
      // which will in turn alert them to the issue with whoever is spamming)
      //
      return `${object.hostname}${pathname === '/' ? '' : pathname}`;
    } catch (err) {
      this.config.logger.error(err, { url, normalized });
      return normalized;
    }
  }

  // <https://github.com/kevva/url-regex/issues/70
  // <https://github.com/sindresorhus/get-urls/blob/master/index.js
  // <https://github.com/kevva/url-regex/issues/71>
  // <https://github.com/kevva/url-regex/pull/35>
  //
  getUrls(text) {
    // before we filter for URL's, we need to replace email addresses
    // with hostnames, otherwise there will be incorrect matches
    // due to the inaccuracy (which is unpreventable) from url-regex-safe
    // when parsing email addresses, e.g. foo.it.beep.mx.bar@gmail.com
    // would normally get parsed to [ foo.it, beep.mx, gmail.com ]
    // but it should only get parsed to gmail.com since that's the hostname
    // <https://github.com/kevva/url-regex/pull/67>
    const urls =
      text
        .replace(NEWLINE_REGEX, ' ')
        .replace(
          EMAIL_REGEX,
          (match) =>
            ` ${this.getHostname(match.slice(match.lastIndexOf('@') + 1))} `
        )
        .replace(URL_REGEX, (match, offset, string) => {
          const nextChar = string.slice(
            offset + match.length,
            offset + match.length + 1
          );
          if (new RE2(/^\w$/).test(nextChar)) return ' ';

          // only return a match if the case was the same when converted
          // (this matches Gmail's behavior in parsing/rendering URL's)
          if (match.toLowerCase() !== match && match.toUpperCase() !== match)
            return ' ';

          return ` ${match} `;
        })
        .match(URL_REGEX) || [];

    const array = new Set();
    for (const url of urls) {
      const normalized = this.getNormalizedUrl(url);

      if (normalized) array.add(normalized);
    }

    return [...array];
  }

  parseLocale(locale) {
    // convert `franc` locales here to their locale iso2 normalized name
    return locale.toLowerCase().split('-')[0].split('_')[0];
  }

  // <https://medium.com/analytics-vidhya/building-a-spam-filter-from-scratch-using-machine-learning-fc58b178ea56>
  // <https://towardsdatascience.com/empirical-analysis-on-email-classification-using-the-enron-dataset-19054d558697>
  // <https://blog.logrocket.com/natural-language-processing-for-node-js/>
  // <https://github.com/NaturalNode/natural#stemmers>
  // eslint-disable-next-line complexity
  async getTokens(string, locale, isHTML = false) {
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
          locales.has(this.parseLocale(meta.getAttribute('content')))
        ) {
          locale = this.parseLocale(meta.getAttribute('content'));
          break;
        }
      }

      const _metas = root.querySelectorAll('META');

      for (const meta of _metas) {
        if (
          meta.getAttribute('http-equiv') === 'Content-Language' &&
          isSANB(meta.getAttribute('content')) &&
          locales.has(this.parseLocale(meta.getAttribute('content')))
        ) {
          locale = this.parseLocale(meta.getAttribute('content'));
          break;
        }
      }

      if (!locale) {
        const html = root.querySelector('html') || root.querySelector('HTML');
        if (
          html &&
          isSANB(html.getAttribute('lang')) &&
          locales.has(this.parseLocale(html.getAttribute('lang')))
        )
          locale = this.parseLocale(html.getAttribute('lang'));
      }
    }

    if (isHTML) string = sanitizeHtml(string, this.config.sanitizeHtml);

    string = striptags(string, [], ' ')
      .trim()
      // replace newlines
      .replace(NEWLINE_REGEX, ' ')
      //
      // attackers may try to inject our replacements into the message
      // therefore we should strip all of them before doing any replacements
      //
      .replace(this.REPLACEMENTS_REGEX, ' ');

    //
    // we should instead use language detection to determine
    // what language/locale this message is in (as opposed to relying on headers)
    // which could get arbitrarily modified by an attacker
    // <https://github.com/wooorm/franc/issues/86> (accurate with min length)
    // <https://github.com/FGRibreau/node-language-detect> (not too accurate)
    //
    const detectedLanguages = franc.all(string, this.config.franc);
    if (Array.isArray(detectedLanguages) && detectedLanguages.length > 0) {
      let detected = this.config.locale;
      let probability = 0;
      for (const lang of detectedLanguages) {
        // if it was undetermined then break out and revert to default (English)
        if (lang[0] && lang[0] === 'und') break;

        //
        // otherwise only use detected languages that have >= 90% accuracy
        // and if no matches were found, the revert to use English as it's most likely spam
        // (we can assume that users would understand a different language sent to them is spam)
        // (so we can assume that language is spoofed to bypass English, the most widely spoken)
        //
        if (lang[0] && ISO_CODE_MAPPING[lang[0]] && lang[1]) {
          // we don't want to check anything lower than our threshold
          if (lang[1] < this.config.detectedLocaleOverrideProbability) break;
          if (probability >= lang[1]) {
            // exit early since we found a match that matched the passed locale
            // eslint-disable-next-line max-depth
            if (locale && locale === ISO_CODE_MAPPING[lang[0]]) {
              detected = locale;
              probability = lang[1];
              break;
            }
          } else {
            detected = ISO_CODE_MAPPING[lang[0]];
            probability = lang[1];
          }
        }
      }

      // override the locale based off detected
      locale = detected;
    }

    locale = this.parseLocale(isSANB(locale) ? locale : this.config.locale);

    // NOTE: "in" and "po" are valid locales but not from i18n
    if (!locales.has(locale) && locale !== 'in' && locale !== 'po') {
      debug(`Locale ${locale} was not valid and will use default`);
      locale = this.parseLocale(this.config.locale);
    }

    // TODO: add new languages <https://github.com/hthetiot/node-snowball/pull/21/commits/3871acf1f38b00960929545bc8ab5f591f50c024>
    // <https://github.com/hthetiot/node-snowball#supported-language-second-argument>
    // <https://github.com/NaturalNode/natural#tokenizers>
    let tokenizer = aggressiveTokenizer;
    let stopwords = stopwordsEn;
    let language = 'english';
    let stemword = 'default';

    switch (locale) {
      case 'ar': {
        // arb
        // ISO 639-3 = ara
        stopwords = stopwordsAra;
        language = 'arabic';
        break;
      }

      case 'da': {
        // dan
        language = 'danish';
        stopwords = stopwordsDan;
        break;
      }

      case 'nl': {
        // nld
        stopwords = stopwordsNl;
        language = 'dutch';
        break;
      }

      case 'en': {
        // eng
        language = 'english';
        break;
      }

      case 'fi': {
        // fin
        language = 'finnish';
        tokenizer = orthographyTokenizer;
        stopwords = stopwordsFin;
        break;
      }

      case 'fa': {
        // fas (Persian/Farsi)
        language = 'farsi';
        tokenizer = aggressiveTokenizerFa;
        stopwords = stopwordsFa;
        stemword = natural.PorterStemmerFa.stem.bind(natural.PorterStemmerFa);
        break;
      }

      case 'fr': {
        // fra
        language = 'french';
        tokenizer = aggressiveTokenizerFr;
        stopwords = stopwordsFr;
        break;
      }

      case 'de': {
        // deu
        language = 'german';
        stopwords = stopwordsDeu;
        // TODO: may want to use porterstemmerde
        // <https://github.com/NaturalNode/natural/blob/master/lib/natural/stemmers/porter_stemmer_de.js>
        break;
      }

      case 'hu': {
        // hun
        language = 'hungarian';
        stopwords = stopwordsHun;
        break;
      }

      case 'in': {
        // ind
        language = 'indonesian';
        tokenizer = aggressiveTokenizerId;
        stopwords = stopwordsId;
        break;
      }

      case 'it': {
        // ita
        language = 'italian';
        tokenizer = aggressiveTokenizerIt;
        stopwords = stopwordsIt;
        break;
      }

      case 'ja': {
        // jpn
        tokenizer = tokenizerJa;
        stopwords = stopwordsJa;
        stemword = natural.StemmerJa.stem.bind(natural.StemmerJa);
        break;
      }

      case 'nb': {
        // nob
        language = 'norwegian';
        tokenizer = aggressiveTokenizerNo;
        stopwords = stopwordsNo;
        break;
      }

      case 'nn': {
        // nno
        // ISO 639-3 = nob
        language = 'norwegian';
        tokenizer = aggressiveTokenizerNo;
        stopwords = stopwordsNo;
        break;
      }

      case 'po': {
        // pol
        language = 'polish';
        tokenizer = aggressiveTokenizerPl;
        stopwords = stopwordsPl;
        stemword = false;
        break;
      }

      case 'pt': {
        // por
        language = 'portuguese';
        tokenizer = aggressiveTokenizerPt;
        stopwords = stopwordsPt;
        break;
      }

      case 'es': {
        // spa
        language = 'spanish';
        tokenizer = aggressiveTokenizerEs;
        stopwords = stopwordsEs;
        break;
      }

      case 'sv': {
        // swe
        language = 'swedish';
        tokenizer = aggressiveTokenizerSv;
        stopwords = stopwordsSv;
        break;
      }

      case 'ro': {
        // ron
        language = 'romanian';
        stopwords = stopwordsRon;
        break;
      }

      case 'ru': {
        // rus
        language = 'russian';
        tokenizer = aggressiveTokenizerRu;
        stopwords = stopwordsRu;
        break;
      }

      case 'ta': {
        // tam
        // NOTE: no stopwords available
        language = 'tamil';
        break;
      }

      case 'tr': {
        // tur
        language = 'turkish';
        stopwords = stopwordsTur;
        break;
      }

      case 'vi': {
        // vie
        language = 'vietnamese';
        tokenizer = aggressiveTokenizerVi;
        stopwords = stopwordsVie;
        stemword = false;
        break;
      }

      case 'zh': {
        // cmn
        // ISO 639-3 = zho (Chinese, Macrolanguage)
        // https://github.com/yishn/chinese-tokenizer
        // NOTE: the chinese tokenizer is breaking apart words where it shouldn't
        tokenizer = {
          tokenize(message) {
            // we need to separate by spaces here
            message +=
              'foobar 行政管理pickles 行政管 理test行 numberyylwggnxav 東京Japan numberyylwggnxav bnumberyylwggnxavbnumberyylwggnxav';
            const arr = message.split(/\s+/);
            const tokens = [];
            // TODO: need to run japanese
            // TODO: need to run orthography
            for (const str of arr) {
              // TODO: we probably need to re-use this tokenizer across everything
              //       but for the "English" part, default to whatever language was passed
              //       NOTE: someone could mix Arabic and English and Mandarin and attempt to bypass
              if (JAPANESE_REGEX.test(str)) {
                const values = chineseTokenizer(str);
                for (const result of values) {
                  console.log('str', str, 'pushing', result.text);
                  // TODO: need to run english tokenizer here
                  //       on anything that isn't 100% is-japanese
                  for (const a of result.text.split(GENERIC_TOKENIZER)) {
                    tokens.push(a);
                  }
                }
              } else {
                console.log('pushing str', str);
                // TODO: need to run english tokenizer here
                for (const a of str.split(GENERIC_TOKENIZER)) {
                  tokens.push(a);
                }
              }
            }

            return tokens;
          }
        };
        language = 'chinese';
        stopwords = stopwordsZh;
        stemword = false;
        break;
      }

      default:
    }

    if (stemword === 'default')
      stemword = (t) => snowball.stemword(t, language);

    console.log('original string', string);

    //
    // TODO: replace any existing replacements in the string
    //       with newly rev hash versioned of the replacement replacements
    //       (prevent spoofing)
    //
    string = string
      // handle emojis
      // - convert github emojis to unicode 13 emojis
      // - replace all unicode emojis
      .split(/\s+/)
      .map((_string) =>
        _string.indexOf(':') === 0 &&
        _string.endsWith(':') &&
        typeof toEmoji[_string.slice(1, -1)] === 'string'
          ? toEmoji[_string.slice(1, -1)]
          : _string
      )
      .join(' ')
      .replace(EMOJI_REGEX, ` ${this.config.replacements.emoji} `)

      // https://github.com/regexhq/mac-regex
      .replace(MAC_REGEX, ` ${this.config.replacements.mac} `)

      // https://github.com/kevva/credit-card-regex
      .replace(CC_REGEX, ` ${this.config.replacements.cc} `)

      // https://github.com/kevva/bitcoin-regex
      .replace(BITCOIN_REGEX, ` ${this.config.replacements.bitcoin} `)

      // https://github.com/regexhq/phone-regex
      .replace(PHONE_REGEX, ` ${this.config.replacements.phone} `)

      // handle hex colors
      // https://github.com/regexhq/hexa-color-regex
      .replace(HEXA_COLOR_REGEX, ` ${this.config.replacements.hexa} `)

      // NOTE: replacement of email addresses must come BEFORE urls
      // replace email addresses
      .replace(EMAIL_REGEX, this.config.replacements.email)

      // replace urls
      .replace(URL_REGEX, ` ${this.config.replacements.url} `)

      // now we ensure that URL's and EMAIL's are properly spaced out
      // (e.g. in case ?email=some@email.com was in a URL)
      .replace(
        this.EMAIL_REPLACEMENT_REGEX,
        ` ${this.config.replacements.email} `
      )

      // TODO: replace file paths, file dirs, dotfiles, and dotdirs

      // TODO: replace dates (mm/dd/yy, mm-dd-yy, yy-mm-dd, etc)

      // replace numbers
      // https://github.com/regexhq/floating-point-regex
      .replace(FLOATING_POINT_REGEX, ` ${this.config.replacements.number} `)
      .replace(NUMBER_REGEX, ` ${this.config.replacements.number} `)

      // TODO: may want to do more from this list (and others?)
      // <https://www.npmjs.com/package/f2e-tools#regexp>

      // replace currency
      .replace(CURRENCY_REGEX, ` ${this.config.replacements.currency} `)

      // handle initialism(e.g. "AFK" -> "abbrev$crypto$afk")
      .replace(
        INITIALISM_REGEX,
        (s) => ` ${this.config.replacements.initialism}${s} `
      )

      // handle abbreviations (e.g. "u.s." -> "abbrev$crypto$us")
      // (note we have to replace the periods here)
      .replace(
        ABBREVIATION_REGEX,
        (s) =>
          ` ${this.config.replacements.abbreviation}${s.split('.').join('')} `
      );

    //
    // expand contractions so "they're" -> [ they, are ] vs. [ they, re ]
    // <https://github.com/NaturalNode/natural/issues/533>
    //
    // NOTE: we're doing this for all languages now, not just en
    //
    string = expandContractions(string);

    console.log('string', string);

    //
    // Future research:
    // - <https://github.com/NaturalNode/natural/issues/523>
    // - <https://github.com/mplatt/fold-to-ascii>
    // - <https://github.com/andrewrk/node-diacritics>)
    // - <https://www.elastic.co/guide/en/elasticsearch/reference/current/analysis-word-delimiter-tokenfilter.html>
    // - <https://www.elastic.co/guide/en/elasticsearch/reference/master/analysis-elision-tokenfilter.html>
    //
    const tokens = [];
    for (const _token of tokenizer.tokenize(string.toLowerCase())) {
      // convert full-width characters to half-width (normalize)
      const token = converter
        .toHalfWidth(_token)
        // strip punctuation characters
        .replace(PUNCTUATION_REGEX, '')
        // strip zero-width characters
        .replace(ZERO_WIDTH_REGEX, '')
        .trim();

      //
      // TODO: note if someone passes a message with mixed English/Chinese
      //       then the English tokenizer will actually filter out Chinese words
      //       (which means someone could spam nasty messages in Chinese inside an English detected email)
      //

      // TODO: replace Japanese Symbols and Punctuation
      // <https://gist.github.com/ryanmcgrath/982242>
      // <https://regex101.com/r/0LkDH8/1/codegen?language=javascript>
      // .replace(/[\u3000-\u303F]|[\uFF00-\uFFEF]/gu, '');

      console.log(`token was "${_token}" but is now "${token}"`);

      // Chinese tokenizer (and others) may yield empty strings
      if (token === '') continue;

      // whitelist words from being stemmed (safeguard)
      if (
        this.WHITELISTED_WORDS.has(token) ||
        token.indexOf(this.config.replacements.initialism) === 0 ||
        token.indexOf(this.config.replacements.abbrevation) === 0
      ) {
        tokens.push(token);
        continue;
      }

      if (stopwords.has(token) || (locale !== 'en' && stopwordsEn.has(token))) {
        continue;
      }

      // locale specific stopwords to ignore
      let localeStem;
      if (typeof stemword === 'function') {
        localeStem = stemword(token);
        if (localeStem && stopwords.has(localeStem)) {
          continue;
        }
      }

      // always check against English stemwords
      let englishStem;
      if (locale !== 'en') {
        englishStem = snowball.stemword(token, 'english');
        if (englishStem && stopwordsEn.has(englishStem)) continue;
      }

      tokens.push(
        localeStem && localeStem !== token ? localeStem : englishStem || token
      );
    }

    debug('locale', locale, 'tokens', tokens);

    if (this.config.debug) return tokens;

    // we should sha256 all tokens with hasha if not in debug mode
    return Promise.all(
      tokens.map((token) => hasha.async(token, this.config.hasha))
    );
  }

  async getTokensAndMailFromSource(string) {
    let source = string;
    if (isBuffer(string)) source = string.toString();
    else if (typeof string === 'string' && isValidPath(string))
      source = await fs.promises.readFile(string);

    const tokens = [];
    const mail = await simpleParser(source, this.config.simpleParser);

    await Promise.all(
      TOKEN_HEADERS.map(async (header) => {
        try {
          const string = isSANB(mail[header])
            ? mail[header]
            : typeof mail[header] === 'object' && isSANB(mail[header].text)
            ? mail[header].text
            : null;

          if (!string) return;

          const contentLanguage = mail.headers.get('content-language');
          const isHTML = header === 'html';
          const tokensFound = await this.getTokens(
            string,
            contentLanguage,
            isHTML
          );

          for (const token of tokensFound) {
            tokens.push(token);
          }
        } catch (err) {
          this.config.logger.error(err);
        }
      })
    );

    return { tokens, mail };
  }

  // eslint-disable-next-line complexity
  async getPhishingResults(mail) {
    const messages = new Set();
    //
    // NOTE: all links pushed are lowercased
    //
    const links = new Set();

    // parse <a> tags with different org domain in text vs the link
    if (isSANB(mail.html)) {
      //
      // NOTE: It would be interested to see if Gmail is prone to an injection attack
      // whereas elements they do not support get stripped out and then the returning
      // elements concatenate to form a URL which is malicious or phishing
      //
      for (const link of this.getUrls(striptags(mail.html, [], ' ').trim())) {
        links.add(link);
      }

      //
      //  we strip the protocol in order to parse out the actual addresses
      // <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/protocol_handlers>
      //

      //
      // NOTE: we cannot use this approach because it does not parse all the links
      //
      // const root = parse(mail.html);
      // const anchors = root.querySelectorAll('a');
      //
      const matches =
        mail.html.replace(NEWLINE_REGEX, ' ').match(ANCHOR_REGEX) || [];

      if (matches.length > 0) {
        for (const match of matches) {
          const root = parse(match);
          // <https://github.com/taoqf/node-html-parser/issues/60>
          const anchor = root.querySelector('a') || root.querySelector('A');

          // there is an edge (not sure where/how) possibly with regex
          // but the `anchor` will be `null` here sometimes so we
          // should catch that and prevent an error from being thrown
          if (!anchor) {
            this.config.logger.error(
              new Error(`Anchor not found for match: ${match}`)
            );
            continue;
          }

          const textContent = striptags(anchor.innerHTML, [], ' ').trim();
          let href = anchor.getAttribute('href');
          const hasHref = isSANB(href) && validator.isURL(href, isURLOptions);

          if (hasHref) {
            // parse out the first url
            // (this is needed because some have "Web:%20http://google.com" for example in href tags)
            [href] = this.getUrls(href);
            // eslint-disable-next-line max-depth
            if (href) links.add(href);
          }

          // the text content could contain multiple URL's
          // so we need to parse them each out
          if (
            isSANB(textContent) &&
            isSANB(href) &&
            validator.isURL(href, isURLOptions)
          ) {
            const string = `Anchor link with href of ${href} and inner text value of "${textContent}"`;
            // eslint-disable-next-line max-depth
            if (this.config.checkIDNHomographAttack) {
              const anchorUrlHostname = this.getHostname(href);
              // eslint-disable-next-line max-depth
              if (anchorUrlHostname) {
                const anchorUrlHostnameToASCII =
                  punycode.toASCII(anchorUrlHostname);
                // eslint-disable-next-line max-depth
                if (anchorUrlHostnameToASCII.indexOf('xn--') === 0)
                  messages.add(
                    `${string} has possible IDN homograph attack from anchor hostname.`
                  );
              }
            }

            // eslint-disable-next-line max-depth
            for (const link of this.getUrls(textContent)) {
              // this link should have already been included but just in case

              links.add(link);

              // eslint-disable-next-line max-depth
              if (this.config.checkIDNHomographAttack) {
                const innerTextUrlHostname = this.getHostname(link);
                // eslint-disable-next-line max-depth
                if (innerTextUrlHostname) {
                  const innerTextUrlHostnameToASCII =
                    punycode.toASCII(innerTextUrlHostname);
                  // eslint-disable-next-line max-depth
                  if (innerTextUrlHostnameToASCII.indexOf('xn--') === 0)
                    messages.add(
                      `${string} has possible IDN homograph attack from inner text hostname.`
                    );
                }
              }
            }
          }
        }
      }
    }

    // <https://docs.apwg.org/ecrimeresearch/2018/5359941.pdf>
    // <https://www.wandera.com/punycode-attacks/>
    for (const prop of MAIL_PHISHING_PROPS) {
      if (isSANB(mail[prop])) {
        for (const link of this.getUrls(mail[prop])) {
          links.add(link);
        }
      }
    }

    if (this.config.checkIDNHomographAttack) {
      for (const link of links) {
        const urlHostname = this.getHostname(link);
        if (urlHostname) {
          const toASCII = punycode.toASCII(urlHostname);
          if (toASCII.indexOf('xn--') === 0)
            messages.add(
              `Possible IDN homograph attack from link of ${link} with punycode converted hostname of ${toASCII}.`
            );
        }
      }
    }

    // check against Cloudflare malware/phishing/adult DNS lookup
    // if it returns `0.0.0.0` it means it was flagged
    await Promise.all(
      [...links].map(async (link) => {
        try {
          const urlHostname = this.getHostname(link);
          if (urlHostname) {
            const toASCII = punycode.toASCII(urlHostname);
            const adultMessage = `Link hostname of ${toASCII} was detected by Cloudflare's Family DNS to contain adult-related content, phishing, and/or malware (https://radar.cloudflare.com/domains/feedback/${toASCII}).`;
            const malwareMessage = `Link hostname of ${toASCII} was detected by Cloudflare's Security DNS to contain phishing and/or malware (https://radar.cloudflare.com/domains/feedback/${toASCII}).`;

            // if it already included both messages then return early
            if (messages.has(adultMessage) && messages.has(malwareMessage))
              return;

            const { isAdult, isMalware } =
              await this.memoizedIsCloudflareBlocked(toASCII);

            if (isAdult && !messages.has(adultMessage))
              messages.add(adultMessage);
            if (isMalware && !messages.has(malwareMessage))
              messages.add(malwareMessage);
          }
        } catch (err) {
          this.config.logger.error(err);
        }
      })
    );

    return { messages: [...messages], links: [...links] };
  }

  // TODO: check against urlhaus and malware bazaar (on FE side using mongo or redis)
  // TODO: use sharp to get uint8array (?)
  // TODO: finish this
  async getNSFWResults() {
    return [];
  }

  // TODO: finish this
  getNSFWResults() {
    return [];
  }

  async getExecutableResults(mail) {
    const messages = [];

    if (!Array.isArray(mail.attachments)) return messages;

    // NOTE: we don't inspect <a> or normal links in the message html/text

    // if any attachments have an executable
    await Promise.all(
      mail.attachments.map(async (attachment) => {
        if (isBuffer(attachment.content)) {
          try {
            if (!fileTypeFromBuffer)
              await pWaitFor(() => Boolean(fileTypeFromBuffer));
            const fileType = await fileTypeFromBuffer(attachment.content);
            // TODO: detect and prohibit macros
            // <https://jhalon.github.io/re-malicious-macros/>
            // <https://github.com/enkomio/MacroInspector>
            if (fileType && fileType.ext && EXECUTABLES.has(fileType.ext))
              messages.push(
                `Attachment's "magic number" indicated it was a dangerous executable with a ".${fileType.ext}" extension.`
              );
          } catch (err) {
            this.config.logger.error(err);
          }
        }

        if (isSANB(attachment.filename)) {
          // run punycode on file name as well since file names can be spoofed
          const filename = punycode.toASCII(
            punycode.toUnicode(attachment.filename.split('?')[0])
          );
          // fileExtension returns lowercase by default
          const ext = fileExtension(filename);
          if (ext && EXECUTABLES.has(ext))
            messages.push(
              `Attachment's file name indicated it was a dangerous executable with a ".${ext}" extension.`
            );
        }

        if (isSANB(attachment.contentType)) {
          const ext = mime.extension(attachment.contentType);
          if (isSANB(ext) && EXECUTABLES.has(ext))
            messages.push(
              `Attachment's Content-Type was a dangerous executable with a ".${ext}" extension.`
            );
        }
      })
    );

    return messages;
  }

  async getExecutableResults(mail) {
    const messages = [];

    if (!Array.isArray(mail.attachments)) return messages;

    // NOTE: we don't inspect <a> or normal links in the message html/text

    // if any attachments have an executable
    await Promise.all(
      mail.attachments.map(async (attachment) => {
        if (isBuffer(attachment.content)) {
          try {
            if (!fileTypeFromBuffer)
              await pWaitFor(() => Boolean(fileTypeFromBuffer));
            const fileType = await fileTypeFromBuffer(attachment.content);
            // TODO: detect and prohibit macros
            // <https://jhalon.github.io/re-malicious-macros/>
            // <https://github.com/enkomio/MacroInspector>
            if (fileType && fileType.ext && EXECUTABLES.has(fileType.ext))
              messages.push(
                `Attachment's "magic number" indicated it was a dangerous executable with a ".${fileType.ext}" extension.`
              );
          } catch (err) {
            this.config.logger.error(err);
          }
        }

        if (isSANB(attachment.filename)) {
          // run punycode on file name as well since file names can be spoofed
          const filename = punycode.toASCII(
            punycode.toUnicode(attachment.filename.split('?')[0])
          );
          // fileExtension returns lowercase by default
          const ext = fileExtension(filename);
          if (ext && EXECUTABLES.has(ext))
            messages.push(
              `Attachment's file name indicated it was a dangerous executable with a ".${ext}" extension.`
            );
        }

        if (isSANB(attachment.contentType)) {
          const ext = mime.extension(attachment.contentType);
          if (isSANB(ext) && EXECUTABLES.has(ext))
            messages.push(
              `Attachment's Content-Type was a dangerous executable with a ".${ext}" extension.`
            );
        }
      })
    );

    return messages;
  }

  async scan(string) {
    const { tokens, mail } = await this.getTokensAndMailFromSource(string);

    // TODO: <https://developers.cloudflare.com/cloudflare-one/policies/filtering/dns-policies/test-dns-filtering/>
    // TODO: <https://developers.cloudflare.com/cloudflare-one/policies/filtering/domain-categories/>

    const [
      classification,
      phishing,
      executables,
      arbitrary,
      viruses,
      nsfw,
      toxicity
    ] = await Promise.all([
      this.getClassification(tokens),
      this.getPhishingResults(mail),
      this.getExecutableResults(mail),
      this.getArbitraryResults(mail),
      this.getVirusResults(mail),
      this.getNSFWResults(mail),
      this.getToxicityResults(mail)
    ]);

    const messages = [];

    if (classification && classification.category === 'spam')
      messages.push('Spam detected from Naive Bayesian classifier.');

    for (const message of phishing.messages) {
      messages.push(message);
    }

    for (const message of nsfw) {
      messages.push(message);
    }

    for (const message of toxicity) {
      messages.push(message);
    }

    for (const message of executables) {
      messages.push(message);
    }

    for (const message of arbitrary) {
      messages.push(message);
    }

    for (const message of viruses) {
      messages.push(message);
    }

    return {
      is_spam: messages.length > 0,
      message:
        messages.length === 0 ? 'Not detected as spam.' : messages.join(' '),
      results: {
        // classifier prediction
        classification,
        phishing: phishing.messages,
        executables,
        arbitrary,
        nsfw,
        toxicity,
        viruses
      },
      links: phishing.links,
      ...(this.config.debug ? { tokens, mail } : {})
    };
  }
}

module.exports = SpamScanner;
