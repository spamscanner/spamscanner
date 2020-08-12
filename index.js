const dns = require('dns');
const fs = require('fs');
const { promisify } = require('util');

// eslint-disable-next-line node/no-deprecated-api
const punycode = require('punycode');

const ClamScan = require('clamscan');
const FileType = require('file-type');
const NaiveBayes = require('@ladjs/naivebayes');
const RE2 = require('re2');
const bitcoinRegex = require('bitcoin-regex');
const contractions = require('expand-contractions');
const creditCardRegex = require('credit-card-regex');
const debug = require('debug')('spamscanner');
const emailRegex = require('email-regex');
const emojiPatterns = require('emoji-patterns');
const escapeStringRegexp = require('escape-string-regexp');
const fileExtension = require('file-extension');
const floatingPointRegex = require('floating-point-regex');
const franc = require('franc');
const getSymbolFromCurrency = require('currency-symbol-map');
const hasha = require('hasha');
const hexaColorRegex = require('hexa-color-regex');
const i18nLocales = require('i18n-locales');
const intoStream = require('into-stream');
const isBuffer = require('is-buffer');
const isSANB = require('is-string-and-not-blank');
const isStream = require('is-stream');
const isValidPath = require('is-valid-path');
const macRegex = require('mac-regex');
const macosVersion = require('macos-version');
const mime = require('mime-types');
const natural = require('natural');
const normalizeUrl = require('normalize-url');
const phoneRegex = require('phone-regex');
const sanitizeHtml = require('sanitize-html');
const snowball = require('node-snowball');
const striptags = require('striptags');
const superagent = require('superagent');
const sw = require('stopword');
const toEmoji = require('gemoji/name-to-emoji');
const universalify = require('universalify');
const urlRegex = require('url-regex');
const validator = require('validator');
const { Iconv } = require('iconv');
const { codes } = require('currency-codes');
const { fromUrl, NO_HOSTNAME } = require('parse-domain');
const { parse } = require('node-html-parser');
const { simpleParser } = require('mailparser');

const { PorterStemmerFa, StemmerId, StemmerJa } = natural;

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
const stopwordsIt = require('natural/lib/natural/util/stopwords_it').words;
// <https://github.com/NaturalNode/natural/issues/543>
const stopwordsJa = require('natural/lib/natural/util/stopwords_ja');
const stopwordsNl = require('natural/lib/natural/util/stopwords_nl').words;
const stopwordsNo = require('natural/lib/natural/util/stopwords_no').words;
const stopwordsPl = require('natural/lib/natural/util/stopwords_pl').words;
const stopwordsPt = require('natural/lib/natural/util/stopwords_pt').words;
const stopwordsRu = require('natural/lib/natural/util/stopwords_ru').words;
const stopwordsSv = require('natural/lib/natural/util/stopwords_sv').words;
const stopwordsZh = require('natural/lib/natural/util/stopwords_zh').words;

// <https://stackoverflow.com/a/41353282>
// <https://www.ietf.org/rfc/rfc3986.txt>
const ENDING_RESERVED_REGEX = new RE2(
  `[${escapeStringRegexp(":/?#[]@!$&'()*+,;=")}]+$`
);

const PKG = require('./package.json');

const VOCABULARY_LIMIT = require('./vocabulary-limit');

const ISO_CODE_MAPPING = require('./iso-code-mapping');

// <https://kb.smarshmail.com/Article/23567>
const EXECUTABLES = require('./executables');

const REPLACEMENT_WORDS = require('./replacement-words');

const locales = new Set(i18nLocales.map((l) => l.toLowerCase()));

const readFile = promisify(fs.readFile);

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
const ANCHOR_REGEX = new RE2(/<a.*?>.*?<\/a>/gi);

// <https://github.com/kevva/url-regex/pull/35#issuecomment-672754025>
const BRACKET_REGEX = new RE2(/^[[\]()]*|[[\]()]*$/g);

// <https://github.com/mathiasbynens/emoji-regex/issues/59#issuecomment-640418649>
const EMOJI_REGEX = new RE2(emojiPatterns.Emoji_All, 'gu');
const FLOATING_POINT_REGEX = new RE2(floatingPointRegex());
const CC_REGEX = new RE2(creditCardRegex());
const PHONE_REGEX = new RE2(phoneRegex());
const BITCOIN_REGEX = new RE2(bitcoinRegex());
const MAC_REGEX = new RE2(macRegex());
const HEXA_COLOR_REGEX = new RE2(hexaColorRegex());

// <https://github.com/NaturalNode/natural/issues/523#issuecomment-623287047>
// <https://github.com/yoshuawuyts/newline-remove>
const NEWLINE_REGEX = new RE2(/\r\n|\n|\r/gm);
// <https://stackoverflow.com/a/5917217>
const NUMBER_REGEX = new RE2(/\d[\d,.]*/g);
const ALPHA_REGEX = new RE2(/^[a-z]+$/i);
const URL_REGEX = new RE2(urlRegex({ exact: false, strict: false }));
const EMAIL_REGEX = new RE2(emailRegex({ exact: false }));
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
    !ALPHA_REGEX.test(symbol)
  )
    currencySymbols.push(escapeStringRegexp(symbol));
}

const CURRENCY_REGEX = new RE2(new RegExp(currencySymbols.join('|'), 'g'));

// <https://spamassassin.apache.org/gtube/>
// <https://spamassassin.apache.org/gtube/gtube.txt>
const GTUBE =
  'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';

const TOKEN_HEADERS = ['subject', 'from', 'to', 'cc', 'bcc', 'html', 'text'];

class SpamScanner {
  constructor(config = {}) {
    this.config = {
      debug: process.env.NODE_ENV === 'test',
      // note that if you attempt to train an existing `scanner.classifier`
      // then you will need to re-use these, so we suggest you store them
      replacements: config.replacements || require('./replacements'),
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
      classifier: config.classifier || require('./get-classifier'),
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
      issues: PKG.bugs.url,
      dnsEndpoint: 'https://family.cloudflare-dns.com/dns-query',
      userAgent: `${PKG.name}/${PKG.version}`,
      clamscan: {
        clamdscan: {
          socket: macosVersion.isMacOS
            ? '/tmp/clamd.socket'
            : '/var/run/clamav/clamd.ctl'
        }
      },
      franc: {
        minLength: 100,
        // we can only support languages available
        // in stopwords and natural's tokenizer methods
        only: Object.keys(ISO_CODE_MAPPING)
      },
      hasha: {
        algorithm: 'sha256'
      },
      vocabularyLimit: VOCABULARY_LIMIT,
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

    this.clamscan = new ClamScan();

    this.getTokensAndMailFromSource = universalify.fromPromise(
      this.getTokensAndMailFromSource.bind(this)
    );
    this.getPhishingResults = this.getPhishingResults.bind(this);
    // this.getNSFWResuls = universalify.fromPromise(this.getNSFWResults.bind(this));
    this.getExecutableResults = universalify.fromPromise(
      this.getExecutableResults.bind(this)
    );
    this.scan = universalify.fromPromise(this.scan.bind(this));
    this.getTokens = this.getTokens.bind(this);
    this.parseLocale = this.parseLocale.bind(this);
    this.getNormalizedUrl = this.getNormalizedUrl.bind(this);
    this.getUrls = this.getUrls.bind(this);
    this.isCloudflareBlocked = this.isCloudflareBlocked.bind(this);
    this.getArbitraryResults = this.getArbitraryResults.bind(this);
    this.getVirusResults = universalify.fromPromise(
      this.getVirusResults.bind(this)
    );
    this.getHostname = this.getHostname.bind(this);
    this.getClassification = this.getClassification.bind(this);

    if (!locales.has(this.parseLocale(this.config.locale)))
      throw new Error(
        `Locale of ${this.config.locale} was not valid according to locales list.`
      );
  }

  getHostname(link) {
    // uses `new Url` (e.g. it adds http:// if it does not exist)
    const url = fromUrl(punycode.toUnicode(link));
    if (url === NO_HOSTNAME) throw new Error(`${link} was invalid`);
    return url;
  }

  getClassification(tokens) {
    return Promise.resolve(this.classifier.categorize(tokens, true));
  }

  async getVirusResults(mail) {
    const messages = [];

    if (!Array.isArray(mail.attachments)) return messages;

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
            const {
              is_infected: isInfected,
              viruses
            } = await clamscan.scan_stream(stream);
            const name = isSANB(attachment.filename)
              ? `"${attachment.filename}"`
              : `#${i + 1}`;
            if (isInfected)
              messages.push(
                `Attachment ${name} was infected with "${viruses}".`
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

    if (isSANB(mail.html)) {
      // gtube
      if (mail.html.includes(GTUBE)) gtube = true;
    }

    if (isSANB(mail.text)) {
      // gtube
      if (!gtube && mail.text.includes(GTUBE)) gtube = true;
    }

    if (gtube)
      messages.push(
        'Message detected to contain the GTUBE test from <https://spamassassin.apache.org/gtube/>.'
      );

    return messages;
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
    // (which would assume you are using 1.1.1.3 and 1.0.0.3)
    //
    try {
      const response = await superagent
        .get(this.config.dnsEndpoint)
        .query({
          name,
          type: 'A'
        })
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
        this.config.logger.error(err);
        // return true if there is an error with DNS lookups
        return true;
      }
    }
  }

  //
  // due to this issue and the fact that PhishTank adds invalid URL's
  // we have to implement our own workaround to normalize a valid/invalid URL
  // <https://github.com/sindresorhus/normalize-url/issues/111>
  //
  getNormalizedUrl(url) {
    url = url.trim().replace(/\.+$/, '').toLowerCase();
    let normalized = url;
    try {
      normalized = normalizeUrl(url, normalizeUrlOptions);
    } catch (err) {
      debug(err);
      // <https://stackoverflow.com/questions/6680825/return-string-without-trailing-slash#comment11853012_6680877>
      normalized = url
        .replace('http://', '')
        .replace('https://', '')
        .replace(/\/+$/, '');
    }

    const hostname = fromUrl(normalized);
    if (hostname === NO_HOSTNAME) {
      debug('No hostname', { url, normalized });
      return normalized;
    }

    try {
      const object = new URL(
        `http://${punycode.toUnicode(hostname)}${normalized.slice(
          hostname.length
        )}`
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
    const urls = text.replace(NEWLINE_REGEX, ' ').match(URL_REGEX) || [];
    const array = [];
    for (const url of urls) {
      //
      // NOTE: we manually must strip starting and closing brackets and parens
      // <https://github.com/kevva/url-regex/pull/35#issuecomment-672754025>
      const normalized = this.getNormalizedUrl(url.replace(BRACKET_REGEX, ''));
      if (!array.includes(normalized)) array.push(normalized);
    }

    return array;
  }

  // TODO: https://github.com/geerlingguy/ansible-role-clamav
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

    const replacementRegexes = [];
    for (const key of Object.keys(this.config.replacements)) {
      replacementRegexes.push(
        escapeStringRegexp(this.config.replacements[key])
      );
    }

    const REPLACEMENTS_REGEX = new RE2(
      new RegExp(replacementRegexes.join('|'), 'g')
    );

    string = striptags(string)
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
    const detectedLanguage = franc(string, this.config.franc);
    if (
      detectedLanguage !== 'und' &&
      isSANB(ISO_CODE_MAPPING[detectedLanguage])
    )
      locale = ISO_CODE_MAPPING[detectedLanguage];

    locale = this.parseLocale(isSANB(locale) ? locale : this.config.locale);

    if (!locales.has(locale)) {
      debug(`Locale ${locale} was not valid and will use default`);
      locale = this.parseLocale(this.config.locale);
    }

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
        stemword = PorterStemmerFa.stem;
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
        stemword = StemmerId.stem;
        break;
      case 'it':
        language = 'italian';
        tokenizer = aggressiveTokenizerIt;
        stopwords = stopwordsIt;
        break;
      case 'ja':
        tokenizer = tokenizerJa;
        stopwords = stopwordsJa;
        stemword = StemmerJa.prototype.stemKatakana;
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

    if (stemword === 'default')
      stemword = (t) => snowball.stemword(t, language);

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
        )

        // replace email addresses
        .replace(EMAIL_REGEX, ` ${this.config.replacements.email} `)

        // replace urls
        .replace(URL_REGEX, ` ${this.config.replacements.url} `)

        // replace numbers
        // https://github.com/regexhq/floating-point-regex
        .replace(FLOATING_POINT_REGEX, ` ${this.config.replacements.number} `)
        .replace(NUMBER_REGEX, ` ${this.config.replacements.number} `)

        // replace currency
        .replace(CURRENCY_REGEX, ` ${this.config.replacements.currency} `);

    // expand contractions so "they're" -> [ they, are ] vs. [ they, re ]
    // <https://github.com/NaturalNode/natural/issues/533>
    if (locale === 'en') string = contractions.expand(string);

    // whitelist exclusions
    const whitelistedWords = Object.values(this.config.replacements);

    //
    // Future research:
    // - <https://github.com/NaturalNode/natural/issues/523>
    // - <https://github.com/mplatt/fold-to-ascii>
    // - <https://github.com/andrewrk/node-diacritics>)
    // - <https://www.elastic.co/guide/en/elasticsearch/reference/current/analysis-word-delimiter-tokenfilter.html>
    // - <https://www.elastic.co/guide/en/elasticsearch/reference/master/analysis-elision-tokenfilter.html>
    //
    const tokens = sw
      .removeStopwords(
        tokenizer.tokenize(string.toLowerCase()).map((token) => {
          // whitelist words from being stemmed (safeguard)
          if (
            whitelistedWords.includes(token) ||
            token.startsWith(this.config.replacements.initialism) ||
            token.startsWith(this.config.replacements.abbrevation)
          )
            return token;

          if (!stemword) {
            this.config.logger.warn('No stemword function', {
              token,
              language
            });
            return token;
          }

          try {
            return stemword(token);
          } catch (err) {
            this.config.logger.error(err, { token, language });
            return token;
          }
        }),
        sw[locale]
      )
      .filter((t) => !stopwords.includes(t));

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
      source = await readFile(string);

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
    const messages = [];

    //
    // NOTE: all links pushed are lowercased
    //
    const links = [];

    // parse <a> tags with different org domain in text vs the link
    if (isSANB(mail.html)) {
      //
      // NOTE: It would be interested to see if Gmail is prone to an injection attack
      // whereas elements they do not support get stripped out and then the returning
      // elements concatenate to form a URL which is malicious or phishing
      //
      for (const link of this.getUrls(striptags(mail.html))) {
        if (!links.includes(link)) links.push(link);
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
      const matches = mail.html.replace(NEWLINE_REGEX, ' ').match(ANCHOR_REGEX);

      if (Array.isArray(matches) && matches.length > 0) {
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

          const textContent = striptags(anchor.innerHTML).trim();
          const href = anchor.getAttribute('href');
          const hasHref = isSANB(href) && validator.isURL(href);

          if (hasHref) {
            // add the link if we haven't already
            const normalized = this.getNormalizedUrl(href);
            // eslint-disable-next-line max-depth
            if (!links.includes(normalized)) links.push(normalized);
          }

          if (
            isSANB(textContent) &&
            validator.isURL(textContent) &&
            isSANB(href) &&
            validator.isURL(href)
          ) {
            const innerTextUrlHostname = this.getHostname(textContent);
            const anchorUrlHostname = this.getHostname(href);
            const innerTextUrlHostnameToASCII = punycode.toASCII(
              innerTextUrlHostname
            );
            const anchorUrlHostnameToASCII = punycode.toASCII(
              anchorUrlHostname
            );
            const string = `Anchor link with href of "${href}" and inner text value of "${textContent}"`;
            // eslint-disable-next-line max-depth
            if (innerTextUrlHostnameToASCII.startsWith('xn--'))
              messages.push(
                `${string} has possible IDN homograph attack from inner text hostname.`
              );
            // eslint-disable-next-line max-depth
            if (anchorUrlHostnameToASCII.startsWith('xn--'))
              messages.push(
                `${string} has possible IDN homograph attack from anchor hostname.`
              );
          }
        }
      }
    }

    // <https://docs.apwg.org/ecrimeresearch/2018/5359941.pdf>
    // <https://www.wandera.com/punycode-attacks/>
    // parse the mail.html and mail.text for links (e.g. w/o <a>)
    if (isSANB(mail.text)) {
      for (const link of this.getUrls(mail.text)) {
        if (!links.includes(link)) links.push(link);
      }
    }

    for (const link of links) {
      const urlHostname = this.getHostname(link);
      const toASCII = punycode.toASCII(urlHostname);
      if (toASCII.startsWith('xn--'))
        messages.push(
          `Possible IDN homograph attack from link of "${link}" with punycode converted hostname of "${toASCII}".`
        );
    }

    // check against Cloudflare malware/phishing/adult DNS lookup
    // if it returns `0.0.0.0` it means it was flagged
    await Promise.all(
      links.map(async (link) => {
        try {
          const urlHostname = this.getHostname(link);
          const toASCII = punycode.toASCII(urlHostname);
          const message = `Link hostname of "${toASCII}" was detected by Cloudflare to contain malware, phishing, and/or adult content.`;
          if (messages.includes(message)) return;
          const isBlocked = await this.isCloudflareBlocked(toASCII);
          if (isBlocked && !messages.includes(message)) messages.push(message);
        } catch (err) {
          this.config.logger.error(err);
        }
      })
    );

    if (messages.length > 0)
      messages.push(
        `Phishing whitelist requests can be filed at ${this.config.issues}.`
      );

    return { messages, links };
  }

  // getNSFWResults() {
  //   return false;
  // }

  async getExecutableResults(mail) {
    const messages = [];

    if (!Array.isArray(mail.attachments)) return messages;

    // NOTE: we don't inspect <a> or normal links in the message html/text

    // if any attachments have an executable
    await Promise.all(
      mail.attachments.map(async (attachment) => {
        if (isBuffer(attachment.content)) {
          try {
            const fileType = await FileType.fromBuffer(attachment.content);
            if (fileType && fileType.ext && EXECUTABLES.includes(fileType.ext))
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
          const ext = fileExtension(filename);
          if (ext && EXECUTABLES.includes(ext))
            messages.push(
              `Attachment's file name indicated it was a dangerous executable with a ".${ext}" extension.`
            );
        }

        if (isSANB(attachment.contentType)) {
          const ext = mime.extension(attachment.contentType);
          if (isSANB(ext) && EXECUTABLES.includes(ext))
            messages.push(
              `Attachment's Content-Type was a dangerous executable with a ".${ext}" extension.`
            );
        }
      })
    );

    if (messages.length > 0)
      messages.push(
        `Executable file whitelist requests can be filed at ${this.config.issues}.  You may want to re-send your attachment in a compressed archive format (e.g. a ZIP file).`
      );

    return messages;
  }

  async scan(string) {
    const { tokens, mail } = await this.getTokensAndMailFromSource(string);

    const [
      classification,
      phishing,
      // nsfw,
      executables,
      arbitrary,
      viruses
    ] = await Promise.all([
      this.getClassification(tokens),
      this.getPhishingResults(mail),
      // Promise.resolve(this.getNSFWResults(mail)),
      this.getExecutableResults(mail),
      this.getArbitraryResults(mail),
      this.getVirusResults(mail)
    ]);

    const messages = [];

    if (classification && classification.category === 'spam')
      messages.push('Spam detected from Naive Bayesian classifier.');

    for (const message of phishing.messages) {
      messages.push(message);
    }

    // for (const message of nsfw) {
    //   messages.push(message);
    // }

    for (const message of executables) {
      messages.push(message);
    }

    for (const message of arbitrary) {
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
        // nsfw,
        executables,
        arbitrary,
        viruses
      },
      links: phishing.links,
      ...(this.config.debug ? { tokens, mail } : {})
    };
  }
}

module.exports = SpamScanner;
