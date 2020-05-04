const fs = require('fs');
const { promisify } = require('util');

const FileType = require('file-type');
const NaiveBayes = require('naivebayes');
const RE2 = require('re2');
const Url = require('url-parse');
const contractions = require('expand-contractions');
const emailRegex = require('email-regex');
const escapeStringRegexp = require('escape-string-regexp');
const fileExtension = require('file-extension');
const getSymbolFromCurrency = require('currency-symbol-map');
const i18nLocales = require('i18n-locales');
const isBuffer = require('is-buffer');
const isSANB = require('is-string-and-not-blank');
const isValidPath = require('is-valid-path');
const mime = require('mime-types');
const natural = require('natural');
// locked to v2.x due to <https://github.com/peerigon/parse-domain/issues/106>
const parseDomain = require('parse-domain');
// eslint-disable-next-line node/no-deprecated-api
const punycode = require('punycode');
const sanitizeHtml = require('sanitize-html');
const snowball = require('node-snowball');
const striptags = require('striptags');
const sw = require('stopword');
const universalify = require('universalify');
const urlRegex = require('url-regex');
const validator = require('validator');
const { Iconv } = require('iconv');
const { codes } = require('currency-codes');
const { parse } = require('node-html-parser');
const { simpleParser } = require('mailparser');
const normalizeUrl = require('normalize-url');

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
const stopwordsJa = require('natural/lib/natural/util/stopwords_ja').words;
const stopwordsNl = require('natural/lib/natural/util/stopwords_nl').words;
const stopwordsNo = require('natural/lib/natural/util/stopwords_no').words;
const stopwordsPl = require('natural/lib/natural/util/stopwords_pl').words;
const stopwordsPt = require('natural/lib/natural/util/stopwords_pt').words;
const stopwordsRu = require('natural/lib/natural/util/stopwords_ru').words;
const stopwordsSv = require('natural/lib/natural/util/stopwords_sv').words;
const stopwordsZh = require('natural/lib/natural/util/stopwords_zh').words;

const issues = 'https://github.com/spamscanner/spamscanner/issues/new';
const locales = i18nLocales.map(l => l.toLowerCase());

const readFile = promisify(fs.readFile);

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

// <https://github.com/kevva/url-regex/issues/70
// <https://github.com/sindresorhus/get-urls/blob/master/index.js
function getUrls(text) {
  const urls = text.match(URL_REGEX) || [];
  const arr = [];
  for (const url of urls) {
    const normalized = normalizeUrl(url.trim().replace(/\.+$/, ''));
    if (!arr.includes(normalized)) arr.push(normalized);
  }

  return arr;
}

// <https://kb.smarshmail.com/Article/23567>
const executables = require('./executables.json');

class SpamScanner {
  constructor(config = {}) {
    this.config = {
      debug: process.env.NODE_ENV === 'test',
      // note that if you attempt to train an existing `scanner.classifier`
      // then you will need to re-use these, so we suggest you store them
      replacements: config.replacements || require('./replacements.json'),
      // <https://nodemailer.com/extras/mailparser/>
      // NOTE: `iconv` package's Iconv cannot be used in worker threads
      // AND it can not also be shared in worker threads either (e.g. cloned)
      // <https://github.com/bnoordhuis/node-iconv/issues/211>
      // BUT we MUST use it because otherwise emails won't get parsed
      simpleParser: { Iconv },
      // <https://github.com/NaturalNode/natural#bayesian-and-logistic-regression>
      classifier: config.classifier || require('./classifier.json'),
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
      ...config
    };

    this.classifier = false;

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

    if (!locales.includes(this.parseLocale(this.config.locale)))
      throw new Error(
        `Locale of ${this.config.locale} was not valid according to locales list.`
      );
  }

  async load(classifier) {
    classifier = classifier || this.config.classifier;

    this.classifier =
      typeof classifier === 'object'
        ? classifier
        : typeof classifier === 'string'
        ? isValidPath(classifier)
          ? require(classifier)
          : JSON.parse(classifier)
        : false;

    if (typeof classifier !== 'object')
      throw new Error('Classifier must be an Object');

    // TODO: we still need to limit vocabulary size
    // (especially since we don't filter out gibberish)
    // <https://github.com/surmon-china/naivebayes/issues/4>
    this.classifier = NaiveBayes.fromJson(this.classifier);
    // since we do tokenization ourselves
    this.classifier.tokenizer = function(tokens) {
      return tokens;
    };

    return this;
  }

  parseLocale(locale) {
    return locale
      .toLowerCase()
      .split('-')[0]
      .split('_')[0];
  }

  // <https://medium.com/analytics-vidhya/building-a-spam-filter-from-scratch-using-machine-learning-fc58b178ea56>
  // <https://towardsdatascience.com/empirical-analysis-on-email-classification-using-the-enron-dataset-19054d558697>
  // <https://blog.logrocket.com/natural-language-processing-for-node-js/>
  // <https://github.com/NaturalNode/natural#stemmers>
  // eslint-disable-next-line complexity
  getTokens(str, locale, isHTML = false) {
    //
    // parse HTML for <html> tag with lang attr
    // otherwise if that wasn't found then look for this
    // <meta http-equiv="Content-Language" content="en-us">
    //
    //
    // NOTE: we shouldn't rely on parsing the locale from the metadata
    // nor from the header, instead we should utilize the metadata passed
    // and if none exist, then we should use something like:
    // - <https://github.com/wooorm/franc>
    // - <https://github.com/FGRibreau/node-language-detect>
    //
    // It may be necessary to have a whitelisted dictionary of all words
    // in English (e.g. via WordNet DB) and then run it through
    // Google Translate using the `mandarin` package I made
    //
    //
    if (!locale && isHTML) {
      const root = parse(str);

      const metas = root.querySelectorAll('meta');

      for (const meta of metas) {
        if (
          meta.getAttribute('http-equiv') === 'Content-Language' &&
          isSANB(meta.getAttribute('content')) &&
          locales.includes(this.parseLocale(meta.getAttribute('content')))
        ) {
          locale = this.parseLocale(meta.getAttribute('content'));
          break;
        }
      }

      if (!locale) {
        const html = root.querySelector('html');
        if (
          html &&
          isSANB(html.getAttribute('lang')) &&
          locales.includes(this.parseLocale(html.getAttribute('lang')))
        )
          locale = this.parseLocale(html.getAttribute('lang'));
      }
    }

    locale = this.parseLocale(isSANB(locale) ? locale : this.config.locale);

    if (!locales.includes(locale)) {
      this.config.logger.debug(
        `Locale ${locale} was not valid and will use default`
      );
      locale = this.parseLocale(this.config.locale);
    }

    // <https://github.com/hthetiot/node-snowball#supported-language-second-argument>
    // <https://github.com/NaturalNode/natural#tokenizers>
    let tokenizer = aggressiveTokenizer;
    let stopwords = stopwordsEn;
    let language = 'english';
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
        break;
      case 'zh':
        language = 'chinese';
        stopwords = stopwordsZh;
        break;
      default:
    }

    if (isHTML) str = sanitizeHtml(str, this.config.sanitizeHtml);

    str = striptags(str)
      // replace newlines
      .replace(NEWLINE_REGEX, ' ')
      // handle initialism(e.g. "AFK" -> "abbrev$crypto$afk")
      .replace(
        INITIALISM_REGEX,
        s => `${this.config.replacements.initialism}${s}`
      )
      // handle abbreviations (e.g. "u.s." -> "abbrev$crypto$us")
      // (note we have to replace the periods here)
      .replace(
        ABBREVIATION_REGEX,
        s => `${this.config.replacements.abbreviation}${s.split('.').join('')}`
      )
      // replace email addresses
      .replace(EMAIL_REGEX, ` ${this.config.replacements.email} `)
      // replace urls
      .replace(URL_REGEX, ` ${this.config.replacements.url} `)
      // replace numbers
      .replace(NUMBER_REGEX, ` ${this.config.replacements.number} `)
      // replace currency
      .replace(CURRENCY_REGEX, ` ${this.config.replacements.currency} `);

    // expand contractions so "they're" -> [ they, are ] vs. [ they, re ]
    // <https://github.com/NaturalNode/natural/issues/533>
    if (locale === 'en') str = contractions.expand(str);

    // whitelist exclusions
    const whitelistedWords = [
      this.config.replacements.url,
      this.config.replacements.email,
      this.config.replacements.number,
      this.config.replacements.currency
    ];

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
        tokenizer.tokenize(str.toLowerCase()).map(token => {
          // whitelist words from being stemmed (safeguard)
          if (
            whitelistedWords.includes(token) ||
            token.startsWith(this.config.replacements.initialism) ||
            token.startsWith(this.config.replacements.abbrevation)
          )
            return token;
          // TODO: we should pass third arg wih charset of parsed html or text (?)
          // <https://github.com/hthetiot/node-snowball#supported-encoding-third-argument>
          return snowball.stemword(token, language);
        }),
        sw[locale]
      )
      .filter(t => !stopwords.includes(t));

    return tokens;
  }

  // TODO: we may also want to tokenize other mail headers (e.g. from/to/cc)
  async getTokensAndMailFromSource(str) {
    let source = str;
    if (isBuffer(str)) source = str.toString();
    else if (typeof str === 'string' && isValidPath(str))
      source = await readFile(str);

    const tokens = [];
    const mail = await simpleParser(source, this.config.simpleParser);

    if (isSANB(mail.subject)) {
      for (const token of this.getTokens(
        mail.subject,
        mail.headers.get('content-language')
      )) {
        tokens.push(token);
      }
    }

    if (isSANB(mail.html)) {
      for (const token of this.getTokens(
        mail.html,
        mail.headers.get('content-language'),
        true
      )) {
        tokens.push(token);
      }
    }

    if (isSANB(mail.text)) {
      for (const token of this.getTokens(
        mail.text,
        mail.headers.get('content-language')
      )) {
        tokens.push(token);
      }
    }

    return { tokens, mail };
  }

  // TODO: check against openphish and phishtank
  getPhishingResults(mail) {
    const messages = [];
    const links = [];

    // parse <a> tags with different org domain in text vs the link
    if (isSANB(mail.html)) {
      for (const link of getUrls(
        sanitizeHtml(mail.html, this.config.sanitizeHtml)
      )) {
        links.push(link);
      }

      const root = parse(mail.html);
      const anchors = root.querySelectorAll('a');
      for (const anchor of anchors) {
        const textContent = striptags(anchor.innerHTML).trim();
        const href = anchor.getAttribute('href');
        if (
          isSANB(textContent) &&
          validator.isURL(textContent) &&
          isSANB(href) &&
          validator.isURL(href)
        ) {
          const innerTextUrl = new Url(textContent, {});
          const anchorUrl = new Url(href);
          const innerTextUrlToASCII = punycode.toASCII(innerTextUrl.hostname);
          const anchorUrlToASCII = punycode.toASCII(anchorUrl.hostname);
          const str = `Anchor link with href of "${href}" and inner text value of "${textContent}"`;
          if (innerTextUrlToASCII.startsWith('xn--'))
            messages.push(
              `${str} has possible IDN homograph attack from inner text hostname.`
            );
          if (anchorUrlToASCII.startsWith('xn--'))
            messages.push(
              `${str} has possible IDN homograph attack from anchor hostname.`
            );
          const parsedInnerTextDomain = parseDomain(innerTextUrlToASCII);
          const parsedAnchorUrlDomain = parseDomain(anchorUrlToASCII);
          if (
            `${parsedInnerTextDomain.domain}.${parsedInnerTextDomain.tld}` !==
            `${parsedAnchorUrlDomain.domain}.${parsedAnchorUrlDomain.tld}`
          )
            messages.push(
              `${str} did not have links with matching organization-level domains.`
            );
        }
      }
    }

    // <https://docs.apwg.org/ecrimeresearch/2018/5359941.pdf>
    // <https://www.wandera.com/punycode-attacks/>
    // parse the mail.html and mail.text for links (e.g. w/o <a>)
    if (isSANB(mail.text)) {
      for (const link of getUrls(mail.text)) {
        links.push(link);
      }
    }

    for (const link of links) {
      const url = new Url(link, {});
      const toASCII = punycode.toASCII(url.hostname);
      if (toASCII.startsWith('xn--'))
        messages.push(
          `Possible IDN homograph attack from link of "${link}" with ASCII-converted hostname of "${toASCII}".`
        );
    }

    if (messages.length > 0)
      messages.push(`Phishing whitelist requests can be filed at ${issues}.`);

    return messages;
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
      mail.attachments.map(async attachment => {
        if (isBuffer(attachment.content)) {
          try {
            const fileType = await FileType.fromBuffer(attachment.content);
            if (fileType && fileType.ext && executables.includes(fileType.ext))
              messages.push(
                `Attachment's "magic number" indicated it was a dangerous executable with a ".${fileType.ext}" extension.`
              );
          } catch (err) {
            this.config.logger.error(err);
          }
        }

        if (isSANB(attachment.filename)) {
          // run punycode on file name as well since file names can be spoofed
          const filename = punycode.toASCII(attachment.filename.split('?')[0]);
          const ext = fileExtension(filename);
          if (ext && executables.includes(ext))
            messages.push(
              `Attachment's file name indicated it was a dangerous executable with a ".${ext}" extension.`
            );
        }

        if (isSANB(attachment.contentType)) {
          const ext = mime.extension(attachment.contentType);
          if (isSANB(ext) && executables.includes(ext))
            messages.push(
              `Attachment's Content-Type was a dangerous executable with a ".${ext}" extension.`
            );
        }
      })
    );

    if (messages.length > 0)
      messages.push(
        `Executable file whitelist requests can be filed at ${issues}.  You may want to re-send your attachment in a compressed archive format (e.g. a ZIP file).`
      );

    return messages;
  }

  async scan(str) {
    if (!this.classifier)
      throw new Error(
        'Classifier not loaded, you must run `scanner.load()` before calling `scanner.scan()`.'
      );

    const { tokens, mail } = await this.getTokensAndMailFromSource(str);

    const [
      classification,
      phishing,
      // nsfw,
      executables
    ] = await Promise.all([
      Promise.resolve(this.classifier.categorize(tokens, true)),
      Promise.resolve(this.getPhishingResults(mail)),
      // Promise.resolve(this.getNSFWResults(mail)),
      this.getExecutableResults(mail)
    ]);

    const messages = [];

    if (classification.category === 'spam')
      messages.push('Spam detected from Naive Bayesian classifier.');

    for (const message of phishing) {
      messages.push(message);
    }

    // for (const message of nsfw) {
    //   messages.push(message);
    // }

    for (const message of executables) {
      messages.push(message);
    }

    return {
      is_spam: messages.length > 0,
      message:
        messages.length === 0 ? 'Not detected as spam.' : messages.join(' '),
      results: {
        // classifier prediction
        // 0 = ham
        // 1 = spam
        classification,
        phishing,
        // nsfw,
        executables
      },
      ...(this.config.debug ? { tokens, mail } : {})
    };
  }
}

module.exports = SpamScanner;
