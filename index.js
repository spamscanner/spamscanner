const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const FileType = require('file-type');
const Url = require('url-parse');
const fileExtension = require('file-extension');
const getUrls = require('get-urls');
const i18nLocales = require('i18n-locales');
const isBuffer = require('is-buffer');
const isSANB = require('is-string-and-not-blank');
const isValidPath = require('is-valid-path');
const mime = require('mime-types');
const natural = require('natural');
const parseDomain = require('parse-domain');
// eslint-disable-next-line node/no-deprecated-api
const punycode = require('punycode');
const striptags = require('striptags');
const universalify = require('universalify');
const validator = require('validator');
const { Iconv } = require('iconv');
const { parse } = require('node-html-parser');
const { simpleParser } = require('mailparser');

const loadClassifier = promisify(natural.BayesClassifier.load);
const readFile = promisify(fs.readFile);
const issues = 'https://github.com/spamscanner/spamscanner/issues/new';
const locales = i18nLocales.map(l => l.toLowerCase());

// <https://kb.smarshmail.com/Article/23567>
const executables = require('./executables.json');

class SpamScanner {
  constructor(config) {
    this.config = {
      // <https://nodemailer.com/extras/mailparser/>
      simpleParser: {
        Iconv
      },
      // <https://github.com/NaturalNode/natural#bayesian-and-logistic-regression>
      classifier: path.join(__dirname, 'classifier.json'),
      // <https://github.com/sindresorhus/get-urls#options>
      getUrls: {
        requireSchemeOrWww: false
      },
      // default locale validated against i18n-locales
      locale: 'en',
      // we recommend to use axe/cabin, see https://cabinjs.com
      logger: console,
      ...config
    };

    this.classifier = false;

    this.getTokensAndMailFromSource = universalify.fromPromise(
      this.getTokensAndMailFromSource.bind(this)
    );
    this.getPhishingResults =
      this.getPhishingResults.bind(this);
    // this.getNSFWResuls = universalify.fromPromise(this.getNSFWResults.bind(this));
    this.getExecutableResults = universalify.fromPromise(
      this.getExecutableResults.bind(this)
    );
    this.scan = universalify.fromPromise(this.scan.bind(this));
    this.getTokens = this.getTokens.bind(this);
    this.parseLocale = this.parseLocale.bind(this);

    if (!locales.includes(this.parseLocale(this.config.locale)))
      throw new Error(
        `Locale of ${this.config.locale} was not valid according to locales list`
      );
  }

  async load(classifier) {
    this.classifier = await loadClassifier(
      classifier || this.config.classifier
    );
    return this;
  }

  parseLocale(locale) {
    return locale
      .toLowerCase()
      .split('-')[0]
      .split('_')[0];
  }

  // <https://blog.logrocket.com/natural-language-processing-for-node-js/>
  // <https://github.com/NaturalNode/natural#stemmers>
  // eslint-disable-next-line complexity
  getTokens(str, locale, isHTML = false) {
    // parse HTML for <html> tag with lang attr
    // otherwise if that wasn't found then look for this
    // <meta http-equiv="Content-Language" content="en-us">

    if (!locale && isHTML) {
      const root = parse(str);

      const metas = root.querySelectorAll('meta');

      for (const meta of metas) {
        if (
          meta.getAttribute('http-equiv') === 'Content-Language' &&
          meta.getAttribute('content') &&
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
          html.getAttribute('lang') &&
          locales.includes(this.parseLocale(html.getAttribute('lang')))
        )
          locale = this.parseLocale(html.getAttribute('lang'));
      }
    }

    locale = this.parseLocale(locale || this.config.locale);

    if (!locales.includes(locale)) {
      this.config.logger.debug(
        `Locale ${locale} was not valid and will use default`
      );
      locale = this.parseLocale(this.config.locale);
    }

    let stemmer;
    switch (locale) {
      case 'nl':
        stemmer = natural.PorterStemmerNl;
        break;
      case 'fa':
        stemmer = natural.PorterStemmerFa;
        break;
      case 'fr':
        stemmer = natural.PorterStemmerFr;
        break;
      case 'id':
      case 'in':
        stemmer = natural.StemmerId;
        break;
      case 'it':
        stemmer = natural.PorterStemmerIt;
        break;
      case 'jp':
        stemmer = natural.StemmerJa;
        break;
      case 'no':
        stemmer = natural.PorterStemmerNo;
        break;
      case 'pt':
        stemmer = natural.PorterStemmerPt;
        break;
      case 'ru':
        stemmer = natural.PorterStemmerRu;
        break;
      case 'sv':
        stemmer = natural.PorterStemmerSv;
        break;
      default:
        stemmer = natural.PorterStemmer;
    }

    return stemmer.tokenizeAndStem(isHTML ? striptags(str) : str);
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
      for (const link of getUrls(mail.html, this.config.getUrls)) {
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
      for (const link of getUrls(mail.text, this.config.getUrls)) {
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

    // TODO: if any <a> or normal links have an executable

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
        'Classifier not loaded, you must run `scanner.load()` before calling `scanner.scan()`'
      );

    const { tokens, mail } = await this.getTokensAndMailFromSource(str);

    const [
      classification,
      classifications,
      phishing,
      // nsfw,
      executables
    ] = await Promise.all([
      Promise.resolve(this.classifier.classify(tokens)),
      Promise.resolve(this.classifier.getClassifications(tokens)),
      Promise.resolve(this.getPhishingResults(mail)),
      // Promise.resolve(this.getNSFWResults(mail)),
      this.getExecutableResults(mail)
    ]);

    const messages = [];

    if (classification === 'spam')
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
        classification,
        classifications,
        phishing,
        // nsfw,
        executables,
        tokens,
        mail
      }
    };
  }
}

module.exports = SpamScanner;
