# spamscanner

[![build status](https://img.shields.io/travis/com/spamscanner/spamscanner.svg)](https://travis-ci.com/spamscanner/spamscanner)
[![code coverage](https://img.shields.io/codecov/c/github/spamscanner/spamscanner.svg)](https://codecov.io/gh/spamscanner/spamscanner)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/spamscanner/spamscanner.svg)](LICENSE)
[![npm downloads](https://img.shields.io/npm/dt/spamscanner.svg)](https://npm.im/spamscanner)

> SpamScanner - The Best Anti-Spam Scanning Service and Anti-Spam API


## Table of Contents

* [Foreword](#foreword)
* [Features](#features)
  * [Spam Content Detection](#spam-content-detection)
  * [Phishing Content Detection](#phishing-content-detection)
  * [Executable Link and Attachment Detection](#executable-link-and-attachment-detection)
* [Requirements](#requirements)
* [Install](#install)
* [Usage](#usage)
* [API](#api)
  * [`const scanner = new SpamScanner(options)`](#const-scanner--new-spamscanneroptions)
  * [`scanner.load(path)`](#scannerloadpath)
  * [`scanner.scan(source)`](#scannerscansource)
  * [`scanner.getTokensAndMailFromSource(source)`](#scannergettokensandmailfromsourcesource)
  * [`scanner.getPhishingResults(mail)`](#scannergetphishingresultsmail)
  * [`scanner.getExecutableResults(mail)`](#scannergetexecutableresultsmail)
  * [`scanner.getTokens(str, locale, isHTML = false)`](#scannergettokensstr-locale-ishtml--false)
  * [`scanner.parseLocale(locale)`](#scannerparselocalelocale)
* [Contributors](#contributors)
* [License](#license)


## Foreword

SpamScanner is a tool and service built by [@niftylettuce][niftylettuce] after hitting countless roadblocks with existing spam-detection solutions.  In other words, it's our current [plan][plan-for-spam] [spam][better-plan-for-spam].

Our goal is to build and utilize a scalable, performant, simple, easy to maintain, and powerful API for use in our service at [ForwardEmail.net][forward-email] to limit spam and provide other measures to prevent attacks on our users.

Initially we tried using [SpamAssassin][], and later evaluated [rspamd][] – but in the end we learned that all existing solutions (even ones besides these) are overtly complex, missing required features or documentation, incredibly challenging to configure; high-barrier to entry, or have proprietary storage backends (that could store and read your messages without your consent) that limit our scalability.

To us, we value privacy and the security of our data and users – specifically we have a "Zero-Tolerance Policy" on storing logs or metadata of any kind, whatsoever (see our [Privacy Policy][privacy-policy] for more on that).  None of these solutions honored this privacy policy (without removing essential spam-detection functionality), so we had to create our own tool – thus "SpamScanner" was born.

The solution we created provides several [Features](#features) and is completely configurable to your liking.  We hope you enjoy it, and help us to enhance it.  Contributors are welcome!


## Features

SpamScanner boasts several features to help reduce spam, phishing, and executable attacks.  We have plans for adding [NSFW image detection][nsfw] and [toxicity detection][toxicity] as well.

### Spam Content Detection

Provides an out of the box trained Naive Bayesian classifier (uses [naivebayes][] and [natural][] under the hood) is provided and sourced from hundreds of thousands of spam and ham emails.  This classifier relies upon tokenized and stemmed words (with respect to the language of the email as well) into two categories ("spam" and "ham").

### Phishing Content Detection

Robust phishing detection approach which prevents domain swapping, [IDN homograph attacks][homograph-attack], and more.

### Executable Link and Attachment Detection

Link and attachment detection techniques that checks links in the message, "Content-Type" headers, file extensions, [magic number][magic-number], and prevents [homograph attacks][homograph-attack] on file names – all against a list of [executable file extensions](executables.json).


## Requirements


## Install

[npm][]:

```sh
npm install spamscanner
```

[yarn][]:

```sh
yarn add spamscanner
```


## Usage

```js
const fs = require('fs');
const path = require('path');

const SpamScanner = require('spamscanner');

const scanner = new SpamScanner();

//
// NOTE: The `source` argument is the full raw email to be scanned
// and you can pass it as String, Buffer, or valid file path
//
const source = fs.readFileSync(
  path.join(__dirname, 'test', 'fixtures', 'spam.eml')
);

// async/await usage
(async () => {
  try {
    const results = await scanner.scan(source);
    console.log('results', results);
  } catch (err) {
    console.error(err);
  }
});

// then/catch usage
scanner
  .scan(source)
  .then(results => console.log('results', results))
  .catch(console.error);

// callback usage
scanner.scan(source, (err, results) => {
  if (err) return console.error(err);
  console.log('results', results);
});
```


## API

### `const scanner = new SpamScanner(options)`

The `SpamScanner` class accepts an optional `options` Object of options to configure the spam scanner instance being created.  It returns a new instance referred to commonly as a `scanner`.

We have configured the scanner defaults to utilize a default classifier, and sensible options for ensuring scanning works properly.

For a list of all options and their defaults, see the [index.js](index.js) file in the root of this repository.

### `scanner.load(path)`

Accepts an optional `path` (String) argument that is the file system path to the trained classifier data.  If you do not pass a `path` then it defaults to loading `./classifier.json` (the default out of the box classifier).

Note that **you must load the classifier into the scanner** with `scanner.load()` **BEFORE** you call `scanner.scan()` – otherwise an exception will be thrown with human-friendly error message.

This method returns a Promise that resolves with `scanner` (so it is chainable) when the classifier data is done loading.  You can also use this method with a second callback argument.

### `scanner.scan(source)`

> **NOTE:** This is most useful method of this API as it returns the results of a scanned message.

Accepts a required `source` (String, Buffer, or file path) argument which points to (or is) a complete and raw SMTP message (e.g. it includes headers and the full email).  Commonly this is known as an "eml" file type and contains the extension `.eml`, however you can pass a String or Buffer representation instead of a file path.

This method returns a Promise that resolves with a `results` Object when scanning is completed.  You can also use this method with a second callback argument.

The `results` are returned as an Object with the following properties (descriptions of each property are listed below):

```js
{
  is_spam: Boolean,
  message: String,
  results: {
    classification: Object,
    phishing: Array,
    executables: Array,
  },
  tokens: Array,
  mail: Object
}
```

| Property                 | Type    | Description                                                                                                                                                                                                                                                                                        |
| ------------------------ | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `is_spam`                | Boolean | A value of `true` is returned if `category` property of the `results.classification` Object was determined to be `"spam"`, otherwise `false`                                                                                                                                                       |
| `message`                | String  | A human-friendly message indicating why the `source` was classified as spam or ham (e.g. all messages/reasons from `results.classification`, `results.phishing`, and `results.executables` are joined together)                                                                                    |
| `results`                | Object  | An Object of properties that provide detailed information about the scan (very useful for debugging)                                                                                                                                                                                               |
| `results.classification` | Object  | An Object with `category` (String) and `probability` (Number) values returned based off the categorization of the `source` from the Naive Bayes classifier                                                                                                                                         |
| `results.phishing`       | Array   | An Array of Strings indicating phishing attempts detected on the `source`                                                                                                                                                                                                                          |
| `results.executables`    | Array   | An Array of Strings indicating executable attacks detected on the `source`                                                                                                                                                                                                                         |
| `tokens`                 | Array   | **Debug only:** An Array of tokenized and stemmed words (parsed from the `source`, with respect to determined locale) used internally (for classification against the classifier) and exposed for debugging.  This property is only returned when `debug` option in the instance is set to `true`. |
| `mail`                   | Object  | **Debug only:** A parsed `mailparser.simpleParser` object used internally and exposed for debugging.  This property is only returned when `debug` option in the instance is set to `true`.                                                                                                         |

### `scanner.getTokensAndMailFromSource(source)`

Accepts a `source` argument (String, Buffer, or file path) to an email message (e.g. a `.eml` file).  This method will automatically call `fs.readFile` internally if the `source` argument is a String and determined to be a valid path.

This method parses the `source` email message using [mailparser's][mailparser] `simpleParser` function.  It then tokenizes and stems the message's subject, html, and text parts (with respect to the i18n determined language of the message, e.g. `en`, `es`, `jp`, `ru`, etc).

Currently SpamScanner supports the following locales for tokenization:

| Name       | Locale       |
| ---------- | ------------ |
| Dutch      | `nl`         |
| English    | `en`         |
| Farsi      | `fa`         |
| French     | `fr`         |
| Indonesian | `id` or `in` |
| Italian    | `it`         |
| Japanese   | `jp`         |
| Norwegian  | `no`         |
| Portugese  | `pt`         |
| Russian    | `ru`         |
| Spanish    | `es`         |
| Swedish    | `sv`         |

This method returns a Promise that resolves with a `{ tokens, mail }` Object.  You can also use this method with a second callback argument.

Note that `tokens` is an Array of parsed tokenized and stemmed words, and `mail` is the `simpleParser` parsed mail Object.

This is the core internal method used for building the [Bag-of-words model][bag-of-words] which is then fed to the classifier for categorization.

See [classifier.js](classifier.js) for an example implementation of this method (e.g. the one used in generating the default classifier dataset).

### `scanner.getPhishingResults(mail)`

Accepts a `mailparser.simpleParser` parsed mail Object.

This method parses `<a>` anchor tags to check if the `href` attribute content's organization-level domain matches the inner text content.

This method returns a Promise that resolves with an Array of messages (if any) that indicates that links parsed from the message were detected to be phishing attempts.  You can also use this method with a second callback argument.

For example, if a link was `<a href="https://phishing.com">https://tesla.com</a>` then it would be detected as phishing.  However a link of `<a href="https://www.tesla.com">tesla.com</a>` would not be detected as phishing, since the organizational-level domain of `tesla.com` is matching.

This method also prevents the common [IDN homograph attacks][homograph-attack].  If _any_ link is detected to start with the string `xn--` (e.g. after conversion from `punycode.toASCII`) then it is detected as phishing.

A common example of this is a link of `рaypal.com` which when converted to ASCII is `xn--aypal-uye.com` – but when rendered it looks almost identical (if not identical) to `paypal.com`.

### `scanner.getExecutableResults(mail)`

Accepts a `mailparser.simpleParser` parsed mail Object.

Note that this method detects (with respect to [executables.json](executables.json) using "Content-Type" header detection, file extension detection, and [magic number][magic-number] detection.

This method returns a Promise that resolves with an Array of messages (if any) that indicate that links and/or attachments parsed from the message were dangerous (e.g. contained executable files or links to executable files).  You can also use this method with a second callback argument.

This method also takes into consideration that the file extension and name could have a [homograph attack][homograph-attack] by using `punycode.toASCII` on the file name.

It also scans against links in the message itself for links to executables.

### `scanner.getTokens(str, locale, isHTML = false)`

Accepts a `str` (String) and optional `locale` (String - valid i18n locale according to [i18n-locales][]) and `isHTML` parameters.  If `isHTML` is set to `true`, then that indicates that the String passed as `str` is in HTML format.

Returns an Array of tokenized and stemmed words, with respect to the passed, detected, or default locale.

Note that this is "smart" in the sense it will parse the "Content-Language" header of the message, the `content` attribute of the HTML message's `<meta http-equiv="Content-Language" content="en-us">`, or the `lang` attribute of `<html lang="en">`.

### `scanner.parseLocale(locale)`

Accepts a `locale` and returns it as a lowercase string with affixed localizations removed (e.g. `en-US` becomes `en` and `en_US` becomes `en` as well).


## Contributors

| Name           | Website                    |
| -------------- | -------------------------- |
| **Nick Baugh** | <http://niftylettuce.com/> |


## License

[Business Source License 1.1](LICENSE) © [Niftylettuce, LLC.](https://niftylettuce.com/)


## 

[npm]: https://www.npmjs.com/

[yarn]: https://yarnpkg.com/

[i18n-locales]: https://github.com/ladjs/i18n-locales

[magic-number]: https://en.wikipedia.org/wiki/Magic_number_(programming)#Magic_numbers_in_files

[homograph-attack]: https://en.wikipedia.org/wiki/IDN_homograph_attack

[niftylettuce]: https://github.com/niftylettuce

[forward-email]: https://forwardemail.net

[rspamd]: https://rspamd.com/

[spamassassin]: https://spamassassin.apache.org/

[privacy-policy]: https://forwardemail.net/privacy

[nsfw]: https://github.com/infinitered/nsfwjs

[toxicity]: https://github.com/tensorflow/tfjs-models/tree/master/toxicity

[natural]: https://github.com/NaturalNode/natural

[mailparser]: https://nodemailer.com/extras/mailparser/

[bag-of-words]: https://en.wikipedia.org/wiki/Bag-of-words_model

[plan-for-spam]: http://www.paulgraham.com/spam.html

[naivebayes]: https://github.com/surmon-china/naivebayes

[better-plan-for-spam]: http://www.paulgraham.com/better.html
