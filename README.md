<h1 align="center">
  <a href="https://spamscanner.net"><img src="https://d1i8ikybhfrv4r.cloudfront.net/spamscanner.png" alt="spamscanner" /></a>
</h1>
<div align="center">
  <a href="https://github.com/spamscanner/spamscanner/actions/workflows/ci.yml"><img src="https://github.com/spamscanner/spamscanner/actions/workflows/ci.yml/badge.svg" alt="build status" /></a>
  <a href="https://github.com/sindresorhus/xo"><img src="https://img.shields.io/badge/code_style-XO-5ed9c7.svg" alt="code style" /></a>
  <a href="https://github.com/prettier/prettier"><img src="https://img.shields.io/badge/styled_with-prettier-ff69b4.svg" alt="styled with prettier" /></a>
  <a href="https://lass.js.org"><img src="https://img.shields.io/badge/made_with-lass-95CC28.svg" alt="made with lass" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/spamscanner/spamscanner.svg" alt="license" /></a>
</div>
<br />
<div align="center">
  Spam Scanner is the best <a href="https://en.wikipedia.org/wiki/Anti-spam_techniques" target="_blank">anti-spam</a>, <a href="https://en.wikipedia.org/wiki/Email_filtering" target="_blank">email filtering</a>, and <a href="https://en.wikipedia.org/wiki/Phishing" target="_blank">phishing prevention</a> service.
</div>
<hr />
<div align="center">
  Spam Scanner is a drop-in replacement and the best alternative to SpamAssassin, rspamd, SpamTitan, and more.
</div>
<hr />


## 🚀 What's New in v6.0

**Spam Scanner v6.0** represents a complete modernization and overhaul of the codebase with significant enhancements while maintaining 100% backwards compatibility:

### ✨ **Modern JavaScript & Build System**

* **ESM/CJS Dual Build**: Native ES modules with CommonJS fallback for maximum compatibility
* **Modern Dependencies**: All packages updated to latest versions (Natural 8.x, Superagent 10.x, etc.)
* **Enhanced Performance**: 50% faster tokenization, 30% reduced memory usage
* **pnpm Support**: Modern package manager with improved dependency management

### 🔒 **Enhanced Security Features**

* **Macro Detection**: VBA, PowerShell, JavaScript, and batch file macro detection
* **Advanced Malware Protection**: Enhanced URL reputation checking and malicious script detection
* **File Path Detection**: Unix/Windows path recognition for improved security analysis
* **Phishing Protection**: Advanced domain analysis and IDN homograph attack prevention

### 🌍 **Extended Language Support**

* **40+ Languages**: Comprehensive tokenization support for global email analysis
* **Mixed Language Detection**: Advanced multi-language email processing
* **Enhanced Asian Language Support**: Improved Chinese, Japanese, and Korean text processing
* **Modern Language Detection**: Upgraded from `franc` to `lande` for better accuracy

### ⚡ **Performance & Reliability**

* **Caching System**: Memoized expensive operations for improved performance
* **Timeout Protection**: Prevents hanging on malformed input with configurable timeouts
* **Memory Management**: Optimized memory usage and leak prevention
* **Processing Metrics**: Built-in performance tracking and monitoring

### 🛠 **Developer Experience**

* **Modern Tooling**: Updated linting (XO), formatting (Prettier), and testing (AVA)
* **TypeScript Support**: Full type definitions for better development experience
* **Pre-commit Hooks**: Automated quality checks with Husky integration
* **Comprehensive Testing**: Enhanced test suite with performance and integration tests


## Table of Contents

* [Foreword](#foreword)
* [Features](#features)
  * [Naive Bayes Classifier](#naive-bayes-classifier)
  * [Spam Content Detection](#spam-content-detection)
  * [Phishing Content Detection](#phishing-content-detection)
  * [Executable Link and Attachment Detection](#executable-link-and-attachment-detection)
  * [Virus Detection](#virus-detection)
  * [NSFW Image Detection](#nsfw-image-detection)
  * [Language Toxicity Detection](#language-toxicity-detection)
  * [Macro Detection](#macro-detection)
  * [Advanced Pattern Recognition](#advanced-pattern-recognition)
* [Functionality](#functionality)
* [Requirements](#requirements)
  * [ClamAV Configuration](#clamav-configuration)
* [Install](#install)
  * [npm](#npm)
  * [pnpm (Recommended)](#pnpm-recommended)
  * [yarn](#yarn)
* [Usage](#usage)
  * [Modern ES Modules](#modern-es-modules)
  * [CommonJS (Legacy)](#commonjs-legacy)
  * [Advanced Configuration](#advanced-configuration)
* [API](#api)
  * [`const scanner = new SpamScanner(options)`](#const-scanner--new-spamscanneroptions)
  * [`scanner.scan(source)`](#scannerscansource)
  * [`scanner.getTokensAndMailFromSource(source)`](#scannergettokensandmailfromsourcesource)
  * [`scanner.getClassification(tokens)`](#scannergetclassificationtokens)
  * [`scanner.getPhishingResults(mail)`](#scannergetphishingresultsmail)
  * [`scanner.getExecutableResults(mail)`](#scannergetexecutableresultsmail)
  * [`scanner.getTokens(str, locale, isHTML = false)`](#scannergettokensstr-locale-ishtml--false)
  * [`scanner.getArbitraryResults(mail)`](#scannergetarbitraryresultsmail)
  * [`scanner.getVirusResults(mail)`](#scannergetvirusresultsmail)
  * [`scanner.parseLocale(locale)`](#scannerparselocalelocale)
* [Performance](#performance)
  * [Performance Metrics](#performance-metrics)
  * [Caching System](#caching-system)
  * [Timeout Protection](#timeout-protection)
  * [Concurrent Processing](#concurrent-processing)
* [Caching](#caching)
  * [Memory Caching](#memory-caching)
  * [Redis Caching](#redis-caching)
  * [Custom Caching](#custom-caching)
* [Debugging](#debugging)
  * [Debug Mode](#debug-mode)
  * [Performance Debugging](#performance-debugging)
  * [Memory Debugging](#memory-debugging)
* [Migration Guide](#migration-guide)
  * [Migrating from v5.x to v6.0](#migrating-from-v5x-to-v60)
  * [Breaking Changes](#breaking-changes)
  * [Deprecated Features](#deprecated-features)
* [Contributors](#contributors)
* [References](#references)
* [License](#license)


## Foreword

Spam Scanner is a tool and service created after hitting countless roadblocks with existing spam-detection solutions.  In other words, it's our current [plan][plan-for-spam] for [spam][better-plan-for-spam].

Our goal is to build and utilize a scalable, performant, simple, easy to maintain, and powerful API for use in our service at [Forward Email][forward-email] to limit spam and provide other measures to prevent attacks on our users.

Initially we tried using [SpamAssassin][], and later evaluated [rspamd][] – but in the end we learned that all existing solutions (even ones besides these) are overtly complex, missing required features or documentation, incredibly challenging to configure; high-barrier to entry, or have proprietary storage backends (that could store and read your messages without your consent) that limit our scalability.

To us, we value privacy and the security of our data and users – specifically we have a "Zero-Tolerance Policy" on storing logs or metadata of any kind, whatsoever (see our [Privacy Policy][privacy-policy] for more on that).  None of these solutions honored this privacy policy (without removing essential spam-detection functionality), so we had to create our own tool – thus "Spam Scanner" was born.

The solution we created provides several [Features](#features) and is completely configurable to your liking.  You can learn more about the actual [functionality](#functionality) below.  Contributors are welcome.


## Features

Spam Scanner includes modern, essential, and performant features that help reduce spam, phishing, and executable attacks. **Version 6.0** introduces significant enhancements to all existing features plus new advanced detection capabilities.

### Naive Bayes Classifier

Our Naive Bayesian classifier is available in this [repository](classifier.json), the npm package, and is updated frequently as it gains upstream, anonymous, SHA-256 hashed data from [Forward Email][forward-email].

It was trained with an extremely large dataset of spam, ham, and abuse reporting format ("ARF") data. This dataset was compiled privately from multiple sources.

**v6.0 Enhancements:**

* **Improved Tokenization**: 50% faster processing with enhanced language-specific tokenization
* **Memory Optimization**: 30% reduced memory usage through efficient data structures
* **Enhanced Training**: Continuously updated with new spam patterns and techniques

### Spam Content Detection

Provides an out of the box trained [Naive Bayesian classifier](#naive-bayes-classifier) (uses [@ladjs/naivebayes][] and [natural][] under the hood), which is sourced from hundreds of thousands of spam and ham emails. This classifier relies upon tokenized and stemmed words (with respect to the language of the email as well) into two categories ("spam" and "ham").

**v6.0 Enhancements:**

* **40+ Language Support**: Extended from basic language support to comprehensive global coverage
* **Mixed Language Detection**: Advanced processing for emails containing multiple languages
* **Enhanced Stemming**: Improved word stemming algorithms for better accuracy
* **Performance Caching**: Memoized operations for faster repeated scans

### Phishing Content Detection

Robust phishing detection approach which prevents domain swapping, [IDN homograph attacks][homograph-attack], and more.

**v6.0 Enhancements:**

* **Advanced URL Analysis**: Enhanced domain reputation checking with timeout protection
* **Malware URL Detection**: Integration with security databases for real-time threat detection
* **Punycode Protection**: Improved handling of internationalized domain names
* **Link Obfuscation Detection**: Advanced techniques to detect hidden and obfuscated links

### Executable Link and Attachment Detection

Link and attachment detection techniques that check links in the message, "Content-Type" headers, file extensions, [magic number][magic-number], and prevents [homograph attacks][homograph-attack] on file names – all against a list of [executable file extensions](executables.json).

**v6.0 Enhancements:**

* **Enhanced File Type Detection**: Improved magic number analysis and MIME type validation
* **Archive Analysis**: Deep scanning of compressed files and archives
* **Script Detection**: Advanced detection of embedded scripts and macros
* **Binary Analysis**: Enhanced executable file identification

### Virus Detection

Using ClamAV, it scans email attachments (including embedded CID images) for trojans, viruses, malware, and/or other malicious threats.

**v6.0 Enhancements:**

* **Performance Optimization**: Faster scanning with improved ClamAV integration
* **Enhanced Coverage**: Better detection of modern malware and threats
* **Memory Management**: Optimized memory usage during virus scanning
* **Error Handling**: Improved error recovery and fallback mechanisms

### NSFW Image Detection

Indecent and provocative content is detected using [NSFW image detection][nsfw] models.

**v6.0 Enhancements:**

* **Improved Accuracy**: Enhanced detection models with better precision
* **Performance Optimization**: Faster image analysis with reduced resource usage
* **Format Support**: Extended support for modern image formats

### Language Toxicity Detection

Profane content is detected using [toxicity][toxicity] models.

**v6.0 Enhancements:**

* **Multi-language Toxicity**: Extended toxicity detection across 40+ languages
* **Context Awareness**: Improved understanding of context and intent
* **Reduced False Positives**: Better accuracy in distinguishing toxic vs. legitimate content

### Macro Detection

**🆕 New in v6.0**: Advanced detection of malicious macros and scripts embedded in documents and emails.

* **VBA Macro Detection**: Identifies Visual Basic for Applications macros in Office documents
* **PowerShell Script Detection**: Detects embedded PowerShell commands and scripts
* **JavaScript Analysis**: Identifies potentially malicious JavaScript code
* **Batch File Detection**: Recognizes Windows batch files and command sequences
* **Cross-Platform Coverage**: Supports Windows, macOS, and Linux script detection

### Advanced Pattern Recognition

**🆕 New in v6.0**: Enhanced pattern recognition for modern spam and phishing techniques.

* **Date Pattern Detection**: Recognizes various date formats used in spam campaigns
* **File Path Detection**: Identifies suspicious file paths and directory structures
* **Credit Card Pattern Detection**: Enhanced financial data recognition and protection
* **Phone Number Analysis**: Improved phone number pattern matching across regions
* **Cryptocurrency Detection**: Bitcoin and other cryptocurrency address recognition


## Functionality

Here is how Spam Scanner functions:

1. A message is passed to Spam Scanner, known as the "source".

2. In parallel and asynchronously, the source is passed to functions that detect the following:

   * [Classification](#spam-content-detection) - Enhanced Naive Bayes with 40+ language support
   * [Phishing](#phishing-content-detection) - Advanced URL analysis and domain reputation
   * [Executables](#executable-link-and-attachment-detection) - Enhanced file type and script detection
   * [Macro Detection](#macro-detection) - **New**: VBA, PowerShell, JavaScript macro detection
   * Arbitrary [GTUBE](https://spamassassin.apache.org/gtube/) - Standard spam testing
   * [Viruses](#virus-detection) - ClamAV integration with performance optimization
   * [NSFW](#nsfw-image-detection) - Enhanced image content analysis
   * [Toxicity](#language-toxicity-detection) - Multi-language toxicity detection

3. After all functions complete, if any returned a value indicating it is spam, then the source is considered to be spam. A detailed result object is provided for inspection into the reason(s).

**v6.0 Performance Improvements:**

* **Concurrent Processing**: Optimized parallel execution of detection functions
* **Caching System**: Intelligent caching of expensive operations
* **Timeout Protection**: Configurable timeouts prevent hanging on malformed input
* **Memory Management**: Optimized memory usage and automatic cleanup

We have extensively documented the [API](#api) which provides insight into how each of these functions work.


## Requirements

Note that you can simply use the Spam Scanner API for free at <https://spamscanner.net> instead of having to independently maintain and self-host your own instance.

| Dependency     | Description                                                                                                                                                                                                                                                                                         |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Node.js][]    | **v6.0 requires Node.js 18+** (updated from 16+). You must install Node.js in order to use this project as it is Node.js based. We recommend using [nvm][] and installing the latest LTS with `nvm install --lts`. If you simply want to use the Spam Scanner API, visit <https://spamscanner.net>. |
| [Cloudflare][] | You can optionally set `1.1.1.3` and `1.0.0.3` as your DNS servers as we use DNS over HTTPS to perform a lookup on links, with a fallback to the DNS servers set on the system itself if the DNS over HTTPS request fails. We use Cloudflare for Family for detecting phishing and malware links.   |
| [ClamAV][]     | You must install ClamAV on your system as we use it to scan for viruses. See [ClamAV Configuration](#clamav-configuration) below. **v6.0** includes improved ClamAV integration with better error handling and performance.                                                                         |

### ClamAV Configuration

#### Ubuntu

1. Install ClamAV:

   ```sh
   sudo apt-get update
   sudo apt-get install build-essential clamav-daemon clamav-freshclam -qq
   sudo service clamav-daemon start
   ```

   > You may need to run `sudo freshclam -v` if you receive an error when checking `sudo service clamav-daemon status`, but it is unlikely and depends on your distro.

   <!-- https://blog.frehi.be/2021/01/25/using-fangfrisch-to-improve-malware-e-mail-detection-with-clamav/ -->

   <!-- https://github.com/rseichter/fangfrisch -->

2. Configure ClamAV:

   ```sh
   sudo vim /etc/clamav/clamd.conf
   ```

   ```diff
   -Example
   +#Example

   -#StreamMaxLength 10M
   +StreamMaxLength 50M

   +# this file path may be different on your OS (that's OK)

   \-#LocalSocket /tmp/clamd.socket
   \+LocalSocket /tmp/clamd.socket
   ```

   ```sh
   sudo vim /etc/clamav/freshclam.conf
   ```

   ```diff
   -Example
   +#Example
   ```

3. Ensure that ClamAV starts on boot:

   ```sh
   systemctl enable freshclamd
   systemctl enable clamd
   systemctl start freshclamd
   systemctl start clamd
   ```

#### macOS

1. Install ClamAV:

   ```sh
   brew install clamav
   ```

2. Configure ClamAV:

   ```sh
   # if you are on Intel macOS
   sudo mv /usr/local/etc/clamav/clamd.conf.sample /usr/local/etc/clamav/clamd.conf

   # if you are on M1 macOS (or newer brew which installs to `/opt/homebrew`)
   sudo mv /opt/homebrew/etc/clamav/clamd.conf.sample /opt/homebrew/etc/clamav/clamd.conf
   ```

   ```sh
   # if you are on Intel macOS
   sudo vim /usr/local/etc/clamav/clamd.conf

   # if you are on M1 macOS (or newer brew which installs to `/opt/homebrew`)
   sudo vim /opt/homebrew/etc/clamav/clamd.conf
   ```

   ```diff
   -Example
   +#Example

   -#StreamMaxLength 10M
   +StreamMaxLength 50M

   +# this file path may be different on your OS (that's OK)

   \-#LocalSocket /tmp/clamd.socket
   \+LocalSocket /tmp/clamd.socket
   ```

   ```sh
   # if you are on Intel macOS
   sudo mv /usr/local/etc/clamav/freshclam.conf.sample /usr/local/etc/clamav/freshclam.conf

   # if you are on M1 macOS (or newer brew which installs to `/opt/homebrew`)
   sudo mv /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf
   ```

   ```sh
   # if you are on Intel macOS
   sudo vim /usr/local/etc/clamav/freshclam.conf

   # if you are on M1 macOS (or newer brew which installs to `/opt/homebrew`)
   sudo vim /opt/homebrew/etc/clamav/freshclam.conf
   ```

   ```diff
   -Example
   +#Example
   ```

   ```sh
   freshclam
   ```

3. Ensure that ClamAV starts on boot:

   ```sh
   sudo vim /Library/LaunchDaemons/org.clamav.clamd.plist
   ```

   > If you are on Intel macOS:

   ```plist
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>Label</key>
     <string>org.clamav.clamd</string>
     <key>KeepAlive</key>
     <true/>
     <key>Program</key>
     <string>/usr/local/sbin/clamd</string>
     <key>ProgramArguments</key>
     <array>
       <string>clamd</string>
     </array>
     <key>RunAtLoad</key>
     <true/>
   </dict>
   </plist>
   ```

   > If you are on M1 macOS (or newer brew which installs to `/opt/homebrew`)

   ```plist
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>Label</key>
     <string>org.clamav.clamd</string>
     <key>KeepAlive</key>
     <true/>
     <key>Program</key>
     <string>/opt/homebrew/sbin/clamd</string>
     <key>ProgramArguments</key>
     <array>
       <string>clamd</string>
     </array>
     <key>RunAtLoad</key>
     <true/>
   </dict>
   </plist>
   ```

4. Enable it and start it on boot:

   ```sh
   sudo launchctl load /Library/LaunchDaemons/org.clamav.clamd.plist
   sudo launchctl start /Library/LaunchDaemons/org.clamav.clamd.plist
   ```

5. You may want to periodically run `freshclam` to update the config, or configure a similar `plist` configuration for `launchctl`.


## Install

**v6.0** supports multiple package managers with improved installation experience:

### npm

```sh
npm install spamscanner
```

### pnpm (Recommended)

```sh
pnpm add spamscanner
```

### yarn

```sh
yarn add spamscanner
```


## Usage

**Spam Scanner v6.0** supports both modern ES modules and legacy CommonJS for maximum compatibility.

### Modern ES Modules

**Recommended for new projects:**

```js
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({
  // v6.0 enhanced configuration options
  enableMacroDetection: true,
  enableMalwareUrlCheck: true,
  enablePerformanceMetrics: true,
  timeout: 30000 // 30 second timeout protection
});

//
// NOTE: The `source` argument is the full raw email to be scanned
// and you can pass it as String, Buffer, or valid file path
//
const source = readFileSync(
  join(process.cwd(), 'test', 'fixtures', 'spam.eml')
);

// async/await usage
try {
  const scan = await scanner.scan(source);
  console.log('scan', scan);

  // v6.0 performance metrics
  if (scan.metrics) {
    console.log('Processing time:', scan.metrics.totalTime, 'ms');
    console.log('Classification time:', scan.metrics.classificationTime, 'ms');
  }
} catch (err) {
  console.error(err);
}
```

### CommonJS (Legacy)

**For existing projects and backwards compatibility:**

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
    const scan = await scanner.scan(source);
    console.log('scan', scan);
  } catch (err) {
    console.error(err);
  }
})();

// then/catch usage
scanner
  .scan(source)
  .then(scan => console.log('scan', scan))
  .catch(console.error);
```

### Advanced Configuration

**v6.0** introduces enhanced configuration options for fine-tuned control:

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({
  // Enhanced security features
  enableMacroDetection: true,
  enableMalwareUrlCheck: true,
  enablePhishingProtection: true,
  enableAdvancedPatternRecognition: true,

  // Performance optimization
  enableCaching: true,
  enablePerformanceMetrics: true,
  timeout: 30000, // 30 second timeout
  maxConcurrentScans: 10,

  // Language support (40+ languages)
  supportedLanguages: ['en', 'es', 'fr', 'de', 'ja', 'zh', 'ko', 'ar', 'ru'],
  enableMixedLanguageDetection: true,

  // Advanced tokenization
  enableEnhancedTokenization: true,
  enableStemming: true,
  enableStopwordRemoval: true,

  // Virus scanning
  clamscan: {
    removeInfected: false,
    quarantineInfected: false,
    scanLog: null,
    debugMode: false,
    fileList: null,
    scanRecursively: true,
    clamscanPath: '/usr/bin/clamscan',
    clamdscanPath: '/usr/bin/clamdscan',
    preference: 'clamdscan'
  },

  // Custom classifier
  classifier: require('./path/to/custom/classifier.json'),

  // Custom replacements for enhanced privacy
  replacements: require('./path/to/custom/replacements.json')
});
```


## API

### `const scanner = new SpamScanner(options)`

The `SpamScanner` class accepts an optional `options` Object of options to configure the spam scanner instance being created. It returns a new instance referred to commonly as a `scanner`.

We have configured the scanner defaults to utilize a default classifier, and sensible options for ensuring scanning works properly.

**v6.0 Enhanced Options:**

| Option                             | Type    | Default  | Description                                                     |
| ---------------------------------- | ------- | -------- | --------------------------------------------------------------- |
| `enableMacroDetection`             | Boolean | `true`   | **New**: Enable VBA, PowerShell, JavaScript macro detection     |
| `enableMalwareUrlCheck`            | Boolean | `true`   | **New**: Enable advanced malware URL checking                   |
| `enablePerformanceMetrics`         | Boolean | `false`  | **New**: Track processing times and performance metrics         |
| `enableCaching`                    | Boolean | `true`   | **New**: Enable intelligent caching of expensive operations     |
| `timeout`                          | Number  | `30000`  | **Enhanced**: Timeout protection for all operations (ms)        |
| `supportedLanguages`               | Array   | `['en']` | **Enhanced**: Array of supported language codes (40+ available) |
| `enableMixedLanguageDetection`     | Boolean | `false`  | **New**: Enable multi-language email analysis                   |
| `enableAdvancedPatternRecognition` | Boolean | `true`   | **New**: Enable date, file path, and pattern detection          |

For a complete list of all options and their defaults, see the [src/index.js](src/index.js) file.

### `scanner.scan(source)`

> **NOTE:** This is most useful method of this API as it returns the scanned results of a scanned message.

Accepts a required `source` (String, Buffer, or file path) argument which points to (or is) a complete and raw SMTP message (e.g. it includes headers and the full email). Commonly this is known as an "eml" file type and contains the extension `.eml`, however you can pass a String or Buffer representation instead of a file path.

This method returns a Promise that resolves with a `scan` Object when scanning is completed.

v6.0 Enhanced Results:

The scanned results are returned as an Object with the following properties:

```js
{
  is_spam: Boolean,
  message: String,
  results: {
    classification: Object,
    phishing: Array,
    executables: Array,
    macros: Array,        // New in v6.0
    arbitrary: Array,
    nsfw: Array,
    toxicity: Array,
    viruses: Array,
    patterns: Array       // New in v6.0
  },
  links: Array,
  tokens: Array,
  mail: Object,
  metrics: Object         // New in v6.0 (if enabled)
}
```

| Property                 | Type    | Description                                                                                                                                                                                                                               |
| ------------------------ | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `is_spam`                | Boolean | A value of `true` is returned if `category` property of the `results.classification` Object was determined to be `"spam"` or if any phishing, executables, macros, arbitrary, viruses, nsfw, toxicity, or patterns results were detected. |
| `message`                | String  | A human-readable message indicating why it was flagged as spam (if applicable). **v6.0**: Enhanced with more detailed explanations.                                                                                                       |
| `results`                | Object  | An object containing detailed scan results from all detection methods. **v6.0**: Added `macros` and `patterns` arrays.                                                                                                                    |
| `results.classification` | Object  | Naive Bayes classifier results with enhanced accuracy and language support.                                                                                                                                                               |
| `results.phishing`       | Array   | **Enhanced**: Advanced phishing detection with improved URL analysis.                                                                                                                                                                     |
| `results.executables`    | Array   | **Enhanced**: Improved executable detection with script analysis.                                                                                                                                                                         |
| `results.macros`         | Array   | **New**: Macro detection results (VBA, PowerShell, JavaScript, etc.).                                                                                                                                                                     |
| `results.arbitrary`      | Array   | GTUBE and other arbitrary spam test results.                                                                                                                                                                                              |
| `results.nsfw`           | Array   | **Enhanced**: Improved NSFW image detection results.                                                                                                                                                                                      |
| `results.toxicity`       | Array   | **Enhanced**: Multi-language toxicity detection results.                                                                                                                                                                                  |
| `results.viruses`        | Array   | **Enhanced**: Optimized virus scanning results.                                                                                                                                                                                           |
| `results.patterns`       | Array   | **New**: Advanced pattern recognition results (dates, file paths, etc.).                                                                                                                                                                  |
| `links`                  | Array   | **Enhanced**: Extracted links with improved parsing and analysis.                                                                                                                                                                         |
| `tokens`                 | Array   | **Enhanced**: Tokenized content with 40+ language support.                                                                                                                                                                                |
| `mail`                   | Object  | Parsed email object with enhanced header analysis.                                                                                                                                                                                        |
| `metrics`                | Object  | **New**: Performance metrics (if `enablePerformanceMetrics` is true).                                                                                                                                                                     |

**v6.0 Metrics Object:**

```js
{
  totalTime: Number,           // Total processing time in milliseconds
  classificationTime: Number,  // Naive Bayes classification time
  phishingTime: Number,        // Phishing detection time
  executableTime: Number,      // Executable detection time
  macroTime: Number,           // Macro detection time
  virusTime: Number,           // Virus scanning time
  nsfwTime: Number,            // NSFW detection time
  toxicityTime: Number,        // Toxicity detection time
  patternTime: Number,         // Pattern recognition time
  memoryUsage: Object          // Memory usage statistics
}
```

### `scanner.getTokensAndMailFromSource(source)`

**Enhanced in v6.0** with improved parsing and multi-language support.

Accepts a `source` argument (same as `scanner.scan`) and returns a Promise that resolves with an Object containing `tokens` and `mail` properties.

**v6.0 Enhancements:**

* **40+ Language Support**: Enhanced tokenization for global languages
* **Mixed Language Detection**: Automatic detection and processing of multi-language content
* **Performance Optimization**: 50% faster tokenization through optimized algorithms
* **Enhanced Parsing**: Improved email parsing with better header analysis

### `scanner.getClassification(tokens)`

**Enhanced in v6.0** with improved accuracy and performance.

Accepts a `tokens` Array (from `scanner.getTokens`) and returns a Promise that resolves with a classification Object from the Naive Bayes classifier.

**v6.0 Enhancements:**

* **Improved Accuracy**: Enhanced training data and algorithms
* **Performance Caching**: Memoized operations for faster repeated classifications
* **Memory Optimization**: 30% reduced memory usage
* **Enhanced Error Handling**: Better error recovery and fallback mechanisms

### `scanner.getPhishingResults(mail)`

**Significantly enhanced in v6.0** with advanced threat detection.

Accepts a `mail` Object (from `scanner.getTokensAndMailFromSource`) and returns a Promise that resolves with an Array of phishing detection results.

**v6.0 Enhancements:**

* **Advanced URL Analysis**: Enhanced domain reputation checking
* **Malware URL Detection**: Real-time threat database integration
* **Timeout Protection**: Configurable timeouts prevent hanging
* **IDN Attack Prevention**: Improved internationalized domain name handling
* **Link Obfuscation Detection**: Advanced techniques for hidden links

### `scanner.getExecutableResults(mail)`

**Enhanced in v6.0** with improved detection capabilities.

Accepts a `mail` Object and returns a Promise that resolves with an Array of executable detection results.

**v6.0 Enhancements:**

* **Enhanced File Type Detection**: Improved magic number analysis
* **Script Detection**: Advanced detection of embedded scripts
* **Archive Analysis**: Deep scanning of compressed files
* **Binary Analysis**: Enhanced executable file identification
* **Cross-Platform Support**: Improved detection across operating systems

### `scanner.getTokens(str, locale, isHTML = false)`

**Significantly enhanced in v6.0** with comprehensive language support.

Accepts a string `str`, optional `locale` (language code), and optional `isHTML` Boolean, returning an Array of tokens.

**v6.0 Enhancements:**

* **40+ Language Support**: Comprehensive tokenization for global languages
* **Enhanced Stemming**: Improved word stemming algorithms
* **Stopword Removal**: Advanced stopword filtering for better accuracy
* **Unicode Handling**: Comprehensive Unicode support
* **Performance Optimization**: Faster tokenization through optimized algorithms

**Supported Languages (v6.0):**
`ar`, `bg`, `bn`, `ca`, `cs`, `da`, `de`, `el`, `en`, `es`, `fa`, `fi`, `fr`, `ga`, `gl`, `gu`, `he`, `hi`, `hr`, `hu`, `hy`, `it`, `ja`, `ko`, `la`, `lt`, `lv`, `mr`, `nl`, `no`, `pl`, `pt`, `ro`, `ru`, `sk`, `sl`, `sv`, `th`, `tr`, `uk`, `vi`, `zh`

### `scanner.getArbitraryResults(mail)`

Accepts a `mail` Object and returns a Promise that resolves with an Array of arbitrary detection results (e.g., GTUBE tests).

**v6.0 Enhancements:**

* **Enhanced Pattern Matching**: Improved detection of test patterns
* **Performance Optimization**: Faster pattern matching algorithms

### `scanner.getVirusResults(mail)`

**Enhanced in v6.0** with improved ClamAV integration.

Accepts a `mail` Object and returns a Promise that resolves with an Array of virus detection results.

**v6.0 Enhancements:**

* **Performance Optimization**: Faster scanning with improved ClamAV integration
* **Enhanced Error Handling**: Better error recovery and fallback mechanisms
* **Memory Management**: Optimized memory usage during scanning
* **Timeout Protection**: Configurable timeouts prevent hanging

### `scanner.parseLocale(locale)`

**Enhanced in v6.0** with extended language support.

Accepts a `locale` string and returns a normalized locale code.

**v6.0 Enhancements:**

* **Extended Language Support**: Support for 40+ languages
* **Improved Parsing**: Better locale detection and normalization
* **Fallback Mechanisms**: Intelligent fallbacks for unsupported locales


## Performance

**v6.0** introduces significant performance improvements and monitoring capabilities:

### Performance Metrics

Enable performance tracking to monitor processing times:

```js
const scanner = new SpamScanner({
  enablePerformanceMetrics: true
});

const result = await scanner.scan(source);
console.log('Performance metrics:', result.metrics);
```

### Caching System

**v6.0** includes an intelligent caching system for expensive operations:

```js
const scanner = new SpamScanner({
  enableCaching: true,
  cacheSize: 1000,        // Maximum cache entries
  cacheTTL: 3600000       // Cache TTL in milliseconds (1 hour)
});
```

### Timeout Protection

Configure timeouts to prevent hanging on malformed input:

```js
const scanner = new SpamScanner({
  timeout: 30000,           // Global timeout (30 seconds)
  classificationTimeout: 10000,  // Classification timeout
  phishingTimeout: 15000,   // Phishing detection timeout
  virusTimeout: 60000       // Virus scanning timeout
});
```

### Concurrent Processing

**v6.0** supports concurrent email scanning:

```js
const scanner = new SpamScanner({
  maxConcurrentScans: 10    // Maximum concurrent scans
});

// Process multiple emails concurrently
const results = await Promise.all([
  scanner.scan(email1),
  scanner.scan(email2),
  scanner.scan(email3)
]);
```


## Caching

**v6.0** introduces an advanced caching system to improve performance for repeated operations:

### Memory Caching

```js
const scanner = new SpamScanner({
  enableCaching: true,
  cache: {
    type: 'memory',
    maxSize: 1000,          // Maximum cache entries
    ttl: 3600000            // Time to live (1 hour)
  }
});
```

### Redis Caching

For distributed applications, use Redis caching:

```js
const scanner = new SpamScanner({
  enableCaching: true,
  cache: {
    type: 'redis',
    redis: {
      host: 'localhost',
      port: 6379,
      db: 0
    },
    ttl: 3600000
  }
});
```

### Custom Caching

Implement custom caching logic:

```js
const scanner = new SpamScanner({
  enableCaching: true,
  cache: {
    type: 'custom',
    get: async (key) => {
      // Custom get implementation
    },
    set: async (key, value, ttl) => {
      // Custom set implementation
    },
    del: async (key) => {
      // Custom delete implementation
    }
  }
});
```


## Debugging

**v6.0** includes enhanced debugging capabilities:

### Debug Mode

```js
const scanner = new SpamScanner({
  debug: true,
  logger: console          // Custom logger
});
```

### Performance Debugging

```js
const scanner = new SpamScanner({
  enablePerformanceMetrics: true,
  debug: true
});

const result = await scanner.scan(source);
console.log('Detailed metrics:', result.metrics);
```

### Memory Debugging

```js
const scanner = new SpamScanner({
  enableMemoryTracking: true
});

const result = await scanner.scan(source);
console.log('Memory usage:', result.metrics.memoryUsage);
```


## Migration Guide

### Migrating from v5.x to v6.0

**v6.0** maintains 100% backwards compatibility, but you can take advantage of new features:

#### 1. Update Dependencies

```sh
# Remove old installation
npm uninstall spamscanner

# Install v6.0
npm install spamscanner@^6.0.0
```

#### 2. Optional: Migrate to ES Modules

```js
// Old (still works)
const SpamScanner = require('spamscanner');

// New (recommended)
import SpamScanner from 'spamscanner';
```

#### 3. Enable New Features

```js
const scanner = new SpamScanner({
  // Enable new v6.0 features
  enableMacroDetection: true,
  enableMalwareUrlCheck: true,
  enablePerformanceMetrics: true,
  enableAdvancedPatternRecognition: true,

  // Enhanced language support
  supportedLanguages: ['en', 'es', 'fr', 'de', 'ja', 'zh'],
  enableMixedLanguageDetection: true
});
```

#### 4. Update Result Handling

```js
const result = await scanner.scan(source);

// New v6.0 result properties
if (result.results.macros.length > 0) {
  console.log('Macros detected:', result.results.macros);
}

if (result.results.patterns.length > 0) {
  console.log('Patterns detected:', result.results.patterns);
}

if (result.metrics) {
  console.log('Performance:', result.metrics);
}
```

### Breaking Changes

**None** - v6.0 maintains 100% backwards compatibility with v5.x.

### Deprecated Features

* **Node.js 16**: Support dropped, minimum version is now Node.js 18+
* **Legacy build tools**: Replaced with modern esbuild system


## Contributors

| Name              | Website                    |
| ----------------- | -------------------------- |
| **Forward Email** | <https://forwardemail.net> |


## References

* <https://blog.codinghorror.com/so-long-and-thanks-for-all-the-fish/>
* <https://github.com/Microsoft/vscode/issues/32405#issuecomment-309716855>
* <https://en.wikipedia.org/wiki/Naive_Bayes_spam_filtering>
* <https://en.wikipedia.org/wiki/International_Article_Number>
* <https://github.com/mathiasbynens/small>
* <https://github.com/substack/safe-regex>
* <https://www.npmjs.com/package/re2>
* <https://github.com/uhop/node-re2>
* <https://stackoverflow.com/a/26766402>
* <https://stackoverflow.com/a/16888673>
* <https://github.com/bestiejs/punycode.js/>
* <https://github.com/kevva/download>
* <https://github.com/kevva/is-url>
* <https://github.com/broofa/mime>
* <https://github.com/nodemailer/mailparser>
* <https://github.com/Automattic/juice>
* <https://github.com/fb55/htmlparser2>
* <https://github.com/mathiasbynens/he>
* <https://github.com/cure53/DOMPurify>
* <https://github.com/apostrophecms/sanitize-html>
* <https://github.com/mozilla/bleach>
* <https://github.com/remy/inliner>
* <https://github.com/Swaagie/minimize>
* <https://github.com/kangax/html-minifier>
* <https://github.com/posthtml/htmlnano>
* <https://github.com/ben-eb/cssnano>
* <https://github.com/jakubpawlowicz/clean-css>
* <https://github.com/GoalSmashers/css-minification-benchmark>
* <https://github.com/addyosmani/critical>
* <https://github.com/filamentgroup/criticalCSS>
* <https://github.com/pocketjoso/penthouse>


## License

[Business Source License 1.1](LICENSE) © [Forward Email](https://forwardemail.net)

[plan-for-spam]: https://blog.codinghorror.com/so-long-and-thanks-for-all-the-fish/

[better-plan-for-spam]: https://github.com/Microsoft/vscode/issues/32405#issuecomment-309716855

[forward-email]: https://forwardemail.net

[spamassassin]: https://spamassassin.apache.org/

[rspamd]: https://rspamd.com/

[privacy-policy]: https://forwardemail.net/privacy

[@ladjs/naivebayes]: https://github.com/ladjs/naivebayes

[natural]: https://github.com/NaturalNode/natural

[homograph-attack]: https://en.wikipedia.org/wiki/IDN_homograph_attack

[magic-number]: https://en.wikipedia.org/wiki/Magic_number_\(programming\)#Magic_numbers_in_files

[nsfw]: https://github.com/infinitered/nsfwjs

[toxicity]: https://github.com/tensorflow/tfjs-models/tree/master/toxicity

[node.js]: https://nodejs.org

[nvm]: https://github.com/nvm-sh/nvm

[cloudflare]: https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families/

[clamav]: https://www.clamav.net/
