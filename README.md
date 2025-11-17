# Spam Scanner

> **The best anti-spam, email filtering, and phishing prevention service for Node.js**

[![build status](https://github.com/spamscanner/spamscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/spamscanner/spamscanner/actions/workflows/ci.yml)
[![code coverage](https://img.shields.io/badge/coverage-88.41%25-brightgreen.svg)](https://github.com/spamscanner/spamscanner)
[![code style](https://img.shields.io/badge/code_style-XO-5ed9c7.svg)](https://github.com/sindresorhus/xo)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![made with lass](https://img.shields.io/badge/made_with-lass-95CC28.svg)](https://lass.js.org)
[![license](https://img.shields.io/github/license/spamscanner/spamscanner.svg)](LICENSE)

> \[!NOTE]
> Spam Scanner is actively maintained and used in production at [Forward Email](https://forwardemail.net) to protect millions of emails daily.

---


## Table of Contents

* [Foreword](#foreword)
* [Why Spam Scanner](#why-spam-scanner)
  * [Key Advantages](#key-advantages)
* [Features](#features)
  * [Core Detection Features](#core-detection-features)
  * [Naive Bayes Classifier](#naive-bayes-classifier)
  * [Phishing Detection](#phishing-detection)
  * [Virus Scanning](#virus-scanning)
  * [Executable Detection](#executable-detection)
  * [NSFW Image Detection](#nsfw-image-detection)
  * [Toxicity Detection](#toxicity-detection)
  * [Macro Detection](#macro-detection)
  * [Language Detection](#language-detection)
  * [Pattern Recognition](#pattern-recognition)
  * [URL Analysis](#url-analysis)
* [Comparison](#comparison)
  * [Spam Scanner vs. Alternatives](#spam-scanner-vs-alternatives)
* [Architecture](#architecture)
  * [System Overview](#system-overview)
  * [Detection Flow](#detection-flow)
  * [Component Architecture](#component-architecture)
* [Requirements](#requirements)
  * [System Requirements](#system-requirements)
  * [Dependencies](#dependencies)
* [Installation](#installation)
  * [ClamAV Installation](#clamav-installation)
* [Quick Start](#quick-start)
  * [Basic Usage](#basic-usage)
  * [With Configuration](#with-configuration)
  * [Checking Specific Features](#checking-specific-features)
* [API Documentation](#api-documentation)
  * [Constructor Options](#constructor-options)
  * [Methods](#methods)
  * [Result Object](#result-object)
* [Advanced Usage](#advanced-usage)
  * [Custom Classifier](#custom-classifier)
  * [Custom Text Replacements](#custom-text-replacements)
  * [Language Filtering](#language-filtering)
  * [Performance Monitoring](#performance-monitoring)
  * [Selective Feature Disabling](#selective-feature-disabling)
  * [Custom Timeout](#custom-timeout)
  * [Custom Logger](#custom-logger)
* [Performance](#performance)
  * [Benchmarks](#benchmarks)
  * [Optimization Tips](#optimization-tips)
  * [Memory Usage](#memory-usage)
* [Contributing](#contributing)
  * [Development Setup](#development-setup)
  * [Running Tests](#running-tests)
* [License](#license)
* [Support](#support)
* [Acknowledgments](#acknowledgments)


## Foreword

Spam Scanner is a tool and service created after hitting countless roadblocks with existing spam-detection solutions. In other words, it's our current [plan for spam](https://forwardemail.net/blog/our-plan-for-spam) and our [better plan for spam](https://forwardemail.net/blog/a-better-plan-for-spam).

Our goal is to build and utilize a scalable, performant, simple, easy to maintain, and powerful API for use in our service at [Forward Email](https://forwardemail.net) to limit spam and provide other measures to prevent attacks on our users.

Initially we tried using [SpamAssassin](https://spamassassin.apache.org), and later evaluated [rspamd](https://rspamd.com) – but in the end we learned that all existing solutions (even ones besides these) are overtly complex, missing required features or documentation, incredibly challenging to configure; high-barrier to entry, or have proprietary storage backends (that could store and read your messages without your consent) that limit our scalability.

To us, we value privacy and the security of our data and users – specifically we have a "Zero-Tolerance Policy" on storing logs or metadata of any kind, whatsoever (see our [Privacy Policy](https://forwardemail.net/privacy-policy) for more on that). None of these solutions honored this privacy policy (without removing essential spam-detection functionality), so we had to create our own tool – thus "Spam Scanner" was born.

---


## Why Spam Scanner

> \[!TIP]
> Spam Scanner is the only modern, privacy-focused, Node.js-based spam detection solution with AI-powered features.

### Key Advantages

* **🔒 Privacy-First** - Zero logging, zero metadata storage
* **🚀 Modern** - Built with Node.js 18+, ES modules, and latest AI models
* **🎯 Accurate** - 88%+ detection accuracy with Naive Bayes classifier
* **⚡ Fast** - Scans emails in under 3 seconds (with model caching)
* **🛡️ Comprehensive** - 10+ detection methods (virus, phishing, NSFW, toxicity, macros, etc.)
* **🌍 Multilingual** - Supports 40+ languages with automatic detection
* **🔧 Easy to Use** - Simple API, extensive documentation, TypeScript support
* **📊 Battle-Tested** - Used in production at Forward Email

---


## Features

Spam Scanner includes modern, essential, and performant features that help reduce spam, phishing, and executable attacks.

### Core Detection Features

| Feature                                               | Description                                                        | Status       |
| ----------------------------------------------------- | ------------------------------------------------------------------ | ------------ |
| **[Naive Bayes Classifier](#naive-bayes-classifier)** | Machine learning spam classification trained on 100K+ emails       | ✅ Production |
| **[Phishing Detection](#phishing-detection)**         | IDN homograph detection, confusables, suspicious link analysis     | ✅ Production |
| **[Virus Scanning](#virus-scanning)**                 | ClamAV integration for attachment scanning                         | ✅ Production |
| **[Executable Detection](#executable-detection)**     | Detects 195+ dangerous file extensions + magic number verification | ✅ Production |
| **[NSFW Image Detection](#nsfw-image-detection)**     | TensorFlow.js-powered image content analysis                       | ✅ Production |
| **[Toxicity Detection](#toxicity-detection)**         | AI-powered toxic language detection (threats, insults, harassment) | ✅ Production |
| **[Macro Detection](#macro-detection)**               | VBA, PowerShell, JavaScript, Batch script detection in attachments | ✅ Production |
| **[Language Detection](#language-detection)**         | Hybrid franc/lande detection for 40+ languages                     | ✅ Production |
| **[Pattern Recognition](#pattern-recognition)**       | Credit cards, phone numbers, IPs, Bitcoin addresses, etc.          | ✅ Production |
| **[URL Analysis](#url-analysis)**                     | TLD parsing, Cloudflare blocking detection, suspicious domains     | ✅ Production |

### Naive Bayes Classifier

Our Naive Bayesian classifier is available in this [repository](classifier.json), the npm package, and is updated frequently as it gains upstream, anonymous, SHA-256 hashed data from [Forward Email](https://forwardemail.net).

* **Training Data**: 100,000+ spam and ham emails
* **Accuracy**: 88%+ classification accuracy
* **Languages**: Supports 40+ languages with language-specific tokenization
* **Stemming**: Porter Stemmer for English, Snowball for 15+ other languages
* **Privacy**: All training data is anonymized and SHA-256 hashed

### Phishing Detection

Advanced phishing detection using multiple techniques:

* **IDN Homograph Detection**: Detects lookalike domains (e.g., `аpple.com` using Cyrillic "а")
* **Confusables Integration**: Uses Unicode confusables database to detect character substitution
* **TLD Analysis**: Validates TLDs and detects suspicious domain patterns
* **Link Analysis**: Checks for mismatched display text and actual URLs
* **Cloudflare Detection**: Identifies domains blocked by Cloudflare

### Virus Scanning

Integrates with ClamAV for comprehensive virus detection:

* **Real-time Scanning**: Scans all email attachments
* **Buffer Support**: Direct buffer scanning without file I/O
* **Timeout Protection**: Configurable scan timeouts
* **Virus Database**: Uses ClamAV's regularly updated virus definitions

### Executable Detection

Detects dangerous executable files:

* **195+ File Extensions**: exe, dll, bat, vbs, ps1, scr, pif, cmd, com, etc.
* **Magic Number Verification**: Detects renamed executables by file content
* **Office Macros**: Detects macro-enabled Office documents (docm, xlsm, pptm)
* **Legacy Office**: Flags legacy Office formats (doc, xls, ppt) as high-risk
* **PDF JavaScript**: Detects malicious JavaScript in PDF files
* **Archive Detection**: Flags archives (zip, rar, 7z) that may hide executables

### NSFW Image Detection

AI-powered image content analysis using TensorFlow\.js:

* **Categories**: Porn, Hentai, Sexy, Neutral, Drawing
* **Model**: NSFWJS model trained on 60K+ images
* **Threshold**: Configurable detection threshold (default: 0.7)
* **Performance**: Model caching for fast subsequent scans
* **Formats**: Supports JPEG, PNG, GIF, WebP, BMP

### Toxicity Detection

Detects toxic language using TensorFlow\.js Toxicity model:

* **Categories**: Identity attack, insult, obscenity, severe toxicity, sexual explicit, threat
* **Threshold**: Configurable toxicity threshold (default: 0.7)
* **Languages**: Optimized for English, supports other languages
* **Performance**: Model caching for fast subsequent scans

### Macro Detection

Detects malicious macros in email content and attachments:

* **VBA Macros**: Detects Visual Basic for Applications code
* **PowerShell**: Detects PowerShell scripts and commands
* **JavaScript**: Detects JavaScript code in emails
* **Batch Scripts**: Detects Windows batch files
* **Office Documents**: Scans docm, xlsm, pptm, xlam, dotm, xltm, potm
* **PDF JavaScript**: Detects JavaScript in PDF attachments

### Language Detection

Hybrid language detection using franc and lande:

* **40+ Languages**: Supports all major world languages
* **Automatic Detection**: Detects language from email content
* **Fallback System**: Uses lande when franc returns "undetermined"
* **Mixed Language Support**: Optional mixed language detection
* **Language Filtering**: Filter results to supported languages only

### Pattern Recognition

Detects various patterns in email content:

* **Credit Cards**: Visa, MasterCard, Amex, Discover, etc.
* **Phone Numbers**: International phone number formats
* **Email Addresses**: RFC-compliant email detection
* **IP Addresses**: IPv4 and IPv6 addresses
* **URLs**: Full URL extraction and analysis
* **Bitcoin Addresses**: Cryptocurrency wallet addresses
* **MAC Addresses**: Network hardware addresses
* **Hex Colors**: Color codes (#RRGGBB)
* **Floating Point Numbers**: Decimal numbers
* **Dates**: Multiple date formats (MM/DD/YYYY, YYYY-MM-DD, etc.)
* **File Paths**: Windows and Unix file paths

### URL Analysis

Comprehensive URL analysis and validation:

* **TLD Parsing**: Uses tldts for accurate TLD extraction
* **Domain Analysis**: Extracts domain, subdomain, public suffix
* **IP Detection**: Identifies IP-based URLs
* **Cloudflare Check**: Detects Cloudflare-blocked domains
* **URL Normalization**: Normalizes URLs for consistent analysis
* **Suspicious Pattern Detection**: Identifies phishing URL patterns

---


## Comparison

### Spam Scanner vs. Alternatives

| Feature                       | Spam Scanner |  SpamAssassin |     rspamd    |  ClamAV |
| ----------------------------- | :----------: | :-----------: | :-----------: | :-----: |
| **License**                   |    BSL 1.1   |   Apache 2.0  |   Apache 2.0  |  GPLv2  |
| **Language**                  |    Node.js   |      Perl     |       C       |    C    |
| **Modern Architecture**       |      Yes     |       No      |    Partial    |    No   |
| **Easy to Use**               |      Yes     |       No      |       No      |   Yes   |
| **Privacy-Focused**           |      Yes     |    Partial    |    Partial    |   Yes   |
| **Naive Bayes Classifier**    |      Yes     |      Yes      |      Yes      |    No   |
| **Virus Scanning**            |      Yes     |      Yes      |      Yes      |   Yes   |
| **Phishing Detection**        |      Yes     |      Yes      |      Yes      |    No   |
| **IDN Homograph Detection**   |      Yes     |       No      |      Yes      |    No   |
| **NSFW Image Detection**      |      Yes     |       No      |       No      |    No   |
| **Toxicity Detection**        |      Yes     |       No      |       No      |    No   |
| **Macro Detection**           |      Yes     |      Yes      |      Yes      |   Yes   |
| **Language Detection**        |   Yes (40+)  | Yes (limited) | Yes (limited) |    No   |
| **Pattern Recognition**       |      Yes     |      Yes      |      Yes      |    No   |
| **Executable Detection**      |  Yes (195+)  |      Yes      |      Yes      |   Yes   |
| **Magic Number Verification** |      Yes     |       No      |       No      |   Yes   |
| **PDF JavaScript Detection**  |      Yes     |       No      |       No      | Partial |
| **Archive Detection**         |      Yes     |      Yes      |      Yes      |   Yes   |
| **Performance Metrics**       |      Yes     |       No      |      Yes      |    No   |
| **TypeScript Support**        |      Yes     |       No      |       No      |    No   |
| **Active Development**        |      Yes     |      Yes      |      Yes      |   Yes   |
| **Production Ready**          |      Yes     |      Yes      |      Yes      |   Yes   |

> \[!NOTE]
> **Alternative to SpamAssassin**: Spam Scanner provides a modern, Node.js-based alternative to SpamAssassin with AI-powered features and better privacy.
>
> **Alternative to rspamd**: Spam Scanner offers easier configuration and better documentation than rspamd, with comparable detection accuracy.
>
> **Alternative to ClamAV**: While Spam Scanner uses ClamAV for virus scanning, it provides comprehensive spam and phishing detection that ClamAV doesn't offer.

---


## Architecture

### System Overview

```mermaid
graph TB
    A[Email Input] --> B{Spam Scanner}
    B --> C[Preprocessing]
    C --> D[Language Detection]
    D --> E[Tokenization]
    E --> F[Naive Bayes Classification]
    
    B --> G[Phishing Detection]
    G --> G1[IDN Homograph Check]
    G --> G2[Confusables Analysis]
    G --> G3[URL Analysis]
    
    B --> H[Attachment Scanning]
    H --> H1[Virus Scan]
    H --> H2[Executable Check]
    H --> H3[Macro Detection]
    H --> H4[NSFW Detection]
    
    B --> I[Content Analysis]
    I --> I1[Toxicity Detection]
    I --> I2[Pattern Recognition]
    
    F --> J[Result Aggregation]
    G --> J
    H --> J
    I --> J
    
    J --> K{Is Spam?}
    K -->|Yes| L[Spam Result]
    K -->|No| M[Ham Result]
```

### Detection Flow

```mermaid
sequenceDiagram
    participant Client
    participant Scanner
    participant Classifier
    participant ClamAV
    participant TensorFlow
    
    Client->>Scanner: scan(email)
    Scanner->>Scanner: Parse Email
    Scanner->>Scanner: Extract URLs
    Scanner->>Scanner: Detect Language
    
    par Parallel Detection
        Scanner->>Classifier: Classify Tokens
        Scanner->>ClamAV: Scan Attachments
        Scanner->>TensorFlow: Detect NSFW
        Scanner->>TensorFlow: Detect Toxicity
        Scanner->>Scanner: Check Phishing
        Scanner->>Scanner: Check Macros
    end
    
    Scanner->>Scanner: Aggregate Results
    Scanner->>Client: Return Result
```

### Component Architecture

```mermaid
graph LR
    A[Spam Scanner] --> B[Core Engine]
    A --> C[Classifiers]
    A --> D[Detectors]
    A --> E[Analyzers]
    
    B --> B1[Email Parser]
    B --> B2[Tokenizer]
    B --> B3[Preprocessor]
    
    C --> C1[Naive Bayes]
    C --> C2[TensorFlow NSFW]
    C --> C3[TensorFlow Toxicity]
    
    D --> D1[Phishing Detector]
    D --> D2[Virus Scanner]
    D --> D3[Macro Detector]
    D --> D4[Executable Detector]
    
    E --> E1[Language Analyzer]
    E --> E2[URL Analyzer]
    E --> E3[Pattern Analyzer]
```

---


## Requirements

> \[!WARNING]
> ClamAV is required for virus scanning. If you do not have it installed, virus scanning will be disabled.

### System Requirements

* **Node.js**: >= 18.0.0
* **ClamAV**: Latest version (for virus scanning)
* **Memory**: 2GB+ RAM recommended (for TensorFlow models)
* **Disk Space**: 500MB+ (for models and virus definitions)

### Dependencies

* **@tensorflow/tfjs-node**: For NSFW and toxicity detection
* **@ladjs/naivebayes**: For spam classification
* **clamscan**: For virus scanning
* **mailparser**: For email parsing
* **natural**: For NLP and tokenization
* **tldts**: For TLD parsing
* **confusables**: For Unicode confusables detection

---


## Installation

```bash
npm install spamscanner
```

### ClamAV Installation

#### macOS

```bash
brew install clamav
freshclam
```

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install clamav clamav-daemon
sudo freshclam
sudo systemctl start clamav-daemon
```

#### CentOS/RHEL

```bash
sudo yum install clamav clamav-update
sudo freshclam
```

> \[!TIP]
> See the [ClamAV configuration guide](https://github.com/spamscanner/spamscanner/blob/master/docs/clamav.md) for detailed installation instructions.

---


## Quick Start

### Basic Usage

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner();

// Raw email string or Buffer
const email = `
From: sender@example.com
To: recipient@example.com
Subject: Test Email

This is a test email.
`;

const result = await scanner.scan(email);

console.log(result);
// {
//   isSpam: false,
//   message: 'Ham',
//   results: { ... },
//   ...
// }
```

### With Configuration

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({
  // Enable performance metrics
  enablePerformanceMetrics: true,
  
  // Filter to supported languages
  supportedLanguages: ['en', 'es', 'fr', 'de'],
  
  // Enable macro detection
  enableMacroDetection: true,
  
  // Set scan timeout
  timeout: 30000,
  
  // Custom ClamAV configuration
  clamscan: {
    preference: 'clamdscan',
    clamdscanPath: '/usr/bin/clamdscan',
  },
});

const result = await scanner.scan(email);
```

### Checking Specific Features

```js
// Check if email is spam
if (result.isSpam) {
  console.log('Spam detected!');
  console.log('Reason:', result.message);
}

// Check for viruses
if (result.results.viruses && result.results.viruses.length > 0) {
  console.log('Viruses found:', result.results.viruses);
}

// Check for phishing
if (result.results.phishing && result.results.phishing.length > 0) {
  console.log('Phishing detected:', result.results.phishing);
}

// Check for executables
if (result.results.executables && result.results.executables.length > 0) {
  console.log('Executables found:', result.results.executables);
}

// Check for NSFW content
if (result.results.nsfw && result.results.nsfw.length > 0) {
  console.log('NSFW content detected:', result.results.nsfw);
}

// Check for toxic language
if (result.results.toxicity && result.results.toxicity.length > 0) {
  console.log('Toxic language detected:', result.results.toxicity);
}
```

---


## API Documentation

### Constructor Options

#### `new SpamScanner(options)`

Creates a new Spam Scanner instance.

##### Options

| Option                             | Type          | Default   | Description                                                                   |
| ---------------------------------- | ------------- | --------- | ----------------------------------------------------------------------------- |
| `enableMacroDetection`             | `boolean`     | `true`    | Enable macro detection in emails and attachments                              |
| `enablePerformanceMetrics`         | `boolean`     | `false`   | Track and return performance metrics                                          |
| `timeout`                          | `number`      | `30000`   | Timeout in milliseconds for scans (virus, URL checks)                         |
| `supportedLanguages`               | `string[]`    | `['en']`  | Array of supported language codes. Empty array `[]` = all languages supported |
| `enableMixedLanguageDetection`     | `boolean`     | `false`   | Enable detection of mixed languages in emails                                 |
| `enableAdvancedPatternRecognition` | `boolean`     | `true`    | Enable advanced pattern recognition (credit cards, phones, etc.)              |
| `toxicityThreshold`                | `number`      | `0.7`     | Threshold for toxicity detection (0.0-1.0, higher = more strict)              |
| `nsfwThreshold`                    | `number`      | `0.6`     | Threshold for NSFW detection (0.0-1.0, higher = more strict)                  |
| `debug`                            | `boolean`     | `false`   | Enable debug logging                                                          |
| `logger`                           | `object`      | `console` | Custom logger object (must have `log`, `error`, `warn` methods)               |
| `clamscan`                         | `object`      | See below | ClamAV configuration options                                                  |
| `classifier`                       | `object`      | `null`    | Custom Naive Bayes classifier data                                            |
| `replacements`                     | `Map\|object` | `null`    | Custom text replacements for preprocessing                                    |

##### ClamAV Options (`clamscan`)

| Option               | Type           | Default                | Description                                      |
| -------------------- | -------------- | ---------------------- | ------------------------------------------------ |
| `removeInfected`     | `boolean`      | `false`                | Remove infected files                            |
| `quarantineInfected` | `boolean`      | `false`                | Quarantine infected files                        |
| `scanLog`            | `string\|null` | `null`                 | Path to scan log file                            |
| `debugMode`          | `boolean`      | `false`                | Enable ClamAV debug mode                         |
| `fileList`           | `string\|null` | `null`                 | Path to file list                                |
| `scanRecursively`    | `boolean`      | `true`                 | Scan directories recursively                     |
| `clamscanPath`       | `string`       | `'/usr/bin/clamscan'`  | Path to clamscan binary                          |
| `clamdscanPath`      | `string`       | `'/usr/bin/clamdscan'` | Path to clamdscan binary                         |
| `preference`         | `string`       | `'clamdscan'`          | Preferred scanner: `'clamdscan'` or `'clamscan'` |

##### Example

```js
const scanner = new SpamScanner({
  enableMacroDetection: true,
  enablePerformanceMetrics: true,
  timeout: 60000,
  supportedLanguages: ['en', 'es', 'fr', 'de', 'ja', 'zh'],
  enableMixedLanguageDetection: false,
  enableAdvancedPatternRecognition: true,
  debug: false,
  logger: console,
  clamscan: {
    preference: 'clamdscan',
    clamdscanPath: '/usr/bin/clamdscan',
    scanRecursively: true,
    debugMode: false,
  },
});
```

---

### Methods

#### `scanner.scan(source)`

Scans an email for spam, viruses, phishing, and other threats.

##### Parameters

* `source` (`string` | `Buffer`) - Raw email content (RFC 822 format)

##### Returns

`Promise<object>` - Scan result object (see [Result Object](#result-object))

##### Example

```js
const result = await scanner.scan(emailString);
```

##### Edge Cases

* **Empty email**: Returns `isSpam: false` with empty results
* **Invalid email format**: Attempts to parse, may return partial results
* **Timeout**: Returns partial results if scan exceeds `timeout` option
* **ClamAV unavailable**: Skips virus scanning, continues with other checks
* **TensorFlow model loading**: First scan may take 30+ seconds, subsequent scans are fast (models cached)

---

#### `scanner.getTokensAndMailFromSource(source)`

Parses email and extracts tokens for classification.

##### Parameters

* `source` (`string` | `Buffer`) - Raw email content

##### Returns

`Promise<object>` - Object with `tokens` (array) and `mail` (parsed email object)

##### Example

```js
const {tokens, mail} = await scanner.getTokensAndMailFromSource(emailString);
console.log('Tokens:', tokens);
console.log('Subject:', mail.subject);
```

---

#### `scanner.getClassification(tokens)`

Classifies tokens as spam or ham using Naive Bayes classifier.

##### Parameters

* `tokens` (`string[]`) - Array of tokens from email

##### Returns

`Promise<object>` - Classification result with `category` and `probability`

##### Example

```js
const classification = await scanner.getClassification(tokens);
console.log('Category:', classification.category); // 'spam' or 'ham'
console.log('Probability:', classification.probability); // 0.0 - 1.0
```

---

#### `scanner.getPhishingResults(mail)`

Detects phishing attempts in email.

##### Parameters

* `mail` (`object`) - Parsed email object from `mailparser`

##### Returns

`Promise<array>` - Array of phishing detection results

##### Example

```js
const phishing = await scanner.getPhishingResults(mail);
// [
//   {
//     type: 'idn_homograph',
//     domain: 'аpple.com',
//     message: 'IDN homograph attack detected'
//   }
// ]
```

---

#### `scanner.getExecutableResults(mail)`

Detects executable files in email attachments.

##### Parameters

* `mail` (`object`) - Parsed email object from `mailparser`

##### Returns

`Promise<array>` - Array of executable detection results

##### Example

```js
const executables = await scanner.getExecutableResults(mail);
// [
//   {
//     filename: 'malware.exe',
//     type: 'executable',
//     extension: 'exe',
//     risk: 'high'
//   }
// ]
```

---

#### `scanner.getVirusResults(mail)`

Scans email attachments for viruses using ClamAV.

##### Parameters

* `mail` (`object`) - Parsed email object from `mailparser`

##### Returns

`Promise<array>` - Array of virus detection results

##### Example

```js
const viruses = await scanner.getVirusResults(mail);
// [
//   {
//     filename: 'infected.pdf',
//     virus: ['Trojan.PDF.Generic'],
//     type: 'virus'
//   }
// ]
```

---

#### `scanner.getMacroResults(mail)`

Detects macros in email content and attachments.

##### Parameters

* `mail` (`object`) - Parsed email object from `mailparser`

##### Returns

`Promise<array>` - Array of macro detection results

##### Example

```js
const macros = await scanner.getMacroResults(mail);
// [
//   {
//     type: 'vba_macro',
//     message: 'VBA macro detected in email content'
//   }
// ]
```

---

#### `scanner.getNSFWResults(mail)`

Detects NSFW content in image attachments using TensorFlow\.js.

##### Parameters

* `mail` (`object`) - Parsed email object from `mailparser`

##### Returns

`Promise<array>` - Array of NSFW detection results

##### Example

```js
const nsfw = await scanner.getNSFWResults(mail);
// [
//   {
//     type: 'nsfw',
//     filename: 'image.jpg',
//     category: 'Porn',
//     probability: 0.85,
//     description: 'NSFW image detected: Porn (85.0%)'
//   }
// ]
```

---

#### `scanner.getToxicityResults(mail)`

Detects toxic language in email content using TensorFlow\.js.

##### Parameters

* `mail` (`object`) - Parsed email object from `mailparser`

##### Returns

`Promise<array>` - Array of toxicity detection results

##### Example

```js
const toxicity = await scanner.getToxicityResults(mail);
// [
//   {
//     type: 'toxicity',
//     category: 'threat',
//     probability: 0.92,
//     description: 'Toxic content detected: threat (92.0%)'
//   },
//   {
//     type: 'toxicity',
//     category: 'insult',
//     probability: 0.78,
//     description: 'Toxic content detected: insult (78.0%)'
//   }
// ]
```

---

#### `scanner.getTokens(str, locale, isHTML)`

Tokenizes text for classification.

##### Parameters

* `str` (`string`) - Text to tokenize
* `locale` (`string`) - Language code (e.g., "en", "es", "fr")
* `isHTML` (`boolean`) - Whether text contains HTML (default: `false`)

##### Returns

`Promise<string[]>` - Array of tokens

##### Example

```js
const tokens = await scanner.getTokens('Hello world', 'en', false);
// ['hello', 'world']
```

---

#### `scanner.parseLocale(locale)`

Normalizes language codes to standard format.

##### Parameters

* `locale` (`string`) - Language code or locale string

##### Returns

`string` - Normalized language code

##### Example

```js
const normalized = scanner.parseLocale('en-US');
// 'en'
```

---

#### `scanner.detectLanguageHybrid(text)`

Detects language using hybrid franc/lande approach.

##### Parameters

* `text` (`string`) - Text to analyze

##### Returns

`Promise<string>` - Detected language code

##### Example

```js
const language = await scanner.detectLanguageHybrid('Bonjour le monde');
// 'fr'
```

---

#### `scanner.extractAllUrls(mail, originalSource)`

Extracts all URLs from email.

##### Parameters

* `mail` (`object`) - Parsed email object
* `originalSource` (`string`) - Original email source

##### Returns

`string[]` - Array of URLs

##### Example

```js
const urls = scanner.extractAllUrls(mail, emailString);
// ['https://example.com', 'http://test.com']
```

---

#### `scanner.parseUrlWithTldts(url)`

Parses URL using tldts for accurate TLD extraction.

##### Parameters

* `url` (`string`) - URL to parse

##### Returns

`object` - Parsed URL components

##### Example

```js
const parsed = scanner.parseUrlWithTldts('https://subdomain.example.co.uk/path');
// {
//   domain: 'example.co.uk',
//   subdomain: 'subdomain',
//   hostname: 'subdomain.example.co.uk',
//   publicSuffix: 'co.uk',
//   isIp: false
// }
```

---

### Result Object

The `scan()` method returns a comprehensive result object:

```js
{
  // Overall spam classification
  isSpam: boolean,
  message: string, // 'Ham' or 'Spam: <reasons>'
  
  // Detection results
  results: {
    // Classification details
    classification: {
      category: 'spam' | 'ham',
      probability: number
    },
    
    // Phishing detection
    phishing: [
      {
        type: 'idn_homograph' | 'suspicious_link' | 'confusables',
        domain: string,
        message: string
      }
    ],
    
    // Executable detection
    executables: [
      {
        filename: string,
        type: 'executable' | 'office_document' | 'legacy_office' | 'pdf_javascript' | 'archive',
        extension: string,
        risk: 'high' | 'medium' | 'low'
      }
    ],
    
    // Macro detection
    macros: [
      {
        type: 'vba_macro' | 'powershell' | 'javascript' | 'batch',
        message: string
      }
    ],
    
    // Arbitrary results (custom detections)
    arbitrary: [],
    
    // Virus scanning
    viruses: [
      {
        filename: string,
        virus: string[],
        type: 'virus'
      }
    ],
    
    // Pattern recognition
    patterns: {
      credit_cards: number,
      phone_numbers: number,
      emails: number,
      ips: number,
      urls: number,
      bitcoin: number,
      dates: number,
      file_paths: number
    },
    
    // IDN homograph attack detection
    idnHomographAttack: [],
    
    // Toxicity detection (array of results)
    toxicity: [
      {
        type: 'toxicity',
        category: 'identity_attack' | 'insult' | 'obscene' | 'severe_toxicity' | 'sexual_explicit' | 'threat',
        probability: number,
        description: string
      }
    ],
    
    // NSFW detection (array of results)
    nsfw: [
      {
        type: 'nsfw',
        filename: string,
        category: 'Porn' | 'Hentai' | 'Sexy' | 'Neutral' | 'Drawing',
        probability: number,
        description: string
      }
    ]
  },
  
  // All URLs extracted from email
  links: string[],
  
  // Tokens extracted from email
  tokens: string[],
  
  // Email metadata
  mail: {
    from: object,
    to: object[],
    subject: string,
    text: string,
    html: string,
    attachments: object[],
    headers: object
  },
  
  // Performance metrics (if enabled)
  metrics: {
    totalTime: number, // milliseconds
    classificationTime: number,
    phishingTime: number,
    executableTime: number,
    macroTime: number,
    virusTime: number,
    patternTime: number,
    idnTime: number,
    memoryUsage: object
  }
}
```

---


## Advanced Usage

### Custom Classifier

```js
import SpamScanner from 'spamscanner';
import NaiveBayes from '@ladjs/naivebayes';

// Train custom classifier
const classifier = new NaiveBayes();
classifier.learn('buy viagra now', 'spam');
classifier.learn('hello friend', 'ham');

const scanner = new SpamScanner({
  classifier: classifier.toJson()
});
```

### Custom Text Replacements

```js
const scanner = new SpamScanner({
  replacements: new Map([
    ['u', 'you'],
    ['ur', 'your'],
    ['r', 'are'],
    ['b4', 'before']
  ])
});
```

### Language Filtering

```js
// Only accept English, Spanish, and French emails
const scanner = new SpamScanner({
  supportedLanguages: ['en', 'es', 'fr']
});

// Accept all languages
const scanner2 = new SpamScanner({
  supportedLanguages: []
});
```

### Performance Monitoring

```js
const scanner = new SpamScanner({
  enablePerformanceMetrics: true
});

const result = await scanner.scan(email);

console.log('Total scan time:', result.metrics.totalTime, 'ms');
console.log('Classification time:', result.metrics.classificationTime, 'ms');
console.log('Virus scan time:', result.metrics.virusScanTime, 'ms');
```

### Selective Feature Disabling

```js
// Disable macro detection for performance
const scanner = new SpamScanner({
  enableMacroDetection: false
});

// Disable advanced pattern recognition
const scanner2 = new SpamScanner({
  enableAdvancedPatternRecognition: false
});
```

### Custom Timeout

```js
// Set 60-second timeout for slow scans
const scanner = new SpamScanner({
  timeout: 60000
});
```

### Custom Logger

```js
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'spam-scanner.log' })
  ]
});

const scanner = new SpamScanner({
  debug: true,
  logger: logger
});
```

---


## Performance

### Benchmarks

| Scan Type                   | First Scan   | Subsequent Scans | Notes                    |
| --------------------------- | ------------ | ---------------- | ------------------------ |
| **Small Email** (< 10KB)    | 2-3s         | 200-500ms        | No attachments           |
| **Medium Email** (10-100KB) | 3-5s         | 500ms-1s         | 1-2 attachments          |
| **Large Email** (100KB-1MB) | 5-10s        | 1-3s             | Multiple attachments     |
| **With NSFW Detection**     | +30s (first) | +100-200ms       | TensorFlow model loading |
| **With Toxicity Detection** | +30s (first) | +100-200ms       | TensorFlow model loading |

> \[!NOTE]
> First scans with TensorFlow models (NSFW/toxicity) take 30+ seconds due to model loading. Subsequent scans are fast because models are cached in memory.

### Optimization Tips

1. **Model Caching**: Keep scanner instance alive to cache TensorFlow models
2. **Disable Unused Features**: Turn off macro detection or pattern recognition if not needed
3. **Adjust Timeout**: Increase timeout for large emails with many attachments
4. **Use clamdscan**: Prefer `clamdscan` over `clamscan` for faster virus scanning
5. **Limit Languages**: Specify `supportedLanguages` to skip unnecessary language detection

### Memory Usage

* **Base**: 50-100MB
* **With TensorFlow Models**: 500MB-1GB
* **Per Scan**: 10-50MB (temporary)

---


## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/spamscanner/spamscanner.git
cd spamscanner

# Install dependencies
pnpm install

# Run tests
npm test

# Run tests with coverage
npm run test-coverage

# Build
pnpm run build
```

### Running Tests

```bash
# All tests
npm test

# Specific test file
node --test test/test.js

# With coverage
npm run test-coverage
```

---


## License

[Business Source License 1.1](LICENSE) © [Forward Email](https://forwardemail.net)


## Support

* **Documentation**: <https://spamscanner.net>
* **Issues**: [GitHub Issues](https://github.com/spamscanner/spamscanner/issues)
* **Email**: <mailto:support@forwardemail.net>

---


## Acknowledgments

* [Forward Email](https://forwardemail.net) - Production usage and testing
* [TensorFlow.js](https://www.tensorflow.org/js) - NSFW and toxicity detection
* [ClamAV](https://www.clamav.net/) - Virus scanning
* [Natural](https://github.com/NaturalNode/natural) - NLP and tokenization
* [tldts](https://github.com/remusao/tldts) - TLD parsing
* [confusables](https://github.com/gc/confusables) - Unicode confusables detection

---

> Made with ❤️ by the [Forward Email](https://forwardemail.net) team
