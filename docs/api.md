# API reference

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Create one scanner and reuse it: it loads the model once and caches DNS and language model answers.


## Options

Every option can be passed to the constructor. Most can also be passed to `scan()` for one message, which merges them over the constructor's.

| Option                  | Default                          | Meaning                                                                                                   |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Score at which a message is spam                                                                          |
| `rejectThreshold`       | `15`                             | Score at which `action` is `reject`                                                                       |
| `scores`                | `{}`                             | Points per test: setting keys or test names ([tests and scores](scoring.md))                              |
| `classifier`            | bundled model                    | A `Classifier`, a model object, a model file path, or `false`                                             |
| `classifierOptions`     | `{}`                             | Options for the bundled model (see [Classifier](#classifier))                                             |
| `allowedLanguages`      | `[]`                             | ISO 639-1 codes; other languages get `LANGUAGE_NOT_ALLOWED`                                               |
| `phishing.cloudflare`   | `true`                           | Ask Cloudflare's filtering resolvers about link hosts                                                     |
| `phishing.adult`        | `true`                           | Also ask the family resolver, which blocks adult sites                                                    |
| `phishing.maxHosts`     | `25`                             | Link hosts looked up per message                                                                          |
| `phishing.homograph`    | `{}`                             | `brands` (replace the built-in list), `extraBrands`, `allowlist` (domains never flagged), `strictMode`    |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS blocklist zones for the client IP and for link domains                                                |
| `dns`                   | `{servers: null, timeout: 3000}` | Name servers for DNS checks (default: the system's)                                                       |
| `attachments`           | `true`                           | Inspect attachments                                                                                       |
| `macros`                | `true`                           | Flag macros, active PDFs and RTF objects                                                                  |
| `arbitrary`             | `true`                           | Run the [rules](scoring.md#rules)                                                                         |
| `authentication`        | `false`                          | `true`, or `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                   |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                         |
| `allowlist`, `denylist` |                                  | IP addresses, domains or addresses; shorthand for `reputation`                                            |
| `clamav`                | `false`                          | `true` (default socket), `{socket}` or `{host, port}`                                                     |
| `llm`                   | `null`                           | [Language model settings](llm.md#any-server-port-and-authentication), with `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: a model whose `classify([text])` answers like `@tensorflow-models/toxicity`   |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: a model whose `classify(imageBuffer)` answers like `nsfwjs`                   |
| `maxLength`             | `100000`                         | Characters of body text read                                                                              |
| `timeout`               | `10000`                          | Milliseconds allowed for each network check                                                               |
| `session`               | `{}`                             | Default SMTP session details                                                                              |

`scan()` also takes `session`:

```js
await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',             // the client's IP address
    resolvedClientHostname: 'mx.example.com', // its verified reverse DNS name
    helo: 'mx.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```


## Methods

| Method                               | Returns                                                                            |
| ------------------------------------ | ---------------------------------------------------------------------------------- |
| `scan(source, options)`              | The result. `source` is a Buffer, string, Uint8Array or readable stream            |
| `scanFile(path, options)`            | The result for a message file                                                      |
| `learn(source, 'spam' \| 'ham')`     | Teaches the classifier one message                                                 |
| `unlearn(source, 'spam' \| 'ham')`   | Undoes `learn`                                                                     |
| `saveModel(path, options)`           | Writes the classifier to a file (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | The `Classifier` in use, or `null`                                                 |
| `getClassification(features)`        | The classifier's verdict for features from `getFeatures`                           |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` for a parsed message                  |
| `getTokens(text, locale)`            | The words of a text                                                                |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                         |
| `parse(source)`                      | `{raw, mail}`, with `mail` from mailparser                                         |

`scanner.metrics` holds `totalScans`, `averageTime` and `lastScanTime`.


## The result

```js
{
  isSpam: true,
  score: 16.25,
  threshold: 5,
  rejectThreshold: 15,
  action: 'reject',                       // 'accept', 'tag' or 'reject'
  message: 'Spam (BAYES_999, PHISHING_LOOKALIKE_DOMAIN, DECEPTIVE_LINK, FROM_NAME_BRAND)',
  tests: [
    {name: 'BAYES_999', score: 6.25, description: 'Classifier spam probability 99.9%'},
    {name: 'PHISHING_LOOKALIKE_DOMAIN', score: 5, description: '"paypa1-secure.top" imitates paypal by swapping characters'},
    // ...
  ],
  results: {
    classification: {probability, category, spam, ham, clues, coverage},
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'],
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser */},
  version: '7.0.0',
  metrics: {totalTime: 42},
}
```

Findings in `phishing`, `attachments`, `executables`, `macros`, `viruses` and `arbitrary` are objects with a `type` and a `message`. `String(finding)` is the message.


## Exports

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Option                                 | Default        | Meaning                                                              |
| -------------------------------------- | -------------- | -------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinson's s and x: how strongly rare features are pulled toward 0.5 |
| `minDistance`                          | `0.1`          | Features closer to 0.5 than this are ignored                         |
| `maxClues`                             | `150`          | Strongest features combined per message                              |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Bounds of the `unsure` range                                         |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Messages of each class needed in a language for full confidence      |
| `languagePrior`                        | `true`         | Weigh words against their own language's counts                      |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` and `entries()` are also available.

### Training

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` takes `{label, features}` items, or `readExamples(sources)`, which reads the same sources as `train`, and returns counts, precision, recall, F1, accuracy and false positive, false negative and unsure rates.

### Servers

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARF reports

`spamscanner/arf` reads and writes abuse feedback reports (RFC 5965), the format mailbox providers use to report spam complaints:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()` returns `null` instead of throwing for messages that are not reports, and `isArfMessage(mail)` checks a parsed message.
