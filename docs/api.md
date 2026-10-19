# API reference

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Create one scanner and reuse it: it loads the model once and caches DNS and language model answers.

Type declarations are included. They need TypeScript 4.7 or later with `import`, and 5.3 or later with `require`.


## Options

Every option can be passed to the constructor. Most can also be passed to `scan()` for one message, which merges them over the constructor's. Options passed as `undefined` keep their defaults. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` and `strictIDNDetection` are read by the constructor only; a model file or object given as `classifier` is read there, so a missing or damaged model throws at once.

| Option                  | Default                          | Meaning                                                                                                                                                              |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Score at which a message is spam                                                                                                                                     |
| `rejectThreshold`       | `15`                             | Score at which `action` is `reject`                                                                                                                                  |
| `scores`                | `{}`                             | Points per test: setting keys or test names ([tests and scores](scoring.md))                                                                                         |
| `classifier`            | bundled model                    | A `Classifier`, a model object, a model file path, or `false`                                                                                                        |
| `classifierOptions`     | `{}`                             | Options for the bundled model (see [Classifier](#classifier))                                                                                                        |
| `allowedLanguages`      | `[]`                             | ISO 639-1 codes (`no` is read as `nb`, `fil` as `tl`, and the old `iw`, `in`, `ji` as `he`, `id`, `yi`); other languages get `LANGUAGE_NOT_ALLOWED`                  |
| `phishing.cloudflare`   | `true`                           | Ask Cloudflare's filtering resolvers about link hosts                                                                                                                |
| `phishing.adult`        | `true`                           | Also ask the family resolver, which blocks adult sites                                                                                                               |
| `phishing.maxHosts`     | `25`                             | Link hosts looked up per message                                                                                                                                     |
| `phishing.maxLength`    | `1000000`                        | Characters of text read for links (twice as many of HTML); more text sets `results.linksTruncated`; `Infinity`, or anything but a positive number, means the default |
| `phishing.homograph`    | `{}`                             | `brands` (replace the built-in list), `extraBrands`, `allowlist` (domains never flagged), `strictMode`                                                               |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS blocklist zones for the client IP and for link domains                                                                                                           |
| `dns`                   | `{servers: null, timeout: 3000}` | Name servers for DNS checks (default: the system's)                                                                                                                  |
| `attachments`           | `true`                           | Inspect attachments                                                                                                                                                  |
| `macros`                | `true`                           | Flag macros, active PDFs and RTF objects                                                                                                                             |
| `arbitrary`             | `true`                           | Run the [rules](scoring.md#rules)                                                                                                                                    |
| `authentication`        | `false`                          | `true`, or `{dnsServers, timeout, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([scoring](scoring.md#authentication))                                    |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; answers are kept per service and headers, and `cacheSize` is the scanner's      |
| `allowlist`, `denylist` |                                  | IP addresses, domains or addresses; shorthand for `reputation` → [Allowlist and denylist](#allowlist-and-denylist)                                                   |
| `clamav`                | `false`                          | `true` (default socket), `{socket}` or `{host, port}`, with `timeout`: milliseconds for all of a message's attachments (`60000`)                                     |
| `llm`                   | `null`                           | [Language model settings](llm.md#any-server-port-and-authentication), with `mode`, `minScore`, `maxScore`                                                            |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: a model whose `classify([text])` answers like `@tensorflow-models/toxicity`                                                              |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: a model whose `classify(imageBuffer)` answers like `nsfwjs`                                                                              |
| `maxLength`             | `100000`                         | Characters of body text read                                                                                                                                         |
| `timeout`               | `10000`                          | Milliseconds allowed for each network check; authentication and the image model get this long in all (ClamAV has its own `clamav.timeout`)                           |
| `session`               | `{}`                             | Default SMTP session details                                                                                                                                         |

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

A server that has already checked SPF, DKIM, DMARC and ARC (with [mailauth](https://github.com/postalsys/mailauth)) can pass its results as `authenticationResults`, and they are scored instead of checked again:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Allowlist and denylist

The denylist matches the client's IP address and hostname, the From, envelope sender and Reply-To addresses, and their domains, whatever they are: a name under a denylisted domain matches it even if it is not a valid hostname (such as `a_b!.evil.example`, or one with a label of more than 63 characters), by its last 127 labels and 253 characters. The allowlist, and a reputation service's allowlist and truth sources, match only what a sender cannot forge: the client's IP address and verified hostname (`remoteAddress`, `resolvedClientHostname`), a From address when DMARC passes for its domain or a passing DKIM signature is aligned with it (and is a valid hostname; relaxed, as in DMARC: the From domain and the signing or SPF domain have the same registrable domain, which mailauth names as the DMARC domain; an entry naming a subdomain, such as `news.example.com`, counts only when that domain, one under it or a parent of it signed the message or passed SPF, not another subdomain such as `evil.example.com`, nor a public suffix; a DMARC pass for the registrable domain without mailauth's alignment details counts only for an entry naming the registrable domain; under strict alignment, `adkim=s` or `aspf=s` in the domain's DMARC record in any case or spacing, only a signature or SPF pass of the From domain itself counts, and DMARC fails without one), and the envelope sender when SPF passes for its domain. A DKIM signature of only the start of the body (a body length, `l=`, shorter than the body: anyone can add text after it) counts for nothing, nor does a DMARC pass that rests on one, and no signature counts when DMARC fails. Results passed in `authenticationResults` count only when they name the domain they passed for, and a domain that is not a hostname (such as `bank.example/x.attacker.example`, which URL parsers read as `bank.example`) counts for none, as does a DMARC pass that rests on one. International domains match in either form: `bücher.example` or `xn--bcher-kva.example`. Reply-To never counts. To allowlist a domain, turn on `authentication` or pass `authenticationResults`.

Each entry is one IP address, domain or email address, matched exactly: a domain entry also covers its subdomains and the addresses at them, but there are no address ranges (`192.0.2.0/24`), wildcards (`*.example.com`) or patterns (`@example.com`). IPv6 addresses match in any form (`2001:0db8::0001` is `2001:db8::1`, the form of RFC 5952), an IPv4 address mapped into IPv6 (`::ffff:192.0.2.1`) matches the IPv4 address, and an IPv4 address translated into IPv6 or under the NAT64 prefix is written with it in dotted form (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), in entries and client addresses alike.


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
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` of a message     |
| `getTokens(text, locale)`            | The words of a text                                                                |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                         |
| `parse(source)`                      | `{raw, mail}`, with `mail` from mailparser (see below)                             |

`scan`, `parse`, `learn`, `unlearn` and `getTokensAndMailFromSource` all read a message the same way: one beyond the MIME parser's limits (more than 1000 parts, a part's header over 1 MB) is read as far as the parser allows. Text whose first line is not a header field (`Name: value`, or the `From` line that starts each message in mbox files) is read as the body of a message with no header, so `mail.text` is that text. Other errors are thrown.

In `getFeatures`, `text` is the text a mail client shows, which the words are read from, and `hidden` how many characters of text the HTML hides. mailparser does not make text of HTML here: `mail.text` holds the plain text parts only, and is empty for a message of HTML alone; the text its HTML shows is `getFeatures(mail).text`.

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
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    virusScanErrors: [], // attachments ClamAV could not scan: {filename, error}
    virusScanSkipped: [], // attachments larger than clamd accepts, not scanned: {filename, reason}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value, answers} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'], // the links checked, of the whole message up to phishing.maxLength
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser; mail.text: the plain text parts only */},
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

Findings in `phishing`, `attachments`, `executables`, `macros`, `viruses` and `arbitrary` are objects with a `type` and a `message`. `String(finding)` is the message. Attachments of an attached message (`message/rfc822`, `.eml`) are named after it: `fw.eml/invoice.exe`. A virus ClamAV finds in such an attachment is reported for it alone, not again for the attached message that carries it. `virusScanErrors` lists the attachments ClamAV could not scan, as `{filename, error}`: such a message may hold a virus, so hold it rather than deliver it. The milter and the content filter defer it unless `onError` (`--on-error`) is `accept`, and every server marks such a message it passes on with `X-Spam-Virus-Scan: failed`. `virusScanSkipped` lists those larger than clamd accepts (its `StreamMaxLength`), as `{filename, reason}`: clamd refuses them on every try, so, as clamav-milter skips a file over its `MaxFileSize`, they are not failures. Its other limits (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), which an archive bomb reaches, are failures.

Each `dnsbl` item carries the list's `answers` (addresses in 127.0.0.0/8, whose meaning each list documents). The answers lists give queries they refuse or cannot answer are not listings, for the client's address or for link domains (`uribl` findings in `phishing`): 127.255.255.x at Spamhaus (such as 127.255.255.254 for a query through a public resolver, and 127.255.255.255 for too many queries), 127.0.1.255 at the Spamhaus DBL, 127.0.0.255 at any list, and 127.0.0.1 at SURBL and URIBL, which answer it to resolvers they block.


## Exports

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Option                                 | Default        | Meaning                                                                                                                                         |
| -------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinson's s and x: how strongly rare features are pulled toward 0.5                                                                            |
| `minDistance`                          | `0.1`          | Features closer to 0.5 than this are ignored                                                                                                    |
| `maxClues`                             | `150`          | Strongest features combined per message                                                                                                         |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Bounds of the `unsure` range                                                                                                                    |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Ham messages in a language needed for full confidence, and a fifth as many spam messages; fewer when `languageShare` of all ham or spam is less |
| `languagePrior`                        | `true`         | Weigh words against their own language's counts                                                                                                 |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` and `entries()` are also available. `Classifier.fromJSON` checks the model and throws a `TypeError` starting `Corrupt classifier model` on damaged data. JSON has no `Infinity`, so an option saved as `Infinity` by version 7.0.3 reads back as `null`: it is read as `Infinity` for `maxClues`, `minDistance` and `minLanguageExamples`, as `-Infinity` for `hamCutoff` (never ham) and `Infinity` for `spamCutoff` (never spam), and as the default for the others. `toJSON` saves a cutoff beyond 0 and 1 as -1 or 2, which works the same. `loadModel` reads a file again when it changes, and `saveModel` writes through a temporary file.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

The milter's `onError` is its answer when a scan fails or ClamAV could not scan an attachment: `'tempfail'` (the default) or `'accept'`, which passes the message on marked `X-Spam-Virus-Scan: failed`, without the `X-Spam-*` headers the sender added.

### ARF reports

`spamscanner/arf` reads and writes abuse feedback reports (RFC 5965), the format mailbox providers use to report spam complaints:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders?.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()` returns `null` instead of throwing for messages that are not reports, and `isArfMessage(mail)` checks a parsed message. `originalHeaders` is `null` for a report without the original message. `create()` returns a string, or a `Buffer` when `originalMessage` is one, so its bytes are kept whatever their character set.
