<!-- source: b3cc9f949acd -->

# API-reference

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Opret én scanner, og genbrug den: den indlæser modellen én gang og cacher svar fra DNS og sprogmodeller.


## Indstillinger

Alle indstillinger kan gives til konstruktøren. De fleste kan også gives til `scan()` for en enkelt besked, og de flettes da oven på konstruktørens.

| Indstilling             | Standard                         | Betydning                                                                                                          |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `threshold`             | `5`                              | Score, hvor en besked er spam                                                                                      |
| `rejectThreshold`       | `15`                             | Score, hvor `action` er `reject`                                                                                   |
| `scores`                | `{}`                             | Point pr. test: indstillingsnøgler eller testnavne ([test og scorer](scoring.md))                                  |
| `classifier`            | medfølgende model                | En `Classifier`, et modelobjekt, en sti til en modelfil eller `false`                                              |
| `classifierOptions`     | `{}`                             | Indstillinger for den medfølgende model (se [Classifier](#classifier))                                             |
| `allowedLanguages`      | `[]`                             | ISO 639-1-koder; andre sprog får `LANGUAGE_NOT_ALLOWED`                                                            |
| `phishing.cloudflare`   | `true`                           | Spørg Cloudflares filtrerende resolvere om værter i links                                                          |
| `phishing.adult`        | `true`                           | Spørg også familieresolveren, som blokerer voksenwebsteder                                                         |
| `phishing.maxHosts`     | `25`                             | Værter i links, der slås op pr. besked                                                                             |
| `phishing.homograph`    | `{}`                             | `brands` (erstatter den indbyggede liste), `extraBrands`, `allowlist` (domæner, der aldrig markeres), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS-blokeringslistezoner for klientens IP og for domæner i links                                                   |
| `dns`                   | `{servers: null, timeout: 3000}` | Navneservere til DNS-tjek (standard: systemets)                                                                    |
| `attachments`           | `true`                           | Undersøg vedhæftede filer                                                                                          |
| `macros`                | `true`                           | Markér makroer, aktive PDF'er og RTF-objekter                                                                      |
| `arbitrary`             | `true`                           | Kør [reglerne](scoring.md#rules)                                                                                   |
| `authentication`        | `false`                          | `true` eller `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                          |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                  |
| `allowlist`, `denylist` |                                  | IP-adresser, domæner eller adresser; kortform for `reputation`                                                     |
| `clamav`                | `false`                          | `true` (standardsocket), `{socket}` eller `{host, port}`                                                           |
| `llm`                   | `null`                           | [Indstillinger for sprogmodellen](llm.md#any-server-port-and-authentication) med `mode`, `minScore`, `maxScore`    |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: en model, hvis `classify([text])` svarer som `@tensorflow-models/toxicity`             |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: en model, hvis `classify(imageBuffer)` svarer som `nsfwjs`                             |
| `maxLength`             | `100000`                         | Antal tegn af brødteksten, der læses                                                                               |
| `timeout`               | `10000`                          | Millisekunder, der er tilladt for hvert netværkstjek                                                               |
| `session`               | `{}`                             | Standardoplysninger om SMTP-sessionen                                                                              |

`scan()` tager også `session`:

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


## Metoder

| Metode                               | Returnerer                                                                            |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Resultatet. `source` er en Buffer, en streng, et Uint8Array eller en læsbar stream    |
| `scanFile(path, options)`            | Resultatet for en beskedfil                                                           |
| `learn(source, 'spam' \| 'ham')`     | Lærer klassifikatoren én besked                                                       |
| `unlearn(source, 'spam' \| 'ham')`   | Fortryder `learn`                                                                     |
| `saveModel(path, options)`           | Skriver klassifikatoren til en fil (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Den `Classifier`, der er i brug, eller `null`                                         |
| `getClassification(features)`        | Klassifikatorens dom for features fra `getFeatures`                                   |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` for en fortolket besked                  |
| `getTokens(text, locale)`            | Ordene i en tekst                                                                     |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                            |
| `parse(source)`                      | `{raw, mail}`, med `mail` fra mailparser                                              |

`scanner.metrics` indeholder `totalScans`, `averageTime` og `lastScanTime`.


## Resultatet

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

Fund i `phishing`, `attachments`, `executables`, `macros`, `viruses` og `arbitrary` er objekter med en `type` og en `message`. `String(finding)` er beskeden.


## Eksporter

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

| Indstilling                            | Standard       | Betydning                                                          |
| -------------------------------------- | -------------- | ------------------------------------------------------------------ |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsons s og x: hvor kraftigt sjældne features trækkes mod 0,5   |
| `minDistance`                          | `0.1`          | Features, der ligger tættere på 0,5 end dette, ignoreres           |
| `maxClues`                             | `150`          | De stærkeste features, der kombineres pr. besked                   |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Grænserne for `unsure`-intervallet                                 |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Beskeder af hver klasse, der kræves på et sprog for fuld sikkerhed |
| `languagePrior`                        | `true`         | Vej ord mod tallene for deres eget sprog                           |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` og `entries()` er også tilgængelige.

### Træning

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` tager `{label, features}`-elementer eller `readExamples(sources)`, som læser de samme kilder som `train`, og returnerer optællinger, præcision, genkaldelse, F1, nøjagtighed samt andelen af falske positiver, falske negativer og usikre.

### Servere

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARF-rapporter

`spamscanner/arf` læser og skriver rapporter om misbrugsfeedback (RFC 5965), det format, som postkasseudbydere bruger til at indberette spamklager:

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

`ArfParser.tryParse()` returnerer `null` i stedet for at kaste en fejl for beskeder, der ikke er rapporter, og `isArfMessage(mail)` tjekker en fortolket besked.
