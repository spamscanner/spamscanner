<!-- source: b3cc9f949acd -->

# API-referens

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Skapa en skanner och återanvänd den: den läser in modellen en gång och cachar svar från DNS och språkmodellen.


## Alternativ

Alla alternativ kan skickas till konstruktorn. De flesta kan också skickas till `scan()` för ett enskilt meddelande, och slås då ihop ovanpå konstruktorns.

| Alternativ              | Standard                         | Betydelse                                                                                                        |
| ----------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Poäng där ett meddelande är spam                                                                                 |
| `rejectThreshold`       | `15`                             | Poäng där `action` är `reject`                                                                                   |
| `scores`                | `{}`                             | Poäng per test: inställningsnycklar eller testnamn ([tester och poäng](scoring.md))                              |
| `classifier`            | medföljande modell               | En `Classifier`, ett modellobjekt, en sökväg till en modellfil eller `false`                                     |
| `classifierOptions`     | `{}`                             | Alternativ för den medföljande modellen (se [Klassificerare](#classifier))                                       |
| `allowedLanguages`      | `[]`                             | ISO 639-1-koder; andra språk får `LANGUAGE_NOT_ALLOWED`                                                          |
| `phishing.cloudflare`   | `true`                           | Fråga Cloudflares filtrerande resolvrar om länkarnas värdar                                                      |
| `phishing.adult`        | `true`                           | Fråga även familjeresolvern, som blockerar webbplatser med vuxeninnehåll                                         |
| `phishing.maxHosts`     | `25`                             | Antal länkvärdar som slås upp per meddelande                                                                     |
| `phishing.homograph`    | `{}`                             | `brands` (ersätter den inbyggda listan), `extraBrands`, `allowlist` (domäner som aldrig flaggas), `strictMode`   |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS-blocklistzoner för klientens IP och för länkdomäner                                                          |
| `dns`                   | `{servers: null, timeout: 3000}` | Namnservrar för DNS-kontroller (standard: systemets)                                                             |
| `attachments`           | `true`                           | Granska bilagor                                                                                                  |
| `macros`                | `true`                           | Flagga makron, aktiva PDF-filer och RTF-objekt                                                                   |
| `arbitrary`             | `true`                           | Kör [reglerna](scoring.md#rules)                                                                                 |
| `authentication`        | `false`                          | `true`, eller `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                       |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                |
| `allowlist`, `denylist` |                                  | IP-adresser, domäner eller adresser; kortform för `reputation`                                                   |
| `clamav`                | `false`                          | `true` (standardsocket), `{socket}` eller `{host, port}`                                                         |
| `llm`                   | `null`                           | [Inställningar för språkmodellen](llm.md#any-server-port-and-authentication), med `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: en modell vars `classify([text])` svarar som `@tensorflow-models/toxicity`           |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: en modell vars `classify(imageBuffer)` svarar som `nsfwjs`                           |
| `maxLength`             | `100000`                         | Antal tecken i brödtexten som läses                                                                              |
| `timeout`               | `10000`                          | Millisekunder som tillåts för varje nätverkskontroll                                                             |
| `session`               | `{}`                             | Standardvärden för SMTP-sessionen                                                                                |

`scan()` tar också emot `session`:

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

| Metod                                | Returnerar                                                                             |
| ------------------------------------ | -------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Resultatet. `source` är en Buffer, en sträng, en Uint8Array eller en läsbar ström      |
| `scanFile(path, options)`            | Resultatet för en meddelandefil                                                        |
| `learn(source, 'spam' \| 'ham')`     | Lär klassificeraren ett meddelande                                                     |
| `unlearn(source, 'spam' \| 'ham')`   | Ångrar `learn`                                                                         |
| `saveModel(path, options)`           | Skriver klassificeraren till en fil (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Den `Classifier` som används, eller `null`                                             |
| `getClassification(features)`        | Klassificerarens utslag för egenskaper från `getFeatures`                              |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` för ett tolkat meddelande                 |
| `getTokens(text, locale)`            | Orden i en text                                                                        |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                             |
| `parse(source)`                      | `{raw, mail}`, med `mail` från mailparser                                              |

`scanner.metrics` innehåller `totalScans`, `averageTime` och `lastScanTime`.


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

Fynd i `phishing`, `attachments`, `executables`, `macros`, `viruses` och `arbitrary` är objekt med en `type` och ett `message`. `String(finding)` är meddelandet.


## Exporter

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

### Klassificerare

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Alternativ                             | Standard       | Betydelse                                                                  |
| -------------------------------------- | -------------- | -------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsons s och x: hur starkt sällsynta egenskaper dras mot 0,5            |
| `minDistance`                          | `0.1`          | Egenskaper som ligger närmare 0,5 än detta ignoreras                       |
| `maxClues`                             | `150`          | Antal starkaste egenskaper som kombineras per meddelande                   |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Gränserna för intervallet `unsure`                                         |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Antal meddelanden av varje klass som krävs på ett språk för full konfidens |
| `languagePrior`                        | `true`         | Väg ord mot räkningen för deras eget språk                                 |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` och `entries()` finns också.

### Träning

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` tar emot poster av formen `{label, features}`, eller `readExamples(sources)`, som läser samma källor som `train`, och returnerar antal, precision, täckning (recall), F1, träffsäkerhet samt andelar falska positiva, falska negativa och osäkra.

### Servrar

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

`spamscanner/arf` läser och skriver rapporter om missbruk (RFC 5965), formatet som e-postleverantörer använder för att rapportera spamklagomål:

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

`ArfParser.tryParse()` returnerar `null` i stället för att kasta ett fel för meddelanden som inte är rapporter, och `isArfMessage(mail)` kontrollerar ett tolkat meddelande.
