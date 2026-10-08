<!-- source: b3cc9f949acd -->

# API-referentie

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Maak één scanner aan en hergebruik die: hij laadt het model één keer en cachet DNS-antwoorden en antwoorden van het taalmodel.


## Opties

Elke optie kan aan de constructor worden meegegeven. De meeste kunnen ook voor één bericht aan `scan()` worden meegegeven, en worden dan over die van de constructor heen samengevoegd.

| Optie                   | Standaard                        | Betekenis                                                                                                                |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `threshold`             | `5`                              | Score waarbij een bericht spam is                                                                                        |
| `rejectThreshold`       | `15`                             | Score waarbij `action` gelijk is aan `reject`                                                                            |
| `scores`                | `{}`                             | Punten per test: instellingssleutels of testnamen ([tests en scores](scoring.md))                                        |
| `classifier`            | meegeleverd model                | Een `Classifier`, een modelobject, het pad van een modelbestand, of `false`                                              |
| `classifierOptions`     | `{}`                             | Opties voor het meegeleverde model (zie [Classifier](#classifier))                                                       |
| `allowedLanguages`      | `[]`                             | ISO 639-1-codes; andere talen krijgen `LANGUAGE_NOT_ALLOWED`                                                             |
| `phishing.cloudflare`   | `true`                           | Vraag de filterende resolvers van Cloudflare naar linkhosts                                                              |
| `phishing.adult`        | `true`                           | Vraag het ook aan de gezinsresolver, die volwassenensites blokkeert                                                      |
| `phishing.maxHosts`     | `25`                             | Aantal linkhosts dat per bericht wordt opgezocht                                                                         |
| `phishing.homograph`    | `{}`                             | `brands` (vervangt de ingebouwde lijst), `extraBrands`, `allowlist` (domeinen die nooit worden gemarkeerd), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zones van DNS-blocklists voor het IP-adres van de client en voor linkdomeinen                                            |
| `dns`                   | `{servers: null, timeout: 3000}` | Nameservers voor DNS-controles (standaard: die van het systeem)                                                          |
| `attachments`           | `true`                           | Bijlagen inspecteren                                                                                                     |
| `macros`                | `true`                           | Macro's, actieve pdf's en RTF-objecten markeren                                                                          |
| `arbitrary`             | `true`                           | De [regels](scoring.md#rules) uitvoeren                                                                                  |
| `authentication`        | `false`                          | `true`, of `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                                  |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                        |
| `allowlist`, `denylist` |                                  | IP-adressen, domeinen of adressen; verkorte vorm van `reputation`                                                        |
| `clamav`                | `false`                          | `true` (standaardsocket), `{socket}` of `{host, port}`                                                                   |
| `llm`                   | `null`                           | [Instellingen voor het taalmodel](llm.md#any-server-port-and-authentication), met `mode`, `minScore`, `maxScore`         |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: een model waarvan `classify([text])` antwoordt zoals `@tensorflow-models/toxicity`           |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: een model waarvan `classify(imageBuffer)` antwoordt zoals `nsfwjs`                           |
| `maxLength`             | `100000`                         | Aantal tekens bodytekst dat wordt gelezen                                                                                |
| `timeout`               | `10000`                          | Toegestane milliseconden per netwerkcontrole                                                                             |
| `session`               | `{}`                             | Standaardgegevens van de SMTP-sessie                                                                                     |

`scan()` accepteert ook `session`:

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


## Methoden

| Methode                              | Geeft terug                                                                                |
| ------------------------------------ | ------------------------------------------------------------------------------------------ |
| `scan(source, options)`              | Het resultaat. `source` is een Buffer, string, Uint8Array of readable stream               |
| `scanFile(path, options)`            | Het resultaat voor een berichtbestand                                                      |
| `learn(source, 'spam' \| 'ham')`     | Leert de classifier één bericht                                                            |
| `unlearn(source, 'spam' \| 'ham')`   | Maakt `learn` ongedaan                                                                     |
| `saveModel(path, options)`           | Schrijft de classifier naar een bestand (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | De `Classifier` die in gebruik is, of `null`                                               |
| `getClassification(features)`        | Het oordeel van de classifier voor kenmerken uit `getFeatures`                             |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` voor een geparsed bericht                     |
| `getTokens(text, locale)`            | De woorden van een tekst                                                                   |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                                 |
| `parse(source)`                      | `{raw, mail}`, met `mail` uit mailparser                                                   |

`scanner.metrics` bevat `totalScans`, `averageTime` en `lastScanTime`.


## Het resultaat

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

Bevindingen in `phishing`, `attachments`, `executables`, `macros`, `viruses` en `arbitrary` zijn objecten met een `type` en een `message`. `String(finding)` is het bericht.


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

| Optie                                  | Standaard      | Betekenis                                                                          |
| -------------------------------------- | -------------- | ---------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | De s en x van Robinson: hoe sterk zeldzame kenmerken naar 0,5 worden getrokken     |
| `minDistance`                          | `0.1`          | Kenmerken die dichter bij 0,5 liggen dan dit, worden genegeerd                     |
| `maxClues`                             | `150`          | Aantal sterkste kenmerken dat per bericht wordt gecombineerd                       |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Grenzen van het bereik `unsure`                                                    |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Aantal berichten van elke klasse dat in een taal nodig is voor volledige zekerheid |
| `languagePrior`                        | `true`         | Woorden wegen tegen de aantallen van hun eigen taal                                |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` en `entries()` zijn ook beschikbaar.

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

`evaluate(classifier, examples)` accepteert items met `{label, features}`, of `readExamples(sources)`, dat dezelfde bronnen leest als `train`, en geeft aantallen, precisie, recall, F1, accuracy en de percentages fout-positieven, fout-negatieven en onzekere berichten terug.

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

### ARF-rapporten

`spamscanner/arf` leest en schrijft abuse feedback reports (RFC 5965), het formaat dat mailboxproviders gebruiken om spamklachten te melden:

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

`ArfParser.tryParse()` geeft `null` terug in plaats van een fout te gooien bij berichten die geen rapport zijn, en `isArfMessage(mail)` controleert een geparsed bericht.
