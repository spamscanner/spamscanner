<!-- source: b3cc9f949acd -->

# API-referanse

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Opprett én skanner og gjenbruk den: den laster inn modellen én gang og mellomlagrer svar fra DNS og språkmodeller.


## Alternativer

Alle alternativer kan sendes til konstruktøren. De fleste kan også sendes til `scan()` for én melding, og flettes da inn over konstruktørens.

| Alternativ              | Standard                         | Betydning                                                                                                        |
| ----------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Poengsum der en melding er spam                                                                                  |
| `rejectThreshold`       | `15`                             | Poengsum der `action` er `reject`                                                                                |
| `scores`                | `{}`                             | Poeng per test: innstillingsnøkler eller testnavn ([tester og poeng](scoring.md))                                |
| `classifier`            | medfølgende modell               | En `Classifier`, et modellobjekt, en sti til en modellfil eller `false`                                          |
| `classifierOptions`     | `{}`                             | Alternativer for den medfølgende modellen (se [Klassifiserer](#classifier))                                      |
| `allowedLanguages`      | `[]`                             | ISO 639-1-koder; andre språk får `LANGUAGE_NOT_ALLOWED`                                                          |
| `phishing.cloudflare`   | `true`                           | Spør Cloudflares filtrerende resolvere om vertene i lenker                                                       |
| `phishing.adult`        | `true`                           | Spør også familieresolveren, som blokkerer voksennettsteder                                                      |
| `phishing.maxHosts`     | `25`                             | Lenkeverter som slås opp per melding                                                                             |
| `phishing.homograph`    | `{}`                             | `brands` (erstatter den innebygde listen), `extraBrands`, `allowlist` (domener som aldri flagges), `strictMode`  |
| `dnsbl`                 | `{ip: [], domain: []}`           | Soner for DNS-blokkeringslister for klientens IP og for domener i lenker                                         |
| `dns`                   | `{servers: null, timeout: 3000}` | Navneservere for DNS-sjekker (standard: systemets)                                                               |
| `attachments`           | `true`                           | Undersøk vedlegg                                                                                                 |
| `macros`                | `true`                           | Flagg makroer, aktive PDF-er og RTF-objekter                                                                     |
| `arbitrary`             | `true`                           | Kjør [reglene](scoring.md#rules)                                                                                 |
| `authentication`        | `false`                          | `true`, eller `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                       |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                |
| `allowlist`, `denylist` |                                  | IP-adresser, domener eller adresser; kortform for `reputation`                                                   |
| `clamav`                | `false`                          | `true` (standard-socket), `{socket}` eller `{host, port}`                                                        |
| `llm`                   | `null`                           | [Innstillinger for språkmodellen](llm.md#any-server-port-and-authentication), med `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: en modell der `classify([text])` svarer som `@tensorflow-models/toxicity`            |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: en modell der `classify(imageBuffer)` svarer som `nsfwjs`                            |
| `maxLength`             | `100000`                         | Antall tegn av brødteksten som leses                                                                             |
| `timeout`               | `10000`                          | Millisekunder tillatt for hver nettverkssjekk                                                                    |
| `session`               | `{}`                             | Standardopplysninger om SMTP-økten                                                                               |

`scan()` tar også imot `session`:

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
| `scan(source, options)`              | Resultatet. `source` er en Buffer, en streng, en Uint8Array eller en lesbar strøm     |
| `scanFile(path, options)`            | Resultatet for en meldingsfil                                                         |
| `learn(source, 'spam' \| 'ham')`     | Lærer klassifisereren opp på én melding                                               |
| `unlearn(source, 'spam' \| 'ham')`   | Angrer `learn`                                                                        |
| `saveModel(path, options)`           | Skriver klassifisereren til en fil (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | `Classifier` som er i bruk, eller `null`                                              |
| `getClassification(features)`        | Klassifisererens vurdering av egenskaper fra `getFeatures`                            |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` for en tolket melding                    |
| `getTokens(text, locale)`            | Ordene i en tekst                                                                     |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                            |
| `parse(source)`                      | `{raw, mail}`, med `mail` fra mailparser                                              |

`scanner.metrics` inneholder `totalScans`, `averageTime` og `lastScanTime`.


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

Funn i `phishing`, `attachments`, `executables`, `macros`, `viruses` og `arbitrary` er objekter med en `type` og en `message`. `String(finding)` er meldingen.


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

### Klassifiserer

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Alternativ                             | Standard       | Betydning                                                        |
| -------------------------------------- | -------------- | ---------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsons s og x: hvor sterkt sjeldne egenskaper trekkes mot 0,5 |
| `minDistance`                          | `0.1`          | Egenskaper nærmere 0,5 enn dette ignoreres                       |
| `maxClues`                             | `150`          | De sterkeste egenskapene som kombineres per melding              |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Grensene for `unsure`-området                                    |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Meldinger av hver klasse som trengs på et språk for full tillit  |
| `languagePrior`                        | `true`         | Vei ord mot tellingene for deres eget språk                      |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` og `entries()` er også tilgjengelige.

### Trening

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` tar imot `{label, features}`-elementer, eller `readExamples(sources)`, som leser de samme kildene som `train`, og returnerer antall, presisjon, gjenkalling, F1, nøyaktighet og andelene falske positiver, falske negativer og usikre.

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

`spamscanner/arf` leser og skriver rapporter om misbruk (RFC 5965), formatet e-postleverandører bruker til å rapportere spamklager:

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

`ArfParser.tryParse()` returnerer `null` i stedet for å kaste en feil for meldinger som ikke er rapporter, og `isArfMessage(mail)` sjekker en tolket melding.
