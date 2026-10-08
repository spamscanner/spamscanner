<!-- source: b3cc9f949acd -->

# Reference API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Vytvořte jeden scanner a používejte ho opakovaně: model načte jednou a ukládá do mezipaměti odpovědi DNS i jazykového modelu.


## Volby

Každou volbu lze předat konstruktoru. Většinu lze předat také `scan()` pro jednu zprávu, kde se sloučí s volbami konstruktoru a mají přednost.

| Volba                   | Výchozí                          | Význam                                                                                                          |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Skóre, od kterého je zpráva spam                                                                                |
| `rejectThreshold`       | `15`                             | Skóre, od kterého je `action` rovno `reject`                                                                    |
| `scores`                | `{}`                             | Body za test: klíče nastavení nebo názvy testů ([testy a skóre](scoring.md))                                    |
| `classifier`            | přibalený model                  | `Classifier`, objekt modelu, cesta k souboru modelu nebo `false`                                                |
| `classifierOptions`     | `{}`                             | Volby přibaleného modelu (viz [Klasifikátor](#classifier))                                                      |
| `allowedLanguages`      | `[]`                             | Kódy ISO 639-1; ostatní jazyky dostanou `LANGUAGE_NOT_ALLOWED`                                                  |
| `phishing.cloudflare`   | `true`                           | Ptát se filtrovacích resolverů Cloudflare na hostitele z odkazů                                                 |
| `phishing.adult`        | `true`                           | Ptát se také rodinného resolveru, který blokuje weby pro dospělé                                                |
| `phishing.maxHosts`     | `25`                             | Počet hostitelů z odkazů vyhledaných na jednu zprávu                                                            |
| `phishing.homograph`    | `{}`                             | `brands` (nahradí vestavěný seznam), `extraBrands`, `allowlist` (domény, které se nikdy neoznačí), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zóny DNS blocklistů pro IP adresu klienta a pro domény v odkazech                                               |
| `dns`                   | `{servers: null, timeout: 3000}` | Jmenné servery pro kontroly DNS (výchozí: systémové)                                                            |
| `attachments`           | `true`                           | Prohlížet přílohy                                                                                               |
| `macros`                | `true`                           | Označovat makra, aktivní PDF a objekty RTF                                                                      |
| `arbitrary`             | `true`                           | Spouštět [pravidla](scoring.md#rules)                                                                           |
| `authentication`        | `false`                          | `true` nebo `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                        |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                               |
| `allowlist`, `denylist` |                                  | IP adresy, domény nebo adresy; zkratka pro `reputation`                                                         |
| `clamav`                | `false`                          | `true` (výchozí socket), `{socket}` nebo `{host, port}`                                                         |
| `llm`                   | `null`                           | [Nastavení jazykového modelu](llm.md#any-server-port-and-authentication) s `mode`, `minScore`, `maxScore`       |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: model, jehož `classify([text])` odpovídá jako `@tensorflow-models/toxicity`         |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: model, jehož `classify(imageBuffer)` odpovídá jako `nsfwjs`                         |
| `maxLength`             | `100000`                         | Počet přečtených znaků textu těla                                                                               |
| `timeout`               | `10000`                          | Milisekundy povolené pro každou síťovou kontrolu                                                                |
| `session`               | `{}`                             | Výchozí údaje o relaci SMTP                                                                                     |

`scan()` přijímá také `session`:

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


## Metody

| Metoda                               | Vrací                                                                             |
| ------------------------------------ | --------------------------------------------------------------------------------- |
| `scan(source, options)`              | Výsledek. `source` je Buffer, řetězec, Uint8Array nebo čitelný stream             |
| `scanFile(path, options)`            | Výsledek pro soubor se zprávou                                                    |
| `learn(source, 'spam' \| 'ham')`     | Naučí klasifikátor jednu zprávu                                                   |
| `unlearn(source, 'spam' \| 'ham')`   | Vrátí zpět `learn`                                                                |
| `saveModel(path, options)`           | Zapíše klasifikátor do souboru (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Používaný `Classifier` nebo `null`                                                |
| `getClassification(features)`        | Verdikt klasifikátoru pro příznaky z `getFeatures`                                |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` pro rozebranou zprávu                |
| `getTokens(text, locale)`            | Slova textu                                                                       |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                        |
| `parse(source)`                      | `{raw, mail}`, kde `mail` pochází z mailparseru                                   |

`scanner.metrics` obsahuje `totalScans`, `averageTime` a `lastScanTime`.


## Výsledek

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

Nálezy v `phishing`, `attachments`, `executables`, `macros`, `viruses` a `arbitrary` jsou objekty s `type` a `message`. `String(finding)` je zpráva.


## Exporty

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

### Klasifikátor

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Volba                                  | Výchozí        | Význam                                                                 |
| -------------------------------------- | -------------- | ---------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsonovy parametry s a x: jak silně se vzácné příznaky táhnou k 0,5 |
| `minDistance`                          | `0.1`          | Příznaky bližší k 0,5 než tato hodnota se ignorují                     |
| `maxClues`                             | `150`          | Počet nejsilnějších příznaků kombinovaných na jednu zprávu             |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Hranice rozsahu `unsure`                                               |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Počet zpráv každé třídy v jazyce potřebný pro plnou důvěru             |
| `languagePrior`                        | `true`         | Vážit slova podle počtů v jejich vlastním jazyce                       |

K dispozici jsou také `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` a `entries()`.

### Trénování

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` přijímá položky `{label, features}` nebo `readExamples(sources)`, které čte stejné zdroje jako `train`, a vrací počty, přesnost, úplnost, F1, správnost a míru falešně pozitivních, falešně negativních a nejistých výsledků.

### Servery

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### Hlášení ARF

`spamscanner/arf` čte a zapisuje hlášení o zneužití (RFC 5965), formát, kterým poskytovatelé poštovních schránek hlásí stížnosti na spam:

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

`ArfParser.tryParse()` u zpráv, které nejsou hlášeními, vrací `null` místo vyhození výjimky, a `isArfMessage(mail)` zkontroluje rozebranou zprávu.
