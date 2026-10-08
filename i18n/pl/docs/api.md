<!-- source: b3cc9f949acd -->

# Dokumentacja API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Utwórz jeden skaner i używaj go wielokrotnie: wczytuje model raz i zapamiętuje odpowiedzi DNS oraz modelu językowego.


## Opcje

Każdą opcję można przekazać do konstruktora. Większość można też przekazać do `scan()` dla jednej wiadomości; nakładają się wtedy na opcje konstruktora.

| Opcja                   | Domyślnie                        | Znaczenie                                                                                                   |
| ----------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Wynik, od którego wiadomość jest spamem                                                                     |
| `rejectThreshold`       | `15`                             | Wynik, od którego `action` ma wartość `reject`                                                              |
| `scores`                | `{}`                             | Punkty za test: klucze ustawień lub nazwy testów ([testy i punkty](scoring.md))                             |
| `classifier`            | dołączony model                  | `Classifier`, obiekt modelu, ścieżka do pliku modelu lub `false`                                            |
| `classifierOptions`     | `{}`                             | Opcje dołączonego modelu (zobacz [Classifier](#classifier))                                                 |
| `allowedLanguages`      | `[]`                             | Kody ISO 639-1; inne języki dostają `LANGUAGE_NOT_ALLOWED`                                                  |
| `phishing.cloudflare`   | `true`                           | Pytaj filtrujące resolvery Cloudflare o hosty z linków                                                      |
| `phishing.adult`        | `true`                           | Pytaj też resolver rodzinny, który blokuje witryny dla dorosłych                                            |
| `phishing.maxHosts`     | `25`                             | Liczba hostów z linków sprawdzanych na wiadomość                                                            |
| `phishing.homograph`    | `{}`                             | `brands` (zastępuje wbudowaną listę), `extraBrands`, `allowlist` (domeny nigdy nieoznaczane), `strictMode`  |
| `dnsbl`                 | `{ip: [], domain: []}`           | Strefy czarnych list DNS dla IP klienta i domen z linków                                                    |
| `dns`                   | `{servers: null, timeout: 3000}` | Serwery nazw dla kontroli DNS (domyślnie systemowe)                                                         |
| `attachments`           | `true`                           | Sprawdzaj załączniki                                                                                        |
| `macros`                | `true`                           | Oznaczaj makra, aktywne pliki PDF i obiekty RTF                                                             |
| `arbitrary`             | `true`                           | Uruchamiaj [reguły](scoring.md#rules)                                                                       |
| `authentication`        | `false`                          | `true` lub `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                     |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                           |
| `allowlist`, `denylist` |                                  | Adresy IP, domeny lub adresy e-mail; skrót dla `reputation`                                                 |
| `clamav`                | `false`                          | `true` (domyślne gniazdo), `{socket}` lub `{host, port}`                                                    |
| `llm`                   | `null`                           | [Ustawienia modelu językowego](llm.md#any-server-port-and-authentication), z `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: model, którego `classify([text])` odpowiada jak `@tensorflow-models/toxicity`   |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: model, którego `classify(imageBuffer)` odpowiada jak `nsfwjs`                   |
| `maxLength`             | `100000`                         | Liczba czytanych znaków treści                                                                              |
| `timeout`               | `10000`                          | Milisekundy dozwolone na każdą kontrolę sieciową                                                            |
| `session`               | `{}`                             | Domyślne dane sesji SMTP                                                                                    |

`scan()` przyjmuje też `session`:

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

| Metoda                               | Zwraca                                                                            |
| ------------------------------------ | --------------------------------------------------------------------------------- |
| `scan(source, options)`              | Wynik. `source` to Buffer, string, Uint8Array lub strumień do odczytu             |
| `scanFile(path, options)`            | Wynik dla pliku z wiadomością                                                     |
| `learn(source, 'spam' \| 'ham')`     | Uczy klasyfikator jednej wiadomości                                               |
| `unlearn(source, 'spam' \| 'ham')`   | Cofa `learn`                                                                      |
| `saveModel(path, options)`           | Zapisuje klasyfikator do pliku (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Używany `Classifier` lub `null`                                                   |
| `getClassification(features)`        | Werdykt klasyfikatora dla cech z `getFeatures`                                    |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` dla sparsowanej wiadomości           |
| `getTokens(text, locale)`            | Słowa tekstu                                                                      |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                        |
| `parse(source)`                      | `{raw, mail}`, gdzie `mail` pochodzi z mailparser                                 |

`scanner.metrics` zawiera `totalScans`, `averageTime` i `lastScanTime`.


## Wynik

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

Ustalenia w `phishing`, `attachments`, `executables`, `macros`, `viruses` i `arbitrary` to obiekty z polami `type` i `message`. `String(finding)` zwraca komunikat.


## Eksporty

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

| Opcja                                  | Domyślnie      | Znaczenie                                                                  |
| -------------------------------------- | -------------- | -------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Parametry s i x Robinsona: jak mocno rzadkie cechy są przyciągane do 0,5   |
| `minDistance`                          | `0.1`          | Cechy bliższe 0,5 niż ta wartość są pomijane                               |
| `maxClues`                             | `150`          | Liczba najsilniejszych cech łączonych na wiadomość                         |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Granice przedziału `unsure`                                                |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Liczba wiadomości każdej klasy w danym języku potrzebna do pełnej pewności |
| `languagePrior`                        | `true`         | Porównuj słowa z licznikami ich własnego języka                            |

Dostępne są też `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` i `entries()`.

### Trenowanie

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` przyjmuje elementy `{label, features}` lub `readExamples(sources)`, które czyta te same źródła co `train`, i zwraca liczniki, precyzję, czułość, F1, dokładność oraz odsetki fałszywie pozytywnych, fałszywie negatywnych i niepewnych wyników.

### Serwery

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### Raporty ARF

`spamscanner/arf` czyta i zapisuje raporty o nadużyciach (RFC 5965), czyli format, w którym dostawcy skrzynek pocztowych zgłaszają skargi na spam:

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

`ArfParser.tryParse()` zwraca `null` zamiast rzucać wyjątek dla wiadomości, które nie są raportami, a `isArfMessage(mail)` sprawdza sparsowaną wiadomość.
