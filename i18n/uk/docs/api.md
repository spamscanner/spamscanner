<!-- source: b3cc9f949acd -->

# Довідник API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Створіть один сканер і використовуйте його повторно: він завантажує модель один раз і кешує відповіді DNS і мовної моделі.


## Параметри

Кожен параметр можна передати конструктору. Більшість також можна передати до `scan()` для одного листа; вони накладаються на параметри конструктора.

| Параметр                | За замовчуванням                 | Значення                                                                                                             |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Бал, з якого лист вважається спамом                                                                                  |
| `rejectThreshold`       | `15`                             | Бал, з якого `action` дорівнює `reject`                                                                              |
| `scores`                | `{}`                             | Бали для тестів: ключі налаштувань або назви тестів ([тести та бали](scoring.md))                                    |
| `classifier`            | вбудована модель                 | `Classifier`, об’єкт моделі, шлях до файлу моделі або `false`                                                        |
| `classifierOptions`     | `{}`                             | Параметри вбудованої моделі (див. [Класифікатор](#classifier))                                                       |
| `allowedLanguages`      | `[]`                             | Коди ISO 639-1; інші мови отримують `LANGUAGE_NOT_ALLOWED`                                                           |
| `phishing.cloudflare`   | `true`                           | Запитувати фільтрувальні резолвери Cloudflare про хости посилань                                                     |
| `phishing.adult`        | `true`                           | Також запитувати сімейний резолвер, який блокує сайти для дорослих                                                   |
| `phishing.maxHosts`     | `25`                             | Скільки хостів посилань перевіряти в одному листі                                                                    |
| `phishing.homograph`    | `{}`                             | `brands` (замінює вбудований перелік), `extraBrands`, `allowlist` (домени, які ніколи не позначаються), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | Зони чорних списків DNS для IP-адреси клієнта та доменів посилань                                                    |
| `dns`                   | `{servers: null, timeout: 3000}` | Сервери імен для перевірок DNS (за замовчуванням системні)                                                           |
| `attachments`           | `true`                           | Перевіряти вкладення                                                                                                 |
| `macros`                | `true`                           | Позначати макроси, активні PDF і об’єкти RTF                                                                         |
| `arbitrary`             | `true`                           | Виконувати [правила](scoring.md#rules)                                                                               |
| `authentication`        | `false`                          | `true` або `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                              |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                    |
| `allowlist`, `denylist` |                                  | IP-адреси, домени або адреси; скорочення для `reputation`                                                            |
| `clamav`                | `false`                          | `true` (стандартний сокет), `{socket}` або `{host, port}`                                                            |
| `llm`                   | `null`                           | [Налаштування мовної моделі](llm.md#any-server-port-and-authentication) з `mode`, `minScore`, `maxScore`             |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: модель, чий `classify([text])` відповідає як `@tensorflow-models/toxicity`               |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: модель, чий `classify(imageBuffer)` відповідає як `nsfwjs`                               |
| `maxLength`             | `100000`                         | Скільки символів тексту тіла читати                                                                                  |
| `timeout`               | `10000`                          | Скільки мілісекунд дозволено на кожну мережеву перевірку                                                             |
| `session`               | `{}`                             | Типові відомості про сеанс SMTP                                                                                      |

`scan()` також приймає `session`:

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


## Методи

| Метод                                | Повертає                                                                       |
| ------------------------------------ | ------------------------------------------------------------------------------ |
| `scan(source, options)`              | Результат. `source` — це Buffer, рядок, Uint8Array або потік для читання       |
| `scanFile(path, options)`            | Результат для файлу листа                                                      |
| `learn(source, 'spam' \| 'ham')`     | Навчає класифікатор на одному листі                                            |
| `unlearn(source, 'spam' \| 'ham')`   | Скасовує `learn`                                                               |
| `saveModel(path, options)`           | Записує класифікатор у файл (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | `Classifier`, що використовується, або `null`                                  |
| `getClassification(features)`        | Вердикт класифікатора для ознак із `getFeatures`                               |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` для розібраного листа             |
| `getTokens(text, locale)`            | Слова тексту                                                                   |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                     |
| `parse(source)`                      | `{raw, mail}`, де `mail` отримано з mailparser                                 |

`scanner.metrics` містить `totalScans`, `averageTime` і `lastScanTime`.


## Результат

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

Знахідки в `phishing`, `attachments`, `executables`, `macros`, `viruses` і `arbitrary` — це об’єкти з `type` і `message`. `String(finding)` повертає повідомлення.


## Експорти

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

### Класифікатор

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Параметр                               | За замовчуванням | Значення                                                            |
| -------------------------------------- | ---------------- | ------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`    | s і x Робінсона: наскільки сильно рідкісні ознаки зсуваються до 0,5 |
| `minDistance`                          | `0.1`            | Ознаки, ближчі до 0,5, ніж це значення, ігноруються                 |
| `maxClues`                             | `150`            | Скільки найсильніших ознак поєднується для одного листа             |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`    | Межі діапазону `unsure`                                             |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02`   | Скільки листів кожного класу потрібно в мові для повної впевненості |
| `languagePrior`                        | `true`           | Зважувати слова відносно лічильників їхньої власної мови            |

Також доступні `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` і `entries()`.

### Навчання

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` приймає елементи `{label, features}` або `readExamples(sources)`, яка читає ті самі джерела, що й `train`, і повертає лічильники, точність, повноту, F1, правильність, а також частки хибнопозитивних, хибнонегативних і невизначених результатів.

### Сервери

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### Звіти ARF

`spamscanner/arf` читає й записує звіти про зловживання (RFC 5965) — формат, у якому поштові провайдери повідомляють про скарги на спам:

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

`ArfParser.tryParse()` повертає `null` замість винятку для листів, які не є звітами, а `isArfMessage(mail)` перевіряє розібраний лист.
