<!-- source: b3cc9f949acd -->

# Справочник API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Создайте один сканер и используйте его повторно: он загружает модель один раз и кеширует ответы DNS и языковой модели.


## Параметры

Любой параметр можно передать в конструктор. Большинство можно также передать в `scan()` для одного письма; они накладываются поверх параметров конструктора.

| Параметр                | По умолчанию                     | Значение                                                                                                               |
| ----------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Оценка, при которой письмо считается спамом                                                                            |
| `rejectThreshold`       | `15`                             | Оценка, при которой `action` равно `reject`                                                                            |
| `scores`                | `{}`                             | Баллы для тестов: ключи настроек или имена тестов ([тесты и баллы](scoring.md))                                        |
| `classifier`            | встроенная модель                | `Classifier`, объект модели, путь к файлу модели или `false`                                                           |
| `classifierOptions`     | `{}`                             | Параметры встроенной модели (см. [Classifier](#classifier))                                                            |
| `allowedLanguages`      | `[]`                             | Коды ISO 639-1; остальные языки получают `LANGUAGE_NOT_ALLOWED`                                                        |
| `phishing.cloudflare`   | `true`                           | Спрашивать фильтрующие резолверы Cloudflare о хостах из ссылок                                                         |
| `phishing.adult`        | `true`                           | Также спрашивать семейный резолвер, который блокирует сайты для взрослых                                               |
| `phishing.maxHosts`     | `25`                             | Сколько хостов из ссылок проверяется в одном письме                                                                    |
| `phishing.homograph`    | `{}`                             | `brands` (замена встроенного списка), `extraBrands`, `allowlist` (домены, которые никогда не помечаются), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | Зоны чёрных списков в DNS для IP клиента и для доменов из ссылок                                                       |
| `dns`                   | `{servers: null, timeout: 3000}` | Серверы имён для DNS-проверок (по умолчанию системные)                                                                 |
| `attachments`           | `true`                           | Проверять вложения                                                                                                     |
| `macros`                | `true`                           | Помечать макросы, активные PDF и объекты RTF                                                                           |
| `arbitrary`             | `true`                           | Применять [правила](scoring.md#rules)                                                                                  |
| `authentication`        | `false`                          | `true` или `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                                |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                      |
| `allowlist`, `denylist` |                                  | IP-адреса, домены или адреса; краткая форма для `reputation`                                                           |
| `clamav`                | `false`                          | `true` (сокет по умолчанию), `{socket}` или `{host, port}`                                                             |
| `llm`                   | `null`                           | [Настройки языковой модели](llm.md#any-server-port-and-authentication) с `mode`, `minScore`, `maxScore`                |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: модель, чей `classify([text])` отвечает как `@tensorflow-models/toxicity`                  |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: модель, чей `classify(imageBuffer)` отвечает как `nsfwjs`                                  |
| `maxLength`             | `100000`                         | Сколько символов текста письма читается                                                                                |
| `timeout`               | `10000`                          | Миллисекунды, отведённые на каждую сетевую проверку                                                                    |
| `session`               | `{}`                             | Сведения об SMTP-сессии по умолчанию                                                                                   |

`scan()` также принимает `session`:

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


## Методы

| Метод                                | Возвращает                                                                         |
| ------------------------------------ | ---------------------------------------------------------------------------------- |
| `scan(source, options)`              | Результат. `source` — Buffer, строка, Uint8Array или поток для чтения              |
| `scanFile(path, options)`            | Результат для файла с письмом                                                      |
| `learn(source, 'spam' \| 'ham')`     | Обучает классификатор на одном письме                                              |
| `unlearn(source, 'spam' \| 'ham')`   | Отменяет `learn`                                                                   |
| `saveModel(path, options)`           | Записывает классификатор в файл (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Используемый `Classifier` или `null`                                               |
| `getClassification(features)`        | Вердикт классификатора для признаков из `getFeatures`                              |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` для разобранного письма               |
| `getTokens(text, locale)`            | Слова текста                                                                       |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                         |
| `parse(source)`                      | `{raw, mail}`, где `mail` получен от mailparser                                    |

`scanner.metrics` содержит `totalScans`, `averageTime` и `lastScanTime`.


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

Находки в `phishing`, `attachments`, `executables`, `macros`, `viruses` и `arbitrary` — объекты с полями `type` и `message`. `String(finding)` возвращает сообщение.


## Экспорт

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

| Параметр                               | По умолчанию   | Значение                                                                        |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Параметры s и x Робинсона: насколько сильно редкие признаки притягиваются к 0,5 |
| `minDistance`                          | `0.1`          | Признаки, которые ближе к 0,5, чем это значение, игнорируются                   |
| `maxClues`                             | `150`          | Сколько самых сильных признаков объединяется в одном письме                     |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Границы диапазона `unsure`                                                      |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Сколько писем каждого класса нужно на языке для полной уверенности              |
| `languagePrior`                        | `true`         | Взвешивать слова относительно счётчиков их собственного языка                   |

Также доступны `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` и `entries()`.

### Обучение

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` принимает элементы `{label, features}` или результат `readExamples(sources)`, который читает те же источники, что и `train`, и возвращает счётчики, точность, полноту, F1, долю верных ответов, а также доли ложноположительных, ложноотрицательных и неуверенных ответов.

### Серверы

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### Отчёты ARF

`spamscanner/arf` читает и создаёт отчёты о злоупотреблениях (RFC 5965) — формат, в котором почтовые провайдеры сообщают о жалобах на спам:

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

`ArfParser.tryParse()` возвращает `null` вместо исключения для писем, которые не являются отчётами, а `isArfMessage(mail)` проверяет разобранное письмо.
