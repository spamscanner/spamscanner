<!-- source: b19ea85ceb6d -->

# Справочник API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Создайте один сканер и используйте его повторно: он загружает модель один раз и кеширует ответы DNS и языковой модели.

Объявления типов входят в пакет. Для них нужен TypeScript 4.7 или новее с `import` и 5.3 или новее с `require`.


## Параметры

Любой параметр можно передать в конструктор. Большинство можно также передать в `scan()` для одного письма; они накладываются поверх параметров конструктора. Параметры, переданные как `undefined`, сохраняют значения по умолчанию. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` и `strictIDNDetection` читает только конструктор; файл или объект модели из `classifier` загружается там же, поэтому отсутствующая или повреждённая модель сразу вызывает ошибку.

| Параметр                | По умолчанию                     | Значение                                                                                                                                                                                                             |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Оценка, при которой письмо считается спамом                                                                                                                                                                          |
| `rejectThreshold`       | `15`                             | Оценка, при которой `action` равно `reject`                                                                                                                                                                          |
| `scores`                | `{}`                             | Баллы для тестов: ключи настроек или имена тестов ([тесты и баллы](scoring.md))                                                                                                                                      |
| `classifier`            | встроенная модель                | `Classifier`, объект модели, путь к файлу модели или `false`                                                                                                                                                         |
| `classifierOptions`     | `{}`                             | Параметры встроенной модели (см. [Classifier](#classifier))                                                                                                                                                          |
| `allowedLanguages`      | `[]`                             | Коды ISO 639-1 (`no` читается как `nb`, `fil` — как `tl`, а старые `iw`, `in`, `ji` — как `he`, `id`, `yi`); остальные языки получают `LANGUAGE_NOT_ALLOWED`                                                         |
| `phishing.cloudflare`   | `true`                           | Спрашивать фильтрующие резолверы Cloudflare о хостах из ссылок                                                                                                                                                       |
| `phishing.adult`        | `true`                           | Также спрашивать семейный резолвер, который блокирует сайты для взрослых                                                                                                                                             |
| `phishing.maxHosts`     | `25`                             | Сколько хостов из ссылок проверяется в одном письме                                                                                                                                                                  |
| `phishing.maxLength`    | `1000000`                        | Символы текста, читаемые в поисках ссылок (вдвое больше для HTML); более длинный текст устанавливает `results.linksTruncated`; `Infinity` или что угодно, кроме положительного числа, означает значение по умолчанию |
| `phishing.homograph`    | `{}`                             | `brands` (замена встроенного списка), `extraBrands`, `allowlist` (домены, которые никогда не помечаются), `strictMode`                                                                                               |
| `dnsbl`                 | `{ip: [], domain: []}`           | Зоны чёрных списков в DNS для IP клиента и для доменов из ссылок                                                                                                                                                     |
| `dns`                   | `{servers: null, timeout: 3000}` | Серверы имён для DNS-проверок (по умолчанию системные)                                                                                                                                                               |
| `attachments`           | `true`                           | Проверять вложения                                                                                                                                                                                                   |
| `macros`                | `true`                           | Помечать макросы, активные PDF и объекты RTF                                                                                                                                                                         |
| `arbitrary`             | `true`                           | Применять [правила](scoring.md#rules)                                                                                                                                                                                |
| `authentication`        | `false`                          | `true` или `{dnsServers, timeout, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([оценка](scoring.md#authentication))                                                                                     |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; ответы хранятся отдельно для каждой службы и набора заголовков, а `cacheSize` действует на весь сканер                          |
| `allowlist`, `denylist` |                                  | IP-адреса, домены или адреса; краткая форма для `reputation` → [Белый и чёрный списки](#allowlist-and-denylist)                                                                                                      |
| `clamav`                | `false`                          | `true` (сокет по умолчанию), `{socket}` или `{host, port}`, с `timeout`: миллисекунды на все вложения письма вместе (`60000`)                                                                                        |
| `llm`                   | `null`                           | [Настройки языковой модели](llm.md#any-server-port-and-authentication) с `mode`, `minScore`, `maxScore`                                                                                                              |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: модель, чей `classify([text])` отвечает как `@tensorflow-models/toxicity`                                                                                                                |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: модель, чей `classify(imageBuffer)` отвечает как `nsfwjs`                                                                                                                                |
| `maxLength`             | `100000`                         | Сколько символов текста письма читается                                                                                                                                                                              |
| `timeout`               | `10000`                          | Миллисекунды, отведённые на каждую сетевую проверку; аутентификация и модель изображений укладываются в это время целиком (у ClamAV свой `clamav.timeout`)                                                           |
| `session`               | `{}`                             | Сведения об SMTP-сессии по умолчанию                                                                                                                                                                                 |

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

Сервер, который уже проверил SPF, DKIM, DMARC и ARC (с помощью [mailauth](https://github.com/postalsys/mailauth)), может передать результаты как `authenticationResults`, и тогда они оцениваются, а не проверяются повторно:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Белый и чёрный списки

Чёрный список сравнивает IP-адрес и имя хоста клиента, адреса From, отправителя конверта и Reply-To, а также их домены, какими бы они ни были: имя под доменом из чёрного списка совпадает с ним, даже если оно не является допустимым именем хоста (например, `a_b!.evil.example` или имя с меткой длиннее 63 символов), по его последним 127 меткам и 253 символам. Белый список, а также белый список и доверенные источники службы репутации, сравнивают только то, что отправитель не может подделать: IP-адрес и проверенное имя хоста клиента (`remoteAddress`, `resolvedClientHostname`), адрес From, если DMARC проходит для его домена или с ним выровнена действительная подпись DKIM (и он является допустимым именем хоста; в мягком режиме, как в DMARC: у домена From и подписывающего домена или домена SPF один и тот же регистрируемый домен, который mailauth называет доменом DMARC; запись с поддоменом, например `news.example.com`, учитывается, только когда письмо подписал или прошёл SPF этот домен, домен под ним или родительский домен, а не другой поддомен, например `evil.example.com`, и не публичный суффикс; прохождение DMARC для регистрируемого домена без сведений mailauth о выравнивании учитывается только для записи с регистрируемым доменом; при строгом выравнивании, `adkim=s` или `aspf=s` в DMARC-записи домена в любом регистре и с любыми пробелами, учитывается только подпись или прохождение SPF самого домена From, а без них DMARC не проходит), и отправителя конверта, если SPF проходит для его домена. Подпись DKIM только начала тела письма (длина тела, `l=`, короче самого тела: после неё кто угодно может дописать текст) не учитывается ни для чего, как и прохождение DMARC, основанное на такой подписи, а если DMARC не проходит, не учитывается ни одна подпись. Результаты, переданные в `authenticationResults`, учитываются, только если в них указан домен, для которого они прошли, а домен, не являющийся именем хоста (например, `bank.example/x.attacker.example`, который парсеры URL читают как `bank.example`), не учитывается ни для какого, как и прохождение DMARC, основанное на таком домене. Международные домены совпадают в любой форме: `bücher.example` или `xn--bcher-kva.example`. Reply-To не учитывается никогда. Чтобы добавить домен в белый список, включите `authentication` или передайте `authenticationResults`.

Каждая запись — один IP-адрес, домен или адрес электронной почты, сравниваемый точно: запись домена охватывает также его поддомены и адреса в них, но диапазонов адресов (`192.0.2.0/24`), подстановочных знаков (`*.example.com`) и шаблонов (`@example.com`) нет. Адреса IPv6 совпадают в любой форме (`2001:0db8::0001` — это `2001:db8::1`, форма из RFC 5952), адрес IPv4, отображённый в IPv6 (`::ffff:192.0.2.1`), совпадает с адресом IPv4, а адрес IPv4, транслированный в IPv6 или под префиксом NAT64, записывается с этим адресом IPv4 в точечной форме (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), как в записях, так и в адресах клиентов.


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
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` письма           |
| `getTokens(text, locale)`            | Слова текста                                                                       |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                         |
| `parse(source)`                      | `{raw, mail}`, где `mail` получен от mailparser (см. ниже)                         |

`scan`, `parse`, `learn`, `unlearn` и `getTokensAndMailFromSource` читают письмо одинаково: письмо, превышающее лимиты MIME-парсера (более 1000 частей, заголовок части больше 1 МБ), читается настолько, насколько позволяет парсер. Текст, первая строка которого не является полем заголовка (`Name: value` или строка `From`, с которой начинается каждое письмо в файлах mbox), читается как тело письма без заголовка, поэтому `mail.text` — это этот текст. Остальные ошибки выбрасываются.

В `getFeatures` `text` — это текст, который показывает почтовый клиент и из которого читаются слова, а `hidden` — сколько символов текста скрывает HTML. mailparser здесь не делает текст из HTML: `mail.text` содержит только части с обычным текстом и пуст для письма, состоящего только из HTML; текст, который показывает его HTML, — это `getFeatures(mail).text`.

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

Находки в `phishing`, `attachments`, `executables`, `macros`, `viruses` и `arbitrary` — объекты с полями `type` и `message`. `String(finding)` возвращает сообщение. Вложения вложенного сообщения (`message/rfc822`, `.eml`) получают его имя: `fw.eml/invoice.exe`. Вирус, найденный ClamAV в таком вложении, сообщается только для него, а не ещё раз для вложенного сообщения, которое его содержит. `virusScanErrors` перечисляет вложения, которые ClamAV не смог проверить, в виде `{filename, error}`: такое сообщение может содержать вирус, поэтому лучше задержать его, чем доставить. Milter и контент-фильтр откладывают такое письмо, если `onError` (`--on-error`) не равен `accept`, а каждый сервер помечает такое письмо, которое передаёт дальше, заголовком `X-Spam-Virus-Scan: failed`. `virusScanSkipped` перечисляет вложения больше, чем принимает clamd (его `StreamMaxLength`), в виде `{filename, reason}`: clamd отклоняет их при каждой попытке, поэтому, так же как clamav-milter пропускает файл больше своего `MaxFileSize`, они не считаются сбоями. Другие его лимиты (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), которых достигает архивная бомба, считаются сбоями.

Каждый элемент `dnsbl` содержит `answers` списка (адреса из 127.0.0.0/8, значение которых документирует каждый список). Ответы, которые списки дают на запросы, которые они отклоняют или на которые не могут ответить, не являются занесением в список — ни для адреса клиента, ни для доменов ссылок (находки `uribl` в `phishing`): 127.255.255.x у Spamhaus (например, 127.255.255.254 на запрос через публичный резолвер и 127.255.255.255 при слишком большом числе запросов), 127.0.1.255 у Spamhaus DBL, 127.0.0.255 у любого списка и 127.0.0.1 у SURBL и URIBL, которые дают такой ответ блокируемым ими резолверам.


## Экспорт

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

| Параметр                               | По умолчанию   | Значение                                                                                                                                               |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Параметры s и x Робинсона: насколько сильно редкие признаки притягиваются к 0,5                                                                        |
| `minDistance`                          | `0.1`          | Признаки, которые ближе к 0,5, чем это значение, игнорируются                                                                                          |
| `maxClues`                             | `150`          | Сколько самых сильных признаков объединяется в одном письме                                                                                            |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Границы диапазона `unsure`                                                                                                                             |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Сколько писем ham нужно на языке для полной уверенности, и впятеро меньше писем спама; меньше, если доля `languageShare` от всего ham или спама меньше |
| `languagePrior`                        | `true`         | Взвешивать слова относительно счётчиков их собственного языка                                                                                          |

Также доступны `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` и `entries()`. `Classifier.fromJSON` проверяет модель и при повреждённых данных выбрасывает `TypeError`, начинающийся с `Corrupt classifier model`. В JSON нет `Infinity`, поэтому параметр, сохранённый версией 7.0.3 как `Infinity`, читается обратно как `null`: он считается `Infinity` для `maxClues`, `minDistance` и `minLanguageExamples`, `-Infinity` для `hamCutoff` (никогда не ham) и `Infinity` для `spamCutoff` (никогда не spam), а для остальных — значением по умолчанию. `toJSON` сохраняет порог за пределами 0 и 1 как -1 или 2, что работает так же. `loadModel` перечитывает файл, когда он меняется, а `saveModel` пишет через временный файл.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` у milter — его ответ, когда проверка не удалась или ClamAV не смог проверить вложение: `'tempfail'` (по умолчанию) или `'accept'`, при котором письмо передаётся дальше с пометкой `X-Spam-Virus-Scan: failed`, без заголовков `X-Spam-*`, добавленных отправителем.

### Отчёты ARF

`spamscanner/arf` читает и создаёт отчёты о злоупотреблениях (RFC 5965) — формат, в котором почтовые провайдеры сообщают о жалобах на спам:

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

`ArfParser.tryParse()` возвращает `null` вместо исключения для писем, которые не являются отчётами, а `isArfMessage(mail)` проверяет разобранное письмо. Для отчёта без исходного письма `originalHeaders` равен `null`. `create()` возвращает строку или `Buffer`, если `originalMessage` тоже передан буфером, поэтому его байты сохраняются независимо от кодировки.
