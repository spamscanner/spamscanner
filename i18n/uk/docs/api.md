<!-- source: 9134d1cd102c -->

# Довідник API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Створіть один сканер і використовуйте його повторно: він завантажує модель один раз і кешує відповіді DNS і мовної моделі.

Оголошення типів входять до пакета. Для них потрібен TypeScript 4.7 або новіший з `import` і 5.3 або новіший з `require`.


## Параметри

Кожен параметр можна передати конструктору. Більшість також можна передати до `scan()` для одного листа; вони накладаються на параметри конструктора. Параметри, передані як `undefined`, зберігають типові значення. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` і `strictIDNDetection` читає лише конструктор; файл або об'єкт моделі з `classifier` завантажується там, тож відсутня чи пошкоджена модель одразу спричиняє помилку.

| Параметр                | За замовчуванням                 | Значення                                                                                                                                                                                           |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Бал, з якого лист вважається спамом                                                                                                                                                                |
| `rejectThreshold`       | `15`                             | Бал, з якого `action` дорівнює `reject`                                                                                                                                                            |
| `scores`                | `{}`                             | Бали для тестів: ключі налаштувань або назви тестів ([тести та бали](scoring.md))                                                                                                                  |
| `classifier`            | вбудована модель                 | `Classifier`, об’єкт моделі, шлях до файлу моделі або `false`                                                                                                                                      |
| `classifierOptions`     | `{}`                             | Параметри вбудованої моделі (див. [Класифікатор](#classifier))                                                                                                                                     |
| `allowedLanguages`      | `[]`                             | Коди ISO 639-1 (`no` читається як `nb`, `fil` як `tl`, а старі `iw`, `in`, `ji` як `he`, `id`, `yi`); інші мови отримують `LANGUAGE_NOT_ALLOWED`                                                   |
| `phishing.cloudflare`   | `true`                           | Запитувати фільтрувальні резолвери Cloudflare про хости посилань                                                                                                                                   |
| `phishing.adult`        | `true`                           | Також запитувати сімейний резолвер, який блокує сайти для дорослих                                                                                                                                 |
| `phishing.maxHosts`     | `25`                             | Скільки хостів посилань перевіряти в одному листі                                                                                                                                                  |
| `phishing.maxLength`    | `1000000`                        | Символи тексту, які читаються в пошуках посилань (удвічі більше для HTML); довший текст встановлює `results.linksTruncated`; `Infinity` або будь-що, крім додатного числа, означає типове значення |
| `phishing.homograph`    | `{}`                             | `brands` (замінює вбудований перелік), `extraBrands`, `allowlist` (домени, які ніколи не позначаються), `strictMode`                                                                               |
| `dnsbl`                 | `{ip: [], domain: []}`           | Зони чорних списків DNS для IP-адреси клієнта та доменів посилань                                                                                                                                  |
| `dns`                   | `{servers: null, timeout: 3000}` | Сервери імен для перевірок DNS (за замовчуванням системні)                                                                                                                                         |
| `attachments`           | `true`                           | Перевіряти вкладення                                                                                                                                                                               |
| `macros`                | `true`                           | Позначати макроси, активні PDF і об’єкти RTF                                                                                                                                                       |
| `arbitrary`             | `true`                           | Виконувати [правила](scoring.md#rules)                                                                                                                                                             |
| `authentication`        | `false`                          | `true` або `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([оцінювання](scoring.md#authentication))                                                |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; відповіді зберігаються окремо для кожної служби й набору заголовків, а `cacheSize` діє на весь сканер         |
| `allowlist`, `denylist` |                                  | IP-адреси, домени або адреси; скорочення для `reputation` → [Білий і чорний списки](#allowlist-and-denylist)                                                                                       |
| `clamav`                | `false`                          | `true` (стандартний сокет), `{socket}` або `{host, port}`, з `timeout`: мілісекунди на всі вкладення листа разом (`60000`)                                                                         |
| `llm`                   | `null`                           | [Налаштування мовної моделі](llm.md#any-server-port-and-authentication) з `mode`, `minScore`, `maxScore`                                                                                           |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: модель, чий `classify([text])` відповідає як `@tensorflow-models/toxicity`                                                                                             |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: модель, чий `classify(imageBuffer)` відповідає як `nsfwjs`                                                                                                             |
| `maxLength`             | `100000`                         | Скільки символів тексту тіла читати                                                                                                                                                                |
| `timeout`               | `10000`                          | Скільки мілісекунд дозволено на кожну мережеву перевірку; автентифікація та модель зображень вкладаються в цей час загалом (ClamAV має власний `clamav.timeout`)                                   |
| `session`               | `{}`                             | Типові відомості про сеанс SMTP                                                                                                                                                                    |

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

Сервер, який уже перевірив SPF, DKIM, DMARC і ARC (за допомогою [mailauth](https://github.com/postalsys/mailauth)), може передати свої результати як `authenticationResults`, і їх буде оцінено без повторної перевірки:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Білий і чорний списки

Чорний список порівнює IP-адресу та ім'я хоста клієнта, адреси From, відправника конверта й Reply-To, а також їхні домени, хай якими вони є: ім'я під доменом із чорного списку збігається з ним, навіть якщо воно не є дійсним ім'ям хоста (як-от `a_b!.evil.example` або ім'я з міткою довшою за 63 символи), за своїми останніми 127 мітками та 253 символами. Білий список, а також білий список і довірені джерела служби репутації, порівнюють лише те, чого відправник не може підробити: IP-адресу та перевірене ім'я хоста клієнта (`remoteAddress`, `resolvedClientHostname`), адресу From, коли DMARC проходить для її домену або з нею вирівняний дійсний підпис DKIM (і він є дійсним ім'ям хоста; нестрого, як у DMARC: домен From і домен підпису або домен SPF мають той самий реєстровний домен, який mailauth називає доменом DMARC; запис із піддоменом, як-от `news.example.com`, враховується лише тоді, коли лист підписав або пройшов SPF цей домен, домен під ним або батьківський домен, а не інший піддомен, як-от `evil.example.com`, і не публічний суфікс; проходження DMARC для реєстровного домену без відомостей mailauth про вирівнювання враховується лише для запису з реєстровним доменом; за суворого вирівнювання, тобто `adkim=s` або `aspf=s` у DMARC-записі домену в будь-якому регістрі та з будь-якими пробілами, враховується лише підпис або проходження SPF самого домену From, а без нього DMARC не проходить), і відправника конверта, коли SPF проходить для його домену. Підпис DKIM лише початку тіла листа (довжина тіла, `l=`, коротша за саме тіло: після неї будь-хто може дописати текст) не враховується ні для чого, як і проходження DMARC, що спирається на такий підпис, а коли DMARC не проходить, не враховується жоден підпис, як і для поля From, задовгого, щоб прочитати його повністю (`mail.from.truncated`). Результати, передані в `authenticationResults`, враховуються лише тоді, коли в них названо домен, для якого перевірку пройдено, а домен, що не є ім'ям хоста (як-от `bank.example/x.attacker.example`, який парсери URL читають як `bank.example`), не враховується ні для чого, як і проходження DMARC, що спирається на такий домен. Міжнародні домени збігаються в будь-якій формі: `bücher.example` або `xn--bcher-kva.example`. Reply-To не враховується ніколи. Щоб додати домен до білого списку, увімкніть `authentication` або передайте `authenticationResults`.

Кожен запис — це одна IP-адреса, домен або адреса електронної пошти, що порівнюється точно: запис домену охоплює також його піддомени та адреси в них, але діапазонів адрес (`192.0.2.0/24`), символів підстановки (`*.example.com`) чи шаблонів (`@example.com`) немає. Адреси IPv6 збігаються в будь-якій формі (`2001:0db8::0001` — це `2001:db8::1`, форма з RFC 5952), адреса IPv4, відображена в IPv6 (`::ffff:192.0.2.1`), збігається з адресою IPv4, а адреса IPv4, трансльована в IPv6 або під префіксом NAT64, записується разом із ним у крапково-десятковій формі (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), як у записах, так і в адресах клієнтів.


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
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` листа        |
| `getTokens(text, locale)`            | Слова тексту                                                                   |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                     |
| `parse(source)`                      | `{raw, mail, error}`, де `mail` отримано з mailparser (див. нижче)             |

`scan`, `parse`, `learn`, `unlearn` і `getTokensAndMailFromSource` читають лист однаково: лист, що перевищує ліміти MIME-парсера (понад 1000 частин, заголовок частини понад 1 МБ), читається настільки, наскільки дозволяє парсер. Поля адрес (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To і List-\*) листа, його частин і вкладених повідомлень читаються до 16 КБ кожне, 2000 ком і крапок із комою та 16 вкладених груп, і до 64 КБ загалом для кожного листа, завжди до кінця цілої адреси, тож не читається жодна адреса, якої поле не містить; обрізане поле позначається як `truncated` (`mail.to.truncated`), а обрізане поле From не дає жодного зарахування за автентифікацію відправника. Текст, перший рядок якого не є полем заголовка (`Name: value` або рядок `From`, з якого починається кожен лист у файлах mbox), читається як тіло листа без заголовка, тож `mail.text` — це цей текст. Інші помилки викидаються. `parse` повертає в `error` межу парсера, яку перевищує повідомлення, так само як `scan` повертає її в `parseError`, і null для повідомлення, прочитаного повністю.

У `getFeatures` `text` — це текст, який показує поштовий клієнт і з якого беруться слова, а `hidden` — скільки символів тексту приховує HTML. mailparser тут не робить текст із HTML: `mail.text` містить лише частини зі звичайним текстом і порожній для листа, що складається лише з HTML; текст, який показує його HTML, — це `getFeatures(mail).text`.

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
    unopenedAttachments: [], // attached messages not opened, past the limits they are read within: {filename, reason}
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

Знахідки в `phishing`, `attachments`, `executables`, `macros`, `viruses` і `arbitrary` — це об’єкти з `type` і `message`. `String(finding)` повертає повідомлення. Вкладення вкладеного повідомлення (`message/rfc822`, `message/global`, `.eml`, `.u8msg`) отримують його ім'я: `fw.eml/invoice.exe`. Вірус, який ClamAV знаходить у такому вкладенні, повідомляється лише для нього, а не ще раз для вкладеного повідомлення, що його містить. `virusScanErrors` перелічує вкладення, які ClamAV не зміг перевірити, у вигляді `{filename, error}`: таке повідомлення може містити вірус, тож краще затримати його, ніж доставити. Milter і контент-фільтр відкладають такий лист, якщо `onError` (`--on-error`) не має значення `accept`, а кожен сервер позначає такий лист, який передає далі, заголовком `X-Spam-Virus-Scan: failed`. `virusScanSkipped` перелічує вкладення, більші, ніж приймає clamd (його `StreamMaxLength`), у вигляді `{filename, reason}`: clamd відхиляє їх за кожної спроби, тож, так само як clamav-milter пропускає файл, більший за його `MaxFileSize`, вони не вважаються збоями. Інші його ліміти (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), яких досягає архівна бомба, вважаються збоями. Вкладені повідомлення відкриваються на глибину до трьох рівнів, з не більш ніж 100 вкладеннями в них і 25 МБ загалом; `unopenedAttachments` перелічує не відкриті через ці межі, у вигляді `{filename, reason}`, вкладення яких не перевірялися. Це не враховується в оцінці, бо переслані повідомлення можуть бути так вкладені, але сторона, якій потрібне повідомлення, прочитане повністю, наприклад щоб заблокувати програму в ньому, може відхилити повідомлення з будь-яким таким записом. Загалом відкривається не більше 100 вкладених повідомлень.

Кожен елемент `dnsbl` містить `answers` списку (адреси в 127.0.0.0/8, значення яких документує кожен список). Відповіді, які списки дають на запити, що їх вони відхиляють або на які не можуть відповісти, не є внесенням до списку — ні для адреси клієнта, ні для доменів посилань (знахідки `uribl` у `phishing`): 127.255.255.x у Spamhaus (як-от 127.255.255.254 на запит через публічний резолвер і 127.255.255.255 за надто великої кількості запитів), 127.0.1.255 у Spamhaus DBL, 127.0.0.255 у будь-якому списку та 127.0.0.1 у SURBL і URIBL, які дають таку відповідь резолверам, що їх вони блокують.


## Експорти

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, unwrapLink, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export
// unwrapLink(address): the URL a link goes to, through Safe Links and
// Proofpoint URL Defense, as the scanner reads it (null for no URL)

import ArfParser from 'spamscanner/arf';
```

### Класифікатор

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Параметр                               | За замовчуванням | Значення                                                                                                                                                   |
| -------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`    | s і x Робінсона: наскільки сильно рідкісні ознаки зсуваються до 0,5                                                                                        |
| `minDistance`                          | `0.1`            | Ознаки, ближчі до 0,5, ніж це значення, ігноруються                                                                                                        |
| `maxClues`                             | `150`            | Скільки найсильніших ознак поєднується для одного листа                                                                                                    |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`    | Межі діапазону `unsure`                                                                                                                                    |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02`   | Скільки листів ham потрібно в мові для повної впевненості, і вп’ятеро менше листів спаму; менше, коли частка `languageShare` від усього ham чи спаму менша |
| `languagePrior`                        | `true`           | Зважувати слова відносно лічильників їхньої власної мови                                                                                                   |

Також доступні `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` і `entries()`. `Classifier.fromJSON` перевіряє модель і за пошкоджених даних кидає `TypeError`, що починається з `Corrupt classifier model`. У JSON немає `Infinity`, тож параметр, збережений версією 7.0.3 як `Infinity`, читається назад як `null`: він вважається `Infinity` для `maxClues`, `minDistance` і `minLanguageExamples`, `-Infinity` для `hamCutoff` (ніколи не ham) і `Infinity` для `spamCutoff` (ніколи не spam), а для решти — значенням за замовчуванням. `toJSON` зберігає поріг поза межами 0 і 1 як -1 або 2, що працює так само. `loadModel` перечитує файл, коли він змінюється, а `saveModel` пише через новий тимчасовий файл, який скидається на диск, перш ніж замінити модель, що зберігає свої права доступу.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` для milter — це його відповідь, коли перевірка не вдалася або ClamAV не зміг перевірити вкладення: `'tempfail'` (за замовчуванням) або `'accept'`, за якого лист передається далі з позначкою `X-Spam-Virus-Scan: failed`, без заголовків `X-Spam-*`, доданих відправником.

### Звіти ARF

`spamscanner/arf` читає й записує звіти про зловживання (RFC 5965) — формат, у якому поштові провайдери повідомляють про скарги на спам:

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

`parse()` приймає Buffer, Uint8Array або рядок. `ArfParser.tryParse()` повертає `null` замість винятку для листів, які не є звітами, а `isArfMessage(mail)` перевіряє розібраний лист. Для звіту без оригінального листа `originalHeaders` дорівнює `null`. `create()` повертає рядок або `Buffer`, якщо `originalMessage` теж є буфером, тож його байти зберігаються незалежно від кодування.
