<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner створив [Forward Email](https://forwardemail.net), поштовий сервіс із відкритим кодом, зосереджений на приватності, для власних поштових серверів. Forward Email не зберігає журналів із вмістом листів, тож жоден сторонній сервіс фільтрації не підходив: фільтр мав працювати на власних серверах і пояснювати кожне рішення без того, щоб людина читала пошту.

На цій сторінці показано, як його використовує поштовий сервер на кшталт серверів Forward Email, і що змінилося для коду, написаного для Spam Scanner 5 або 6.


## На сервері вхідної пошти

Forward Email отримує пошту за допомогою [smtp-server](https://nodemailer.com/extras/smtp-server/). Шаблон для будь-якого сервера на його основі:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()` приймає потік SMTP напряму. Якщо результати [mailauth](https://github.com/postalsys/mailauth) уже є, пропустіть `authentication` і передайте лише IP-адресу.

Відповідь 421 або 451 змушує сервер-відправник поставити лист у чергу й спробувати пізніше. Нові правила відхилення можна починати з тимчасового коду й переходити на 550, коли їхні результати перевірено, не втрачаючи пошти в проміжку.


## Оновлення з версії 5 або 6

Версія 7 переписана заново. Конструктор, `scan()` і поля результату, які читає код для версій 5 і 6, досі працюють; змінилися класифікатор, модель і необов’язкові перевірки на TensorFlow.

### Що залишилося

* `new SpamScanner(options)` і `await scanner.scan(source)`.
* `require('spamscanner')` повертає клас, і `import SpamScanner from 'spamscanner'` працює.
* `result.isSpam`, `result.message`, а також `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` і `.idnHomographAttack`.
* Кожен елемент у `results.phishing`, `.executables`, `.arbitrary` і `.viruses` перетворюється на такий самий рядок повідомлення, як раніше (`String(item)`, шаблонні рядки, `message.includes('adult-related content')`). Тепер це об’єкти з `type`, `message` і подробицями.
* `getTokensAndMailFromSource()`, `getClassification()` і `getTokens()`.
* Ці параметри відображаються на нові назви: `clamscan` на `clamav`, `enableMacroDetection: false` на `macros: false`, `enableArbitraryDetection: false` на `arbitrary: false`, `enableAuthentication` з `authOptions` на `authentication` і `session`, `enableReputation` з `reputationOptions.apiUrl` на `reputation`, `strictIDNDetection` на `phishing.homograph.strictMode`, а також `allowlist` і `denylist`. `logger` і `memoize` приймаються й ігноруються.

### Що змінилося

| Раніше                                                                                                | Тепер                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` читав файл                                                                 | Рядок — це текст листа. Використовуйте `scanFile(path)` або передайте Buffer                                                                                                 |
| Наївна баєсова модель слів (`classifier.json`), яку тепер не можна завантажити                        | Новий класифікатор і формат моделі; перенавчіть за допомогою `spamscanner train` ([навчання](training.md))                                                                   |
| Перевірки на токсичність і NSFW під час першого використання завантажували моделі TensorFlow з мережі | Використовуйте власну модель: `toxicity: {model}` і `nsfw: {model}` приймають будь-який об’єкт із методом `classify()`, наприклад з `@tensorflow-models/toxicity` і `nsfwjs` |
| `results.arbitrary` перелічував кожен шаблон, що збігся                                               | Він перелічує правила, достатньо сильні, щоб самостійно позначити спам; усі правила є в `result.tests`                                                                       |
| Відповідь «так» або «ні»                                                                              | `result.score`, `result.action` (`accept`, `tag` або `reject`) і `result.tests`, кожен із балами та причиною                                                                 |
| `isSpam` визначав класифікатор або будь-яка окрема перевірка                                          | `isSpam` означає бал 5 або більше; пороги й бали можна змінювати                                                                                                             |
| Перевірки репутації через кінцеву точку Forward Email                                                 | Загальний сервіс репутації, вимкнений, доки не задано `reputation.apiUrl`                                                                                                    |

### Нове

* [Мовні моделі](llm.md) для спірних випадків, локальні або хмарні.
* SPF, DKIM, DMARC і ARC; чорні списки DNS; фільтрувальні резолвери Cloudflare.
* Перевірки вкладень за вмістом: замасковані виконувані файли, архіви, макроси, активні PDF.
* [Milter, HTTP API, TCP-сервер і сервер spamd](mail-servers.md), а також [командний рядок](cli.md).
* Навчання, оцінювання й навчання за скаргами, з командного рядка або через API.
