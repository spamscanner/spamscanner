<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner создан в [Forward Email](https://forwardemail.net), почтовом сервисе с открытым исходным кодом, ориентированном на приватность, для собственных почтовых серверов. Forward Email не хранит журналов с содержимым писем, поэтому внешний сервис фильтрации не подходил: фильтр должен был работать на собственных серверах и объяснять каждое решение без того, чтобы человек читал почту.

На этой странице показано, как его использует почтовый сервер вроде серверов Forward Email и что изменилось для кода, написанного под Spam Scanner 5 или 6.


## На сервере входящей почты

Forward Email принимает почту с помощью [smtp-server](https://nodemailer.com/extras/smtp-server/). Шаблон для любого сервера на его основе:

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

`scanner.scan()` принимает SMTP-поток напрямую. Если результаты [mailauth](https://github.com/postalsys/mailauth) уже есть, пропустите `authentication` и передайте только IP-адрес.

Ответ 421 или 451 заставляет отправляющий сервер поставить письмо в очередь и повторить попытку позже. Новые правила отклонения можно начать с временного кода и перейти на 550, когда их результаты проверены, не теряя почту в промежутке.


## Обновление с версии 5 или 6

Версия 7 переписана заново. Конструктор, `scan()` и поля результата, которые читает код для версий 5 и 6, по-прежнему работают; изменились классификатор, модель и необязательные проверки на TensorFlow.

### Без изменений

* `new SpamScanner(options)` и `await scanner.scan(source)`.
* `require('spamscanner')` возвращает класс, и `import SpamScanner from 'spamscanner'` работает.
* `result.isSpam`, `result.message`, а также `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` и `.idnHomographAttack`.
* Каждый элемент в `results.phishing`, `.executables`, `.arbitrary` и `.viruses` преобразуется в такую же строку сообщения, как раньше (`String(item)`, шаблонные строки, `message.includes('adult-related content')`). Теперь это объекты с `type`, `message` и подробностями.
* `getTokensAndMailFromSource()`, `getClassification()` и `getTokens()`.
* Эти параметры соответствуют новым именам: `clamscan` — `clamav`, `enableMacroDetection: false` — `macros: false`, `enableArbitraryDetection: false` — `arbitrary: false`, `enableAuthentication` с `authOptions` — `authentication` и `session`, `enableReputation` с `reputationOptions.apiUrl` — `reputation`, `strictIDNDetection` — `phishing.homograph.strictMode`, а также `allowlist` и `denylist`. `logger` и `memoize` принимаются и игнорируются.

### Изменения

| Раньше                                                                                      | Теперь                                                                                                                                                 |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `scan('path/to/file.eml')` читал файл                                                       | Строка считается текстом письма. Используйте `scanFile(path)` или передайте Buffer                                                                     |
| Наивная байесовская модель слов (`classifier.json`), которую теперь нельзя загрузить        | Новый классификатор и формат модели; переобучите модель через `spamscanner train` ([обучение](training.md))                                            |
| Проверки на токсичность и NSFW загружали модели TensorFlow из сети при первом использовании | Своя модель: `toxicity: {model}` и `nsfw: {model}` принимают любой объект с методом `classify()`, например из `@tensorflow-models/toxicity` и `nsfwjs` |
| `results.arbitrary` перечислял все совпавшие шаблоны                                        | Он перечисляет правила, достаточно сильные, чтобы самостоятельно пометить спам; все правила есть в `result.tests`                                      |
| Ответ «да» или «нет»                                                                        | `result.score`, `result.action` (`accept`, `tag` или `reject`) и `result.tests`, каждый с баллами и причиной                                           |
| `isSpam` определял классификатор или любая отдельная проверка                               | `isSpam` означает оценку 5 или выше; пороги и баллы можно менять                                                                                       |
| Проверки репутации через конечную точку Forward Email                                       | Универсальный сервис репутации, выключен, пока не задан `reputation.apiUrl`                                                                            |

### Новое

* [Языковые модели](llm.md) для спорных случаев, локальные или облачные.
* SPF, DKIM, DMARC и ARC; чёрные списки в DNS; фильтрующие резолверы Cloudflare.
* Проверки вложений по содержимому: замаскированные исполняемые файлы, архивы, макросы, активные PDF.
* [Milter, HTTP API, TCP-сервер и сервер spamd](mail-servers.md), а также [командная строка](cli.md).
* Обучение, оценка качества и обучение по жалобам из командной строки или через API.
