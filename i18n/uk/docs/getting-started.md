<!-- source: 8263c06f1dab -->

# Початок роботи

Spam Scanner потребує Node.js 18 або новішої версії, а з окремим виконуваним файлом — нічого.


## Встановлення

Як інструмент командного рядка:

```sh
npm install --global spamscanner
spamscanner version
```

Як бібліотеку в проєкті Node.js:

```sh
npm install spamscanner
```

Як окремий виконуваний файл для Linux або macOS із вбудованими Node.js і моделлю:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Виконувані файли для Linux (x64 і arm64), macOS (Intel і Apple silicon) і Windows додаються до кожного [випуску](https://github.com/spamscanner/spamscanner/releases).


## Перевірка листа

Збережіть лист у файл (більшість поштових програм називають це «Зберегти як» або «Показати оригінал») і перевірте його:

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

Код виходу дорівнює 0 для ham (бажаного листа), 1 для спаму і 2 у разі помилки, тож скрипти можуть використовувати його напряму. `--json` виводить повний результат, а `--headers` виводить лист із доданими заголовками `X-Spam-*`.

Листи можна також передавати через стандартний ввід:

```sh
cat message.eml | spamscanner scan -
```


## Використання з Node.js

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJS теж працює:

```js
const SpamScanner = require('spamscanner');
```

`scan()` приймає необроблений лист як Buffer, рядок, Uint8Array або потік для читання. Рядок завжди вважається текстом листа: Spam Scanner ніколи не читає файл лише тому, що рядок схожий на шлях. Для файлів використовуйте `scanner.scanFile(path)`.


## Відомості про сеанс SMTP

IP-адреса клієнта, його перевірене ім’я хоста, ім’я HELO і конверт роблять результат точнішим: автентифікації потрібна IP-адреса, а правилу про підробку власного домену — отримувачі.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

Те саме з командного рядка:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Додаткові перевірки

Жодна з них не ввімкнена за замовчуванням, бо кожна потребує сервісу або рішення:

| Перевірка                          | Параметр бібліотеки                              | Командний рядок             |
| ---------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC              | `authentication: true`                           | `--auth`                    |
| Чорний список IP                   | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Чорний список доменів для посилань | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                             | `clamav: true` або `clamav: {socket}`            | `--clamav [socket]`         |
| Мовна модель                       | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Списки дозволу й заборони          | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Фільтрувальні резолвери Cloudflare (1.1.1.2 для шкідливого ПЗ, 1.1.1.3 для вмісту для дорослих) за замовчуванням запитуються про хости посилань. Вимкніть це за допомогою `phishing: {cloudflare: false}` або `--no-cloudflare`. [Що залишає комп’ютер](security.md)

Spamhaus та деякі інші чорні списки не відповідають на запити, надіслані через публічні резолвери, як-от 8.8.8.8 або 1.1.1.1. Використовуйте їх із локальним кешувальним резолвером і перевірте їхні умови використання для вашого обсягу пошти.


## Наступні кроки

* Поставте його перед поштовим сервером: [Postfix і Sendmail](postfix.md), [інші сервери](mail-servers.md).
* Навчіть його на вашій власній пошті: [навчання](training.md).
* Додайте мовну модель для спірних випадків: [мовні моделі](llm.md).
