<!-- source: 8263c06f1dab -->

# Начало работы

Spam Scanner требует Node.js 18 или новее, а с автономным исполняемым файлом не требует ничего.


## Установка

Как инструмент командной строки:

```sh
npm install --global spamscanner
spamscanner version
```

Как библиотека в проекте на Node.js:

```sh
npm install spamscanner
```

Как автономный исполняемый файл для Linux или macOS со встроенными Node.js и моделью:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Исполняемые файлы для Linux (x64 и arm64), macOS (Intel и Apple silicon) и Windows прикреплены к каждому [релизу](https://github.com/spamscanner/spamscanner/releases).


## Проверка письма

Сохраните письмо в файл (в большинстве почтовых программ это называется «Сохранить как» или «Показать оригинал») и проверьте его:

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

Код выхода равен 0 для ham, 1 для спама и 2 при ошибке, поэтому скрипты могут использовать его напрямую. `--json` выводит полный результат, а `--headers` выводит письмо с добавленными заголовками `X-Spam-*`.

Письма также можно передавать через стандартный ввод:

```sh
cat message.eml | spamscanner scan -
```


## Использование из Node.js

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

CommonJS тоже работает:

```js
const SpamScanner = require('spamscanner');
```

`scan()` принимает исходное письмо как Buffer, строку, Uint8Array или поток для чтения. Строка всегда считается текстом письма: Spam Scanner никогда не читает файл только потому, что строка похожа на путь. Для файлов используйте `scanner.scanFile(path)`.


## Сведения об SMTP-сессии

IP-адрес клиента, его проверенное имя хоста, имя из HELO и конверт делают результат точнее: аутентификации нужен IP-адрес, а правилу о подделке собственного домена нужны получатели.

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

То же из командной строки:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Дополнительные проверки

Ни одна из них не включена по умолчанию, потому что каждой нужен сервис или решение:

| Проверка                         | Параметр библиотеки                              | Командная строка            |
| -------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC            | `authentication: true`                           | `--auth`                    |
| Чёрный список IP                 | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Чёрный список доменов для ссылок | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                           | `clamav: true` или `clamav: {socket}`            | `--clamav [socket]`         |
| Языковая модель                  | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Белые и чёрные списки            | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Фильтрующие резолверы Cloudflare (1.1.1.2 для вредоносных программ, 1.1.1.3 для контента для взрослых) по умолчанию получают запросы о хостах из ссылок. Это отключается через `phishing: {cloudflare: false}` или `--no-cloudflare`. [Что покидает машину](security.md)

Spamhaus и некоторые другие чёрные списки не отвечают на запросы через публичные резолверы, такие как 8.8.8.8 или 1.1.1.1. Используйте их с локальным кеширующим резолвером и проверьте их условия использования для вашего объёма почты.


## Дальнейшие шаги

* Поставьте фильтр перед почтовым сервером: [Postfix и Sendmail](postfix.md), [другие серверы](mail-servers.md).
* Обучите его на своей почте: [обучение](training.md).
* Добавьте языковую модель для спорных случаев: [языковые модели](llm.md).
