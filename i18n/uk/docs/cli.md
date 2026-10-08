<!-- source: c061da9312ad -->

# Командний рядок

```text
spamscanner <command> [options]
```

| Команда                                    | Що робить                                                                         |
| ------------------------------------------ | --------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Перевіряє лист із файлу або стандартного вводу                                    |
| `filter -f <sender> -- <recipients...>`    | Контент-фільтр Postfix: перевіряє стандартний ввід, додає заголовки, передає далі |
| `milter`                                   | Milter для Postfix і Sendmail, порт 7831                                          |
| `http`                                     | HTTP API, порт 7832                                                               |
| `server`                                   | Простий TCP-сервер, порт 7830                                                     |
| `spamd`                                    | Сумісний зі SpamAssassin сервер spamd, порт 783                                   |
| `train`                                    | Навчає модель на файлах mbox, каталогах Maildir, теках або наборах даних          |
| `eval`                                     | Вимірює якість моделі на розміченій пошті                                         |
| `learn spam\|ham [file\|-] --model <file>` | Навчає модель на одному листі                                                     |
| `llm-test`                                 | Перевіряє налаштування мовної моделі на трьох зразкових листах                    |
| `models`                                   | Виводить рекомендовані відкриті моделі                                            |
| `version`, `help`                          |                                                                                   |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Параметр                   | Значення                                                  |
| -------------------------- | --------------------------------------------------------- |
| `--json`                   | Вивести повний результат у JSON                           |
| `--headers`                | Вивести лист із доданими заголовками `X-Spam-*`           |
| `--subject-tag <tag>`      | Також додати префікс до теми спаму                        |
| `--verbose`                | Показати кожен тест і найсильніші ознаки класифікатора    |
| `--threshold <n>`          | Бал, з якого пошта вважається спамом (за замовчуванням 5) |
| `--reject-threshold <n>`   | Бал, з якого пошта відхиляється (за замовчуванням 15)     |
| `--model <file>`           | Файл моделі замість вбудованої                            |
| `--no-classifier`          | Не використовувати класифікатор                           |
| `--config <file>`          | Файл JSON із [параметрами бібліотеки](api.md#options)     |
| `--allow-language <codes>` | Дозволені мови, наприклад `en,de,fr`                      |

Коди виходу: 0 — ham (бажаний лист), 1 — спам, 2 — помилка.

### Сеанс SMTP

| Параметр            | Значення                                    |
| ------------------- | ------------------------------------------- |
| `--ip <address>`    | IP-адреса клієнта, який надіслав лист       |
| `--hostname <name>` | Перевірене зворотне DNS-ім’я клієнта        |
| `--helo <name>`     | Ім’я, яке він назвав у HELO або EHLO        |
| `--from <address>`  | Відправник у конверті (MAIL FROM)           |
| `--to <address>`    | Отримувач у конверті; повторіть для кількох |

### Перевірки

| Параметр              | Значення                                                                            |
| --------------------- | ----------------------------------------------------------------------------------- |
| `--auth`              | Перевіряти SPF, DKIM, DMARC і ARC (потрібен `--ip`)                                 |
| `--dnsbl <zone>`      | Чорний список IP, наприклад `zen.spamhaus.org`; можна повторювати                   |
| `--uribl <zone>`      | Чорний список доменів для посилань, наприклад `dbl.spamhaus.org`; можна повторювати |
| `--dns-server <ip>`   | Сервер імен для перевірок DNS; можна повторювати                                    |
| `--no-cloudflare`     | Не запитувати фільтрувальні резолвери Cloudflare про посилання                      |
| `--clamav [socket]`   | Перевіряти вкладення через clamd на його стандартному або вказаному сокеті          |
| `--allowlist <value>` | Завжди приймати цю IP-адресу, домен або адресу; можна повторювати                   |
| `--denylist <value>`  | Завжди відхиляти цю IP-адресу, домен або адресу; можна повторювати                  |

### Мовна модель

| Параметр                                                   | Значення                                                                                                                                           |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` та інші ([перелік](llm.md#providers))                                                         |
| `--llm-model <name>`                                       | Модель, наприклад `qwen3.5:4b` або `claude-haiku-4-5`                                                                                              |
| `--llm-method <method>`                                    | `decision` (ймовірність для кожного вердикту за один крок; за замовчуванням, де доступно) або `generate` ([методи](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | ID облікового запису Cloudflare, для `clef` і `clef-flash`                                                                                         |
| `--llm-url <url>`                                          | Базова URL-адреса, наприклад `http://10.0.0.5:11434`                                                                                               |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Змінити одну частину URL-адреси провайдера                                                                                                         |
| `--llm-api-key <key>`                                      | Ключ API; див. також змінні середовища нижче                                                                                                       |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` або `none`                                                                                     |
| `--llm-auth-header <name>`                                 | Заголовок для ключа, з `--llm-auth header`                                                                                                         |
| `--llm-username`, `--llm-password`                         | Для `--llm-auth basic`                                                                                                                             |
| `--llm-header "Name: value"`                               | Додатковий заголовок запиту; можна повторювати                                                                                                     |
| `--llm-mode <mode>`                                        | `auto` (лише спірні випадки, за замовчуванням) або `always`                                                                                        |
| `--llm-timeout <ms>`                                       | За замовчуванням 30000                                                                                                                             |
| `--llm-policy <text>`                                      | Додаткові правила для моделі, наприклад «Ми ніколи не надсилаємо рахунків»                                                                         |
| `--llm-redact`, `--no-llm-redact`                          | Спершу видаляти персональні дані; за замовчуванням увімкнено для віддалених провайдерів                                                            |


## filter

[Контент-фільтр Postfix](postfix.md#content-filter). Він читає лист зі стандартного вводу, додає заголовки `X-Spam-*` і передає його до sendmail з тим самим конвертом.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Параметр              | Значення                                                                  |
| --------------------- | ------------------------------------------------------------------------- |
| `--sendmail <path>`   | За замовчуванням `/usr/sbin/sendmail`                                     |
| `--subject-tag <tag>` | Додати префікс до теми спаму                                              |
| `--reject`            | Повертати відправнику пошту на порозі відхилення замість передавання далі |
| `--discard`           | Відкидати пошту на порозі відхилення замість передавання далі             |

Коди виходу відповідають домовленостям sendmail, які читає Postfix: 0 — доставлено (або відкинуто), 64 — не вказано отримувачів, 69 — відхилено як спам (Postfix повертає лист відправнику), 75 — будь-який збій, тож Postfix зберігає лист і пробує пізніше.


## milter, http, server і spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Порт 783 клієнти SpamAssassin використовують за замовчуванням. Порти нижче 1024 потребують root або можливості `CAP_NET_BIND_SERVICE`; використайте інший порт, наприклад `--port 7833`, і вкажіть його клієнту.

| Параметр              | Значення                                                                         |
| --------------------- | -------------------------------------------------------------------------------- |
| `--port <n>`          | TCP-порт                                                                         |
| `--host <ip>`         | Адреса для прослуховування (за замовчуванням 127.0.0.1)                          |
| `--socket <path>`     | Натомість слухати на Unix-сокеті                                                 |
| `--reject`            | Milter: відхиляти пошту на порозі відхилення                                     |
| `--reject-code <n>`   | Milter: 451, спробуйте пізніше (за замовчуванням), або 550                       |
| `--quarantine`        | Milter: тримати спам у карантині поштового сервера                               |
| `--name <hostname>`   | Milter: ім’я цього сервера в Authentication-Results                              |
| `--token <secret>`    | HTTP: вимагати `Authorization: Bearer <secret>`; потрібно для `/learn`           |
| `--allow-tell`        | spamd: приймати запити TELL (`spamc -L spam`) для навчання                       |
| `--out <file>`        | HTTP і spamd: зберігати вивчене в цей файл моделі                                |
| `--subject-tag <tag>` | Milter і spamd: додавати префікс до теми спаму                                   |
| `--verbose`           | Milter: журналювати кожну перевірку. TCP-сервер: відповідати одним рядком тексту |

Наведені вище параметри перевірки діють і для серверів. [Milter](postfix.md#milter), [HTTP API, TCP-сервер і spamd](http-api.md).


## train, eval і learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Параметр                                        | Значення                                                                      |
| ----------------------------------------------- | ----------------------------------------------------------------------------- |
| `--spam <path>`                                 | Спам: файл mbox, каталог Maildir або тека з файлами `.eml`; можна повторювати |
| `--ham <path>`                                  | Ham, так само; можна повторювати                                              |
| `--dataset <file>`                              | Файл CSV або JSON Lines зі стовпцями тексту й мітки; можна повторювати        |
| `--text-column <name>`, `--label-column <name>` | Назви стовпців, коли їх не вдається визначити автоматично                     |
| `--out <file>`                                  | Куди записати модель (за замовчуванням `spamscanner-model.json`)              |
| `--merge`                                       | Почати з вбудованої моделі (або `--model`), а не з порожньої                  |

`learn` оновлює файл моделі на місці, а першого разу створює його з вбудованої моделі. [Навчання](training.md)


## llm-test і models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` надсилає моделі один звичайний лист і два шахрайські, англійською та італійською, виводить її вердикти, час на кожен, використаний метод і обладнання та завершується з кодом 0, лише якщо всі три правильні.


## Файл конфігурації

`--config file.json` (або змінна середовища `SPAMSCANNER_CONFIG`) завантажує [параметри бібліотеки](api.md#options). Параметри командного рядка мають пріоритет над файлом.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Змінні середовища

| Змінна                                                                                                                                                                                                                                                                                                                     | Значення                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                       | Файл конфігурації                                   |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                        | Файл моделі, що використовується замість вбудованої |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                        | Токен для HTTP API                                  |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                  | Ключ API для будь-якого провайдера мовних моделей   |
| `CLOUDFLARE_API_TOKEN` і `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Власний ключ кожного провайдера                     |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                  | Налагоджувальне журналювання                        |
