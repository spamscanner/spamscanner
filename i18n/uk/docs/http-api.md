<!-- source: faf44f093f8b -->

# HTTP API, TCP-сервер і spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Він слухає на 127.0.0.1, якщо `--host` не вказує інше. З токеном кожен запит, крім `/health`, потребує `Authorization: Bearer <token>`. Перш ніж відкривати його за межі комп’ютера, поставте його за зворотний проксі з TLS.

| Метод і шлях       | Тіло              | Відповідь                                                    |
| ------------------ | ----------------- | ------------------------------------------------------------ |
| `GET /health`      |                   | `{"ok": true, "version": "7.0.0"}`                           |
| `POST /scan`       | Необроблений лист | [Результат перевірки](api.md#the-result) у JSON              |
| `POST /check`      | Необроблений лист | Лист із доданими заголовками `X-Spam-*`, як `message/rfc822` |
| `POST /learn/spam` | Необроблений лист | `{"ok": true, "learned": "spam"}`; потрібен токен            |
| `POST /learn/ham`  | Необроблений лист | `{"ok": true, "learned": "ham"}`; потрібен токен             |

Параметри запиту описують сеанс SMTP:

| Параметр     | Значення                                                       |
| ------------ | -------------------------------------------------------------- |
| `ip`         | IP-адреса клієнта                                              |
| `hostname`   | Його перевірене зворотне DNS-ім’я                              |
| `helo`       | Його ім’я в HELO або EHLO                                      |
| `from`       | Відправник у конверті                                          |
| `to`         | Отримувач; повторіть параметр або розділіть кількох комами     |
| `verbose=1`  | `/scan`: також повернути список слів і тему                    |
| `subjectTag` | `/check`: додати префікс до теми спаму, наприклад `%5BSPAM%5D` |

`/check` також повертає `X-Spam-Flag`, `X-Spam-Score` і `X-Spam-Action` як заголовки відповіді, тож клієнт може ухвалити рішення, не розбираючи лист.

Листи, більші за 25 МБ, отримують `413`. Перевірка, що завершилася збоєм, отримує `500` з `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

З `--out model.json` те, чого навчає `/learn`, зберігається в цей файл після кожного запиту. Без нього вивчене зберігається лише до перезапуску сервера.

З Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

З Python:

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## TCP-сервер

```sh
spamscanner server --port 7830
```

Надішліть необроблений лист, закрийте передавальну сторону з’єднання й прочитайте один рядок JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

З `--verbose` відповіддю натомість є рядок тексту: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` або `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Сумісний зі SpamAssassin сервер для spamc, Exim, Haraka та інших клієнтів SpamAssassin. [Налаштування Exim і Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Команда         | Відповідь                                                 |
| --------------- | --------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                 |
| `SYMBOLS`       | Вердикт і назви тестів, що спрацювали                     |
| `REPORT`        | Вердикт і таблиця тестів, балів і причин                  |
| `REPORT_IFSPAM` | Як `REPORT`, але з порожнім звітом для ham                |
| `PROCESS`       | Вердикт і лист із заголовками `X-Spam-*`                  |
| `HEADERS`       | Вердикт і блок заголовків листа із заголовками `X-Spam-*` |
| `PING`          | `PONG`                                                    |
| `SKIP`          | Нічого                                                    |
| `TELL`          | Вивчає спам або ham, з `--allow-tell`; зберігає в `--out` |

Стиснені запити (`Compress: zlib`) відхиляються.
