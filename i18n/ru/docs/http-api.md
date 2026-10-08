<!-- source: faf44f093f8b -->

# HTTP API, TCP-сервер и spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Сервер слушает 127.0.0.1, если в `--host` не указано иное. Если задан токен, каждому запросу, кроме `/health`, нужен `Authorization: Bearer <token>`. Прежде чем открывать доступ к нему за пределами машины, поставьте перед ним обратный прокси с TLS.

| Метод и путь       | Тело            | Ответ                                                             |
| ------------------ | --------------- | ----------------------------------------------------------------- |
| `GET /health`      |                 | `{"ok": true, "version": "7.0.0"}`                                |
| `POST /scan`       | Исходное письмо | [Результат проверки](api.md#the-result) в JSON                    |
| `POST /check`      | Исходное письмо | Письмо с добавленными заголовками `X-Spam-*` как `message/rfc822` |
| `POST /learn/spam` | Исходное письмо | `{"ok": true, "learned": "spam"}`; нужен токен                    |
| `POST /learn/ham`  | Исходное письмо | `{"ok": true, "learned": "ham"}`; нужен токен                     |

Параметры запроса описывают SMTP-сессию:

| Параметр     | Значение                                                                |
| ------------ | ----------------------------------------------------------------------- |
| `ip`         | IP-адрес клиента                                                        |
| `hostname`   | Его проверенное имя в обратной зоне DNS                                 |
| `helo`       | Его имя из HELO или EHLO                                                |
| `from`       | Отправитель в конверте                                                  |
| `to`         | Получатель; повторите параметр или перечислите нескольких через запятую |
| `verbose=1`  | `/scan`: также вернуть список слов и тему                               |
| `subjectTag` | `/check`: добавлять префикс к теме спама, например `%5BSPAM%5D`         |

`/check` также возвращает `X-Spam-Flag`, `X-Spam-Score` и `X-Spam-Action` в заголовках ответа, чтобы клиент мог принять решение, не разбирая письмо.

На письма больше 25 МБ возвращается `413`. На неудачную проверку возвращается `500` с `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

С `--out model.json` всё, чему обучает `/learn`, сохраняется в этот файл после каждого запроса. Без него обучение действует до перезапуска сервера.

Из Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Из Python:

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

Отправьте исходное письмо, закройте передающую сторону соединения и прочитайте одну строку JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

С `--verbose` ответом вместо этого будет строка текста: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` или `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Сервер, совместимый со SpamAssassin, для spamc, Exim, Haraka и других клиентов SpamAssassin. [Настройка Exim и Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Команда         | Ответ                                                            |
| --------------- | ---------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                        |
| `SYMBOLS`       | Вердикт и имена сработавших тестов                               |
| `REPORT`        | Вердикт и таблица тестов, баллов и причин                        |
| `REPORT_IFSPAM` | Как `REPORT`, но с пустым отчётом для ham                        |
| `PROCESS`       | Вердикт и письмо с заголовками `X-Spam-*`                        |
| `HEADERS`       | Вердикт и блок заголовков письма с заголовками `X-Spam-*`        |
| `PING`          | `PONG`                                                           |
| `SKIP`          | Ничего                                                           |
| `TELL`          | Обучение на спаме или ham, с `--allow-tell`; сохраняет в `--out` |

Сжатые запросы (`Compress: zlib`) отклоняются.
