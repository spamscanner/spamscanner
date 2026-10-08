<!-- source: 1151282f29d3 -->

# Другие почтовые серверы

Spam Scanner поддерживает четыре протокола, поэтому большинство почтовых программ могут использовать его без отдельного плагина:

| Протокол | Команда                                  | Кто использует                                           |
| -------- | ---------------------------------------- | -------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (с filter-milter)           |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka и всё, что написано для SpamAssassin |
| HTTP     | `spamscanner http`                       | Скрипты, вебхуки, собственные MTA и сервисы              |
| Конвейер | `spamscanner scan`, `spamscanner filter` | Конвейеры Postfix, procmail, maildrop, задания cron      |

Для [Postfix и Sendmail](postfix.md) есть отдельная страница.


## Прямая замена spamd из SpamAssassin

`spamscanner spamd` отвечает по протоколу spamd из SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` и, с `--allow-tell`, `TELL`. Программы, написанные для SpamAssassin, работают без изменений: остановите `spamd` и запустите Spam Scanner на том же порту.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Со spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Сквозные тесты репозитория проверяют его с помощью собственного spamc из SpamAssassin.


## Exim

Условие ACL `spam` в Exim обращается к spamd. В основной конфигурации:

```text
spamd_address = 127.0.0.1 783
```

В ACL для DATA (`acl_check_data` в exim4 из Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` отвечает временной ошибкой 4xx, поэтому отправители повторяют попытку, а ошибку можно исправить. Когда результаты выглядят правильно, замените его на `deny` для окончательного отказа.


## Haraka

Плагин `spamassassin` в Haraka обращается к spamd. Включите его в `config/plugins` и задайте в `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: папка «Спам» и обучение

Правило Sieve раскладывает помеченную почту в Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

С IMAPSieve перемещение письма в Junk или из него может обучать модель. Запустите HTTP API с токеном и файлом модели:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

и укажите milter или серверу spamd ту же модель через `--model /var/lib/spamscanner/model.json` (или `SPAMSCANNER_MODEL`). Время от времени перезапускайте его, чтобы подхватить результаты обучения. Скрипт, запускаемый через `sieve_pipe`, отправляет письмо:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

[Руководство Dovecot по жалобам на спам](https://doc.dovecot.org/main/core/config/spam_reporting.html) описывает остальную настройку, которая одинакова для любого спам-фильтра, обучаемого через скрипт.


## procmail и maildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop:

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

`scan --headers` завершается с кодом 1 для спама. С правилами выше procmail и maildrop используют вывод, а не код выхода.


## HTTP API

Любая программа, способная отправить HTTP-запрос, может проверять почту:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

На странице [HTTP API](http-api.md) перечислены все конечные точки.


## Внутри почтового сервера на Node.js

С [smtp-server](https://nodemailer.com/extras/smtp-server/), плагинами Haraka или любым другим сервером на Node.js вызывайте библиотеку напрямую:

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({authentication: true});

// smtp-server's onData handler
async function onData(stream, session, callback) {
  const result = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (result.action === 'reject') {
    const error = new Error('Message rejected as spam');
    error.responseCode = 451;
    return callback(error);
  }

  // Deliver, with result.isSpam deciding the folder.
  callback();
}
```

`session.envelope` из smtp-server уже имеет структуру `mailFrom` и `rcptTo`, которую читает Spam Scanner.
