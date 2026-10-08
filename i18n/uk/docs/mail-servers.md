<!-- source: 1151282f29d3 -->

# Інші поштові сервери

Spam Scanner підтримує чотири протоколи, тож більшість поштових програм можуть використовувати його без окремого плагіна:

| Протокол | Команда                                  | Хто використовує                                         |
| -------- | ---------------------------------------- | -------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (з filter-milter)           |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka і будь-що, написане для SpamAssassin |
| HTTP     | `spamscanner http`                       | Скрипти, вебхуки, власні MTA та сервіси                  |
| Конвеєр  | `spamscanner scan`, `spamscanner filter` | Конвеєри Postfix, procmail, maildrop, завдання cron      |

Для [Postfix і Sendmail](postfix.md) є окрема сторінка.


## Пряма заміна spamd від SpamAssassin

`spamscanner spamd` відповідає за протоколом spamd від SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING`, а з `--allow-tell` — і `TELL`. Програми, написані для SpamAssassin, працюють без змін; зупиніть `spamd` і запустіть Spam Scanner на тому самому порту.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Зі spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Наскрізні тести репозиторію запускають проти нього власний spamc від SpamAssassin.


## Exim

Умова ACL `spam` в Exim звертається до spamd. В основній конфігурації:

```text
spamd_address = 127.0.0.1 783
```

У DATA ACL (`acl_check_data` в exim4 у Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` відповідає тимчасовою помилкою 4xx, тож відправники повторюють спробу, а помилку можна виправити. Коли результати виглядатимуть правильними, змініть на `deny` для постійного відхилення.


## Haraka

Плагін `spamassassin` у Haraka звертається до spamd. Увімкніть його в `config/plugins` і задайте в `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: тека «Спам» і навчання

Правило Sieve переміщує позначену пошту в Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

З IMAPSieve переміщення листа в Junk або з нього може навчати модель. Запустіть HTTP API з токеном і файлом моделі:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

і вкажіть milter або серверу spamd ту саму модель через `--model /var/lib/spamscanner/model.json` (або `SPAMSCANNER_MODEL`). Час від часу перезапускайте його, щоб підхопити вивчене. Скрипт, який запускає `sieve_pipe`, надсилає лист:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

[Посібник Dovecot зі звітування про спам](https://doc.dovecot.org/main/core/config/spam_reporting.html) описує решту налаштування, однакову для будь-якого спам-фільтра, що вчиться через скрипт.


## procmail і maildrop

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

`scan --headers` завершується з кодом 1 для спаму. З наведеними правилами procmail і maildrop використовують виведення, а не код виходу.


## HTTP API

Будь-яка програма, що вміє надсилати HTTP-запити, може перевіряти пошту:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

На сторінці [HTTP API](http-api.md) перелічено всі кінцеві точки.


## Усередині поштового сервера на Node.js

Зі [smtp-server](https://nodemailer.com/extras/smtp-server/), плагінами Haraka або будь-яким іншим сервером на Node.js викликайте бібліотеку напряму:

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

`session.envelope` зі smtp-server уже має структуру `mailFrom` і `rcptTo`, яку читає Spam Scanner.
