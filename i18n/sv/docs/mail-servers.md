<!-- source: 1151282f29d3 -->

# Andra e-postservrar

Spam Scanner talar fyra protokoll, så de flesta e-postprogram kan använda det utan ett eget insticksprogram:

| Protokoll | Kommando                                 | Används av                                                 |
| --------- | ---------------------------------------- | ---------------------------------------------------------- |
| Milter    | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (med filter-milter)           |
| spamd     | `spamscanner spamd`                      | spamc, Exim, Haraka och allt som skrivits för SpamAssassin |
| HTTP      | `spamscanner http`                       | Skript, webhooks, egna MTA:er och tjänster                 |
| Pipe      | `spamscanner scan`, `spamscanner filter` | Postfix-pipes, procmail, maildrop, cron-jobb               |

[Postfix och Sendmail](postfix.md) har en egen sida.


## En direkt ersättare för SpamAssassins spamd

`spamscanner spamd` svarar på SpamAssassins spamd-protokoll: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` och, med `--allow-tell`, `TELL`. Programvara som skrivits för SpamAssassin fungerar oförändrad; stoppa `spamd` och starta Spam Scanner på samma port.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Med spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Repositoriets end-to-end-tester kör SpamAssassins egen spamc mot det.


## Exim

Exims ACL-villkor `spam` talar med spamd. I huvudkonfigurationen:

```text
spamd_address = 127.0.0.1 783
```

I DATA-ACL:en (`acl_check_data` i Debians exim4):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` svarar med ett tillfälligt 4xx-fel, så avsändare försöker igen och ett misstag kan rättas. Ändra det till `deny` för en permanent avvisning när resultaten ser rätt ut.


## Haraka

Harakas insticksprogram `spamassassin` talar med spamd. Aktivera det i `config/plugins` och ställ in, i `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: skräppostmapp och inlärning

En Sieve-regel sorterar märkt e-post till Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Med IMAPSieve kan modellen lära sig när ett meddelande flyttas till eller från Junk. Starta HTTP-API:t med en token och en modellfil:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

och peka miltern eller spamd-servern mot samma modell med `--model /var/lib/spamscanner/model.json` (eller `SPAMSCANNER_MODEL`). Starta om den då och då så att den läser in det som lärts. Ett skript som körs av `sieve_pipe` skickar meddelandet:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Dovecots [guide för spamrapportering](https://doc.dovecot.org/main/core/config/spam_reporting.html) visar resten av konfigurationen, som är densamma för alla spamfilter som lär sig från ett skript.


## procmail och maildrop

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

`scan --headers` avslutas med 1 för spam. procmail och maildrop använder utdata, inte slutkoden, med reglerna ovan.


## HTTP-API

Alla program som kan göra en HTTP-förfrågan kan skanna e-post:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP-API:t](http-api.md) listar alla slutpunkter.


## I en e-postserver i Node.js

Med [smtp-server](https://nodemailer.com/extras/smtp-server/), Haraka-insticksprogram eller någon annan Node.js-server anropar du biblioteket direkt:

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

`session.envelope` från smtp-server har redan den form med `mailFrom` och `rcptTo` som Spam Scanner läser.
