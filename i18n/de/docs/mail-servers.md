<!-- source: 1151282f29d3 -->

# Andere Mailserver

Spam Scanner spricht vier Protokolle, daher kann die meiste Mailsoftware ihn ohne eigenes Plugin verwenden:

| Protokoll | Befehl                                   | Verwendet von                                                       |
| --------- | ---------------------------------------- | ------------------------------------------------------------------- |
| Milter    | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (mit filter-milter)                    |
| spamd     | `spamscanner spamd`                      | spamc, Exim, Haraka und allem, was für SpamAssassin geschrieben ist |
| HTTP      | `spamscanner http`                       | Skripten, Webhooks, eigenen MTAs und Diensten                       |
| Pipe      | `spamscanner scan`, `spamscanner filter` | Postfix-Pipes, procmail, maildrop, Cronjobs                         |

[Postfix und Sendmail](postfix.md) haben eine eigene Seite.


## Ein direkter Ersatz für spamd von SpamAssassin

`spamscanner spamd` beantwortet das spamd-Protokoll von SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` und, mit `--allow-tell`, `TELL`. Für SpamAssassin geschriebene Software funktioniert unverändert: `spamd` stoppen und Spam Scanner auf demselben Port starten.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Mit spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Die End-to-End-Tests des Repositorys lassen das spamc von SpamAssassin selbst dagegen laufen.


## Exim

Die ACL-Bedingung `spam` von Exim spricht mit spamd. In der Hauptkonfiguration:

```text
spamd_address = 127.0.0.1 783
```

In der DATA-ACL (`acl_check_data` in exim4 von Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` antwortet mit einem temporären 4xx-Fehler, sodass Absender es erneut versuchen und sich ein Fehler korrigieren lässt. Ändern Sie es in `deny` für eine dauerhafte Ablehnung, sobald die Ergebnisse stimmen.


## Haraka

Das Plugin `spamassassin` von Haraka spricht mit spamd. Aktivieren Sie es in `config/plugins` und setzen Sie in `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Junk-Ordner und Lernen

Eine Sieve-Regel legt markierte E-Mails in Junk ab:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Mit IMAPSieve kann das Verschieben einer Nachricht in den oder aus dem Junk-Ordner dem Modell etwas beibringen. Starten Sie die HTTP-API mit einem Token und einer Modelldatei:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

und richten Sie den Milter oder spamd-Server mit `--model /var/lib/spamscanner/model.json` (oder `SPAMSCANNER_MODEL`) auf dasselbe Modell aus. Starten Sie ihn ab und zu neu, damit er das Gelernte übernimmt. Ein von `sieve_pipe` ausgeführtes Skript sendet die Nachricht:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Die [Anleitung zur Spam-Meldung](https://doc.dovecot.org/main/core/config/spam_reporting.html) von Dovecot zeigt den Rest der Einrichtung, der für jeden Spamfilter gleich ist, der über ein Skript lernt.


## procmail und maildrop

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

`scan --headers` beendet sich bei Spam mit 1. procmail und maildrop verwenden mit den obigen Regeln die Ausgabe, nicht den Exit-Code.


## HTTP-API

Jedes Programm, das eine HTTP-Anfrage stellen kann, kann E-Mails prüfen:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[Die HTTP-API](http-api.md) listet alle Endpunkte auf.


## In einem Node.js-Mailserver

Mit [smtp-server](https://nodemailer.com/extras/smtp-server/), Haraka-Plugins oder einem anderen Node.js-Server rufen Sie die Bibliothek direkt auf:

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

`session.envelope` aus smtp-server hat bereits die Form mit `mailFrom` und `rcptTo`, die Spam Scanner liest.
