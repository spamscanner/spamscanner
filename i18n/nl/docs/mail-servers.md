<!-- source: 1151282f29d3 -->

# Andere mailservers

Spam Scanner spreekt vier protocollen, zodat de meeste mailsoftware het zonder eigen plug-in kan gebruiken:

| Protocol | Opdracht                                 | Gebruikt door                                                    |
| -------- | ---------------------------------------- | ---------------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (met filter-milter)                 |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka en alles wat voor SpamAssassin is geschreven |
| HTTP     | `spamscanner http`                       | Scripts, webhooks, eigen MTA's en diensten                       |
| Pipe     | `spamscanner scan`, `spamscanner filter` | Postfix-pipes, procmail, maildrop, cronjobs                      |

[Postfix en Sendmail](postfix.md) hebben een eigen pagina.


## Een vervanging voor spamd van SpamAssassin

`spamscanner spamd` beantwoordt het spamd-protocol van SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` en, met `--allow-tell`, `TELL`. Software die voor SpamAssassin is geschreven, werkt ongewijzigd; stop `spamd` en start Spam Scanner op dezelfde poort.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Met spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

De end-to-endtests van de repository draaien de eigen spamc van SpamAssassin ertegen.


## Exim

De ACL-voorwaarde `spam` van Exim praat met spamd. In de hoofdconfiguratie:

```text
spamd_address = 127.0.0.1 783
```

In de DATA-ACL (`acl_check_data` in exim4 van Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` antwoordt met een tijdelijke 4xx-fout, zodat afzenders het opnieuw proberen en een fout te herstellen is. Verander het in `deny` voor een definitieve weigering zodra de resultaten kloppen.


## Haraka

De plug-in `spamassassin` van Haraka praat met spamd. Zet hem aan in `config/plugins` en stel in `config/spamassassin.ini` in:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Junk-map en leren

Een Sieve-regel zet gemarkeerde mail in Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Met IMAPSieve kan het verplaatsen van een bericht naar of uit Junk het model iets leren. Start de HTTP API met een token en een modelbestand:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

en laat de milter- of spamd-server hetzelfde model gebruiken met `--model /var/lib/spamscanner/model.json` (of `SPAMSCANNER_MODEL`). Herstart hem af en toe om op te pikken wat er is geleerd. Een script dat door `sieve_pipe` wordt gedraaid, post het bericht:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

De [handleiding voor spammeldingen](https://doc.dovecot.org/main/core/config/spam_reporting.html) van Dovecot laat de rest van de configuratie zien, die hetzelfde is voor elk spamfilter dat via een script leert.


## procmail en maildrop

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

`scan --headers` eindigt met 1 voor spam. procmail en maildrop gebruiken met de regels hierboven de uitvoer, niet de exitcode.


## HTTP API

Elk programma dat een HTTP-verzoek kan doen, kan mail scannen:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[De HTTP API](http-api.md) noemt elk endpoint.


## In een Node.js-mailserver

Roep met [smtp-server](https://nodemailer.com/extras/smtp-server/), Haraka-plug-ins of elke andere Node.js-server de bibliotheek direct aan:

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

`session.envelope` van smtp-server heeft al de vorm met `mailFrom` en `rcptTo` die Spam Scanner leest.
