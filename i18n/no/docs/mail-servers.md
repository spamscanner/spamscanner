<!-- source: 1151282f29d3 -->

# Andre e-postservere

Spam Scanner snakker fire protokoller, så det meste av e-postprogramvare kan bruke det uten et eget tillegg:

| Protokoll | Kommando                                 | Brukes av                                                  |
| --------- | ---------------------------------------- | ---------------------------------------------------------- |
| Milter    | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (med filter-milter)           |
| spamd     | `spamscanner spamd`                      | spamc, Exim, Haraka og alt som er skrevet for SpamAssassin |
| HTTP      | `spamscanner http`                       | Skript, webhooks, egne MTA-er og tjenester                 |
| Pipe      | `spamscanner scan`, `spamscanner filter` | Postfix-pipes, procmail, maildrop, cron-jobber             |

[Postfix og Sendmail](postfix.md) har en egen side.


## En direkte erstatning for SpamAssassins spamd

`spamscanner spamd` svarer på SpamAssassins spamd-protokoll: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` og, med `--allow-tell`, `TELL`. Programvare skrevet for SpamAssassin virker uendret; stopp `spamd` og start Spam Scanner på samme port.

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

Ende-til-ende-testene i repositoriet kjører SpamAssassins egen spamc mot det.


## Exim

ACL-betingelsen `spam` i Exim snakker med spamd. I hovedkonfigurasjonen:

```text
spamd_address = 127.0.0.1 783
```

I DATA-ACL-en (`acl_check_data` i Debians exim4):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` svarer med en midlertidig 4xx-feil, så avsendere prøver igjen og en feil kan rettes. Endre den til `deny` for en permanent avvisning når resultatene ser riktige ut.


## Haraka

Tillegget `spamassassin` i Haraka snakker med spamd. Aktiver det i `config/plugins`, og sett i `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Søppelpost-mappe og læring

En Sieve-regel legger merket e-post i Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Med IMAPSieve kan det å flytte en melding inn i eller ut av Junk lære opp modellen. Start HTTP API-et med et token og en modellfil:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

og pek milteren eller spamd-serveren mot den samme modellen med `--model /var/lib/spamscanner/model.json` (eller `SPAMSCANNER_MODEL`). Start den på nytt nå og da for å ta i bruk det som er lært. Et skript som kjøres av `sieve_pipe`, sender meldingen:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Dovecots [veiledning for spamrapportering](https://doc.dovecot.org/main/core/config/spam_reporting.html) viser resten av oppsettet, som er det samme for ethvert spamfilter som lærer fra et skript.


## procmail og maildrop

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

`scan --headers` avslutter med 1 for spam. procmail og maildrop bruker utdataene, ikke avslutningskoden, med reglene ovenfor.


## HTTP API

Ethvert program som kan sende en HTTP-forespørsel, kan skanne e-post:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API-et](http-api.md) lister opp alle endepunkter.


## Inne i en e-postserver i Node.js

Med [smtp-server](https://nodemailer.com/extras/smtp-server/), Haraka-tillegg eller en hvilken som helst annen Node.js-server kaller du biblioteket direkte:

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

`session.envelope` fra smtp-server har allerede formen med `mailFrom` og `rcptTo` som Spam Scanner leser.
