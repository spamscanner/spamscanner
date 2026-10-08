<!-- source: 1151282f29d3 -->

# Andre mailservere

Spam Scanner taler fire protokoller, så det meste mailsoftware kan bruge den uden et særskilt plugin:

| Protokol | Kommando                                 | Bruges af                                                   |
| -------- | ---------------------------------------- | ----------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (med filter-milter)            |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka og alt, der er skrevet til SpamAssassin |
| HTTP     | `spamscanner http`                       | Scripts, webhooks, egne MTA'er og tjenester                 |
| Pipe     | `spamscanner scan`, `spamscanner filter` | Postfix-pipes, procmail, maildrop, cron-job                 |

[Postfix og Sendmail](postfix.md) har deres egen side.


## En direkte erstatning for SpamAssassins spamd

`spamscanner spamd` svarer på SpamAssassins spamd-protokol: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` og, med `--allow-tell`, `TELL`. Software, der er skrevet til SpamAssassin, virker uændret; stop `spamd`, og start Spam Scanner på samme port.

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

Repositoriets end-to-end-test kører SpamAssassins egen spamc mod den.


## Exim

Exims ACL-betingelse `spam` taler med spamd. I hovedkonfigurationen:

```text
spamd_address = 127.0.0.1 783
```

I DATA-ACL'en (`acl_check_data` i Debians exim4):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` svarer med en midlertidig 4xx-fejl, så afsendere prøver igen, og en fejl kan rettes. Skift den til `deny` for en permanent afvisning, når resultaterne ser rigtige ud.


## Haraka

Harakas plugin `spamassassin` taler med spamd. Slå det til i `config/plugins`, og sæt i `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Junk-mappe og indlæring

En Sieve-regel lægger markeret post i Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Med IMAPSieve kan det at flytte en besked ind i eller ud af Junk lære modellen op. Start HTTP API'et med et token og en modelfil:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

og peg milteren eller spamd-serveren på den samme model med `--model /var/lib/spamscanner/model.json` (eller `SPAMSCANNER_MODEL`). Genstart den en gang imellem for at få det indlærte med. Et script, der køres af `sieve_pipe`, sender beskeden:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Dovecots [vejledning i spamrapportering](https://doc.dovecot.org/main/core/config/spam_reporting.html) viser resten af opsætningen, som er den samme for ethvert spamfilter, der lærer fra et script.


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

`scan --headers` afslutter med 1 for spam. procmail og maildrop bruger outputtet, ikke afslutningskoden, med reglerne ovenfor.


## HTTP API

Ethvert program, der kan sende en HTTP-forespørgsel, kan scanne post:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API'et](http-api.md) viser alle endpoints.


## I en mailserver i Node.js

Med [smtp-server](https://nodemailer.com/extras/smtp-server/), Haraka-plugins eller enhver anden Node.js-server kalder du biblioteket direkte:

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

`session.envelope` fra smtp-server har allerede den `mailFrom`- og `rcptTo`-form, som Spam Scanner læser.
