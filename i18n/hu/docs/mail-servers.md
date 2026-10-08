<!-- source: 1151282f29d3 -->

# Más levelezőszerverek

A Spam Scanner négy protokollt ismer, így a legtöbb levelezőszoftver saját bővítmény nélkül is használhatja:

| Protokoll | Parancs                                  | Ki használja                                              |
| --------- | ---------------------------------------- | --------------------------------------------------------- |
| Milter    | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (filter-milterrel)           |
| spamd     | `spamscanner spamd`                      | spamc, Exim, Haraka és minden, amit SpamAssassinhoz írtak |
| HTTP      | `spamscanner http`                       | Szkriptek, webhookok, egyedi MTA-k és szolgáltatások      |
| Pipe      | `spamscanner scan`, `spamscanner filter` | Postfix pipe-ok, procmail, maildrop, cron feladatok       |

A [Postfix és a Sendmail](postfix.md) külön oldalt kapott.


## Közvetlen csere a SpamAssassin spamd-jére

A `spamscanner spamd` a SpamAssassin spamd protokollján válaszol: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` és a `--allow-tell` kapcsolóval `TELL`. A SpamAssassinhoz írt szoftverek változatlanul működnek: le kell állítani a `spamd` szolgáltatást, és ugyanazon a porton el kell indítani a Spam Scannert.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

A spamc-vel:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

A tároló végpontok közötti tesztjei magát a SpamAssassin spamc-jét futtatják ellene.


## Exim

Az Exim `spam` ACL-feltétele a spamd-vel kommunikál. A fő konfigurációban:

```text
spamd_address = 127.0.0.1 783
```

A DATA ACL-ben (a Debian exim4 csomagjában `acl_check_data`):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

A `defer` ideiglenes 4xx hibával válaszol, így a feladók újra próbálkoznak, és a hiba javítható. Ha az eredmények megfelelőnek tűnnek, a végleges elutasításhoz cserélje `deny`-ra.


## Haraka

A Haraka `spamassassin` bővítménye a spamd-vel kommunikál. Kapcsolja be a `config/plugins` fájlban, és a `config/spamassassin.ini` fájlban állítsa be:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Levélszemét mappa és tanulás

Egy Sieve-szabály a megjelölt leveleket a Levélszemét mappába helyezi:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

IMAPSieve-vel a levelek Levélszemét mappába vagy onnan kifelé mozgatása tanítja a modellt. Indítsa el a HTTP API-t egy tokennel és egy modellfájllal:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

majd állítsa a miltert vagy a spamd szervert ugyanerre a modellre a `--model /var/lib/spamscanner/model.json` kapcsolóval (vagy a `SPAMSCANNER_MODEL` változóval). Időnként indítsa újra, hogy átvegye a tanultakat. A `sieve_pipe` által futtatott szkript elküldi a levelet:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

A Dovecot [spamjelentési útmutatója](https://doc.dovecot.org/main/core/config/spam_reporting.html) bemutatja a beállítás többi részét, amely ugyanaz minden olyan spamszűrőnél, amely szkriptből tanul.


## procmail és maildrop

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

A `scan --headers` spam esetén 1-es kóddal lép ki. A fenti szabályokkal a procmail és a maildrop a kimenetet használja, nem a kilépési kódot.


## HTTP API

Bármely program, amely HTTP-kérést tud küldeni, vizsgálhat leveleket:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[A HTTP API](http-api.md) oldal minden végpontot felsorol.


## Node.js-levelezőszerveren belül

Az [smtp-server](https://nodemailer.com/extras/smtp-server/), a Haraka-bővítmények vagy bármely más Node.js-szerver közvetlenül hívhatja a könyvtárat:

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

Az smtp-server `session.envelope` objektuma már a Spam Scanner által olvasott `mailFrom` és `rcptTo` szerkezettel rendelkezik.
