<!-- source: 1151282f29d3 -->

# Další poštovní servery

Spam Scanner mluví čtyřmi protokoly, takže ho většina poštovního softwaru může používat bez vlastního pluginu:

| Protokol | Příkaz                                   | Používají                                               |
| -------- | ---------------------------------------- | ------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (s filter-milter)          |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka a cokoli napsaného pro SpamAssassin |
| HTTP     | `spamscanner http`                       | Skripty, webhooky, vlastní MTA a služby                 |
| Roura    | `spamscanner scan`, `spamscanner filter` | Roury v Postfixu, procmail, maildrop, úlohy cronu       |

[Postfix a Sendmail](postfix.md) mají vlastní stránku.


## Náhrada za spamd ze SpamAssassinu

`spamscanner spamd` odpovídá na protokol spamd ze SpamAssassinu: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` a s `--allow-tell` také `TELL`. Software napsaný pro SpamAssassin funguje beze změn; zastavte `spamd` a spusťte Spam Scanner na stejném portu.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Se spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Testy end-to-end v repozitáři proti němu spouštějí spamc přímo ze SpamAssassinu.


## Exim

Podmínka ACL `spam` v Eximu komunikuje se spamd. V hlavní konfiguraci:

```text
spamd_address = 127.0.0.1 783
```

V ACL pro DATA (`acl_check_data` v exim4 z Debianu):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` odpovídá dočasnou chybou 4xx, takže odesílatelé to zkusí znovu a chybu lze opravit. Až budou výsledky vypadat správně, změňte ho na `deny` pro trvalé odmítnutí.


## Haraka

Plugin `spamassassin` v Haraka komunikuje se spamd. Zapněte ho v `config/plugins` a v `config/spamassassin.ini` nastavte:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: složka Junk a učení

Pravidlo Sieve přesune označenou poštu do Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

S IMAPSieve může přesun zprávy do Junk nebo z ní model učit. Spusťte HTTP API s tokenem a souborem modelu:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

a nasměrujte milter nebo server spamd na stejný model pomocí `--model /var/lib/spamscanner/model.json` (nebo `SPAMSCANNER_MODEL`). Čas od času ho restartujte, aby načetl, co se naučil. Skript spouštěný přes `sieve_pipe` zprávu odešle:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

[Návod k hlášení spamu](https://doc.dovecot.org/main/core/config/spam_reporting.html) od Dovecotu ukazuje zbytek nastavení, který je stejný pro jakýkoli spamový filtr, jenž se učí ze skriptu.


## procmail a maildrop

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

`scan --headers` u spamu končí s kódem 1. procmail a maildrop s výše uvedenými pravidly používají výstup, ne návratový kód.


## HTTP API

Poštu může kontrolovat jakýkoli program, který umí poslat požadavek HTTP:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API](http-api.md) uvádí všechny koncové body.


## Uvnitř poštovního serveru v Node.js

Se [smtp-server](https://nodemailer.com/extras/smtp-server/), pluginy Haraky nebo jakýmkoli jiným serverem v Node.js volejte knihovnu přímo:

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

`session.envelope` ze smtp-server už má tvar `mailFrom` a `rcptTo`, který Spam Scanner čte.
