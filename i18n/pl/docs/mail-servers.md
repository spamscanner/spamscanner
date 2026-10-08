<!-- source: 1151282f29d3 -->

# Inne serwery pocztowe

Spam Scanner obsługuje cztery protokoły, więc większość oprogramowania pocztowego może z niego korzystać bez osobnej wtyczki:

| Protokół | Polecenie                                | Używany przez                                                |
| -------- | ---------------------------------------- | ------------------------------------------------------------ |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (z filter-milter)               |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka i wszystko, co napisano dla SpamAssassin |
| HTTP     | `spamscanner http`                       | Skrypty, webhooki, własne MTA i usługi                       |
| Potok    | `spamscanner scan`, `spamscanner filter` | Potoki Postfix, procmail, maildrop, zadania cron             |

[Postfix i Sendmail](postfix.md) mają osobną stronę.


## Zamiennik dla spamd ze SpamAssassin

`spamscanner spamd` odpowiada w protokole spamd ze SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` oraz, z `--allow-tell`, `TELL`. Oprogramowanie napisane dla SpamAssassin działa bez zmian; zatrzymaj `spamd` i uruchom Spam Scanner na tym samym porcie.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Ze spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Testy end-to-end w repozytorium uruchamiają na nim oryginalny spamc ze SpamAssassin.


## Exim

Warunek ACL `spam` w Exim komunikuje się ze spamd. W głównej konfiguracji:

```text
spamd_address = 127.0.0.1 783
```

W ACL dla DATA (`acl_check_data` w exim4 z Debiana):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` odpowiada tymczasowym błędem 4xx, więc nadawcy ponawiają próbę, a pomyłkę można naprawić. Gdy wyniki będą wyglądać poprawnie, zmień to na `deny`, aby odrzucać na stałe.


## Haraka

Wtyczka `spamassassin` w Haraka komunikuje się ze spamd. Włącz ją w `config/plugins` i ustaw w `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: folder Junk i nauka

Reguła Sieve przenosi oznaczoną pocztę do Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Z IMAPSieve przeniesienie wiadomości do Junk lub z Junk może uczyć model. Uruchom HTTP API z tokenem i plikiem modelu:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

i wskaż milterowi lub serwerowi spamd ten sam model przez `--model /var/lib/spamscanner/model.json` (lub `SPAMSCANNER_MODEL`). Co jakiś czas go restartuj, aby wczytał to, czego się nauczył. Skrypt uruchamiany przez `sieve_pipe` wysyła wiadomość:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

[Poradnik zgłaszania spamu](https://doc.dovecot.org/main/core/config/spam_reporting.html) w dokumentacji Dovecot pokazuje resztę konfiguracji, która jest taka sama dla każdego filtra antyspamowego uczącego się przez skrypt.


## procmail i maildrop

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

`scan --headers` kończy z kodem 1 dla spamu. Przy powyższych regułach procmail i maildrop korzystają z wyjścia, a nie z kodu wyjścia.


## HTTP API

Każdy program, który potrafi wysłać żądanie HTTP, może skanować pocztę:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API](http-api.md) wymienia wszystkie punkty końcowe.


## W serwerze pocztowym Node.js

Z [smtp-server](https://nodemailer.com/extras/smtp-server/), wtyczkami Haraka lub dowolnym innym serwerem Node.js wywołuj bibliotekę bezpośrednio:

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

`session.envelope` z smtp-server ma już kształt `mailFrom` i `rcptTo`, który czyta Spam Scanner.
