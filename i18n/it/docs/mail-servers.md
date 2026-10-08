<!-- source: 1151282f29d3 -->

# Altri server di posta

Spam Scanner parla quattro protocolli, quindi la maggior parte dei software di posta può usarlo senza un plugin dedicato:

| Protocollo | Comando                                  | Usato da                                                          |
| ---------- | ---------------------------------------- | ----------------------------------------------------------------- |
| Milter     | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (con filter-milter)                  |
| spamd      | `spamscanner spamd`                      | spamc, Exim, Haraka e qualsiasi software scritto per SpamAssassin |
| HTTP       | `spamscanner http`                       | Script, webhook, MTA e servizi personalizzati                     |
| Pipe       | `spamscanner scan`, `spamscanner filter` | Pipe di Postfix, procmail, maildrop, job di cron                  |

[Postfix e Sendmail](postfix.md) hanno una pagina dedicata.


## Un sostituto diretto dello spamd di SpamAssassin

`spamscanner spamd` risponde al protocollo spamd di SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` e, con `--allow-tell`, `TELL`. Il software scritto per SpamAssassin funziona senza modifiche; ferma `spamd` e avvia Spam Scanner sulla stessa porta.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Con spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

I test end-to-end del repository lo verificano con lo spamc di SpamAssassin.


## Exim

La condizione ACL `spam` di Exim comunica con spamd. Nella configurazione principale:

```text
spamd_address = 127.0.0.1 783
```

Nella ACL DATA (`acl_check_data` nell'exim4 di Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` risponde con un errore temporaneo 4xx, quindi i mittenti riprovano e un errore si può correggere. Sostituiscilo con `deny` per un rifiuto permanente quando i risultati sembrano corretti.


## Haraka

Il plugin `spamassassin` di Haraka comunica con spamd. Attivalo in `config/plugins` e imposta, in `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: cartella Junk e apprendimento

Una regola Sieve archivia la posta marcata in Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Con IMAPSieve, spostare un messaggio dentro o fuori da Junk può istruire il modello. Avvia l'API HTTP con un token e un file di modello:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

e fai puntare il milter o il server spamd allo stesso modello con `--model /var/lib/spamscanner/model.json` (o `SPAMSCANNER_MODEL`). Riavvialo di tanto in tanto perché carichi ciò che è stato appreso. Uno script eseguito da `sieve_pipe` invia il messaggio:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

La [guida alla segnalazione dello spam](https://doc.dovecot.org/main/core/config/spam_reporting.html) di Dovecot mostra il resto della configurazione, che è la stessa per qualsiasi filtro antispam che impara da uno script.


## procmail e maildrop

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

`scan --headers` esce con 1 per lo spam. Con le regole sopra, procmail e maildrop usano l'output, non il codice di uscita.


## API HTTP

Qualsiasi programma in grado di effettuare una richiesta HTTP può analizzare la posta:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[L'API HTTP](http-api.md) elenca ogni endpoint.


## All'interno di un server di posta Node.js

Con [smtp-server](https://nodemailer.com/extras/smtp-server/), i plugin di Haraka o qualsiasi altro server Node.js, chiama direttamente la libreria:

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

Il `session.envelope` di smtp-server ha già la struttura `mailFrom` e `rcptTo` che Spam Scanner legge.
