<!-- source: 1151282f29d3 -->

# Otros servidores de correo

Spam Scanner habla cuatro protocolos, así que la mayoría del software de correo puede usarlo sin un complemento propio:

| Protocolo | Comando                                  | Lo usan                                                            |
| --------- | ---------------------------------------- | ------------------------------------------------------------------ |
| Milter    | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (con filter-milter)                   |
| spamd     | `spamscanner spamd`                      | spamc, Exim, Haraka y cualquier software escrito para SpamAssassin |
| HTTP      | `spamscanner http`                       | Scripts, webhooks, MTA y servicios propios                         |
| Tubería   | `spamscanner scan`, `spamscanner filter` | Tuberías de Postfix, procmail, maildrop, tareas de cron            |

[Postfix y Sendmail](postfix.md) tienen su propia página.


## Un sustituto directo del spamd de SpamAssassin

`spamscanner spamd` responde al protocolo spamd de SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` y, con `--allow-tell`, `TELL`. El software escrito para SpamAssassin funciona sin cambios; detén `spamd` e inicia Spam Scanner en el mismo puerto.

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

Las pruebas de extremo a extremo del repositorio ejecutan contra él el propio spamc de SpamAssassin.


## Exim

La condición de ACL `spam` de Exim se comunica con spamd. En la configuración principal:

```text
spamd_address = 127.0.0.1 783
```

En la ACL de DATA (`acl_check_data` en el exim4 de Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` responde con un error temporal 4xx, así que los remitentes vuelven a intentarlo y un error se puede corregir. Cámbialo a `deny` para un rechazo permanente cuando los resultados parezcan correctos.


## Haraka

El complemento `spamassassin` de Haraka se comunica con spamd. Actívalo en `config/plugins` y define, en `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: carpeta Junk y aprendizaje

Una regla de Sieve archiva en Junk el correo marcado:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Con IMAPSieve, mover un mensaje a Junk o sacarlo de ahí puede enseñar al modelo. Inicia la API HTTP con un token y un archivo de modelo:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

y haz que el milter o el servidor spamd usen el mismo modelo con `--model /var/lib/spamscanner/model.json` (o `SPAMSCANNER_MODEL`). Reinícialo de vez en cuando para que recoja lo aprendido. Un script que ejecuta `sieve_pipe` envía el mensaje:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

La [guía de denuncia de spam](https://doc.dovecot.org/main/core/config/spam_reporting.html) de Dovecot muestra el resto de la configuración, que es la misma para cualquier filtro de spam que aprenda a partir de un script.


## procmail y maildrop

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

`scan --headers` termina con 1 para el spam. Con las reglas anteriores, procmail y maildrop usan la salida, no el código de salida.


## API HTTP

Cualquier programa que pueda hacer una petición HTTP puede analizar correo:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[La API HTTP](http-api.md) enumera todos los endpoints.


## Dentro de un servidor de correo en Node.js

Con [smtp-server](https://nodemailer.com/extras/smtp-server/), complementos de Haraka o cualquier otro servidor en Node.js, llama directamente a la biblioteca:

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

El `session.envelope` de smtp-server ya tiene la forma `mailFrom` y `rcptTo` que lee Spam Scanner.
