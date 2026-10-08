<!-- source: 1151282f29d3 -->

# Outros servidores de e-mail

O Spam Scanner fala quatro protocolos, então a maioria dos softwares de e-mail consegue usá-lo sem um plugin próprio:

| Protocolo | Comando                                  | Usado por                                                        |
| --------- | ---------------------------------------- | ---------------------------------------------------------------- |
| Milter    | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (com filter-milter)                 |
| spamd     | `spamscanner spamd`                      | spamc, Exim, Haraka e qualquer coisa escrita para o SpamAssassin |
| HTTP      | `spamscanner http`                       | Scripts, webhooks, MTAs e serviços próprios                      |
| Pipe      | `spamscanner scan`, `spamscanner filter` | Pipes do Postfix, procmail, maildrop, tarefas do cron            |

[Postfix e Sendmail](postfix.md) têm uma página própria.


## Um substituto direto para o spamd do SpamAssassin

O `spamscanner spamd` responde ao protocolo spamd do SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` e, com `--allow-tell`, `TELL`. Os softwares escritos para o SpamAssassin funcionam sem mudanças; pare o `spamd` e inicie o Spam Scanner na mesma porta.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Com o spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Os testes de ponta a ponta do repositório executam o próprio spamc do SpamAssassin contra ele.


## Exim

A condição de ACL `spam` do Exim conversa com o spamd. Na configuração principal:

```text
spamd_address = 127.0.0.1 783
```

Na ACL de DATA (`acl_check_data` no exim4 do Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

O `defer` responde com um erro 4xx temporário, então os remetentes tentam de novo e um erro pode ser corrigido. Troque-o por `deny` para uma recusa permanente quando os resultados parecerem corretos.


## Haraka

O plugin `spamassassin` do Haraka conversa com o spamd. Ative-o em `config/plugins` e defina, em `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: pasta Junk e aprendizado

Uma regra Sieve arquiva os e-mails marcados na pasta Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Com o IMAPSieve, mover uma mensagem para dentro ou para fora da pasta Junk pode ensinar o modelo. Inicie a API HTTP com um token e um arquivo de modelo:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

e aponte o milter ou o servidor spamd para o mesmo modelo com `--model /var/lib/spamscanner/model.json` (ou `SPAMSCANNER_MODEL`). Reinicie-o de tempos em tempos para carregar o que foi aprendido. Um script executado pelo `sieve_pipe` envia a mensagem:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

O [guia de relato de spam](https://doc.dovecot.org/main/core/config/spam_reporting.html) do Dovecot mostra o resto da configuração, que é a mesma para qualquer filtro de spam que aprende a partir de um script.


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

O `scan --headers` sai com 1 para spam. Com as regras acima, o procmail e o maildrop usam a saída, e não o código de saída.


## API HTTP

Qualquer programa que consiga fazer uma requisição HTTP pode analisar e-mails:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[A API HTTP](http-api.md) lista todos os endpoints.


## Dentro de um servidor de e-mail em Node.js

Com o [smtp-server](https://nodemailer.com/extras/smtp-server/), plugins do Haraka ou qualquer outro servidor Node.js, chame a biblioteca diretamente:

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

O `session.envelope` do smtp-server já tem o formato `mailFrom` e `rcptTo` que o Spam Scanner lê.
