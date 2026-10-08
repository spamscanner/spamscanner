<!-- source: 1151282f29d3 -->

# Autres serveurs de messagerie

Spam Scanner parle quatre protocoles : la plupart des logiciels de messagerie peuvent donc l’utiliser sans plugin dédié.

| Protocole | Commande                                 | Utilisé par                                                       |
| --------- | ---------------------------------------- | ----------------------------------------------------------------- |
| Milter    | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (avec filter-milter)                 |
| spamd     | `spamscanner spamd`                      | spamc, Exim, Haraka, et tout ce qui a été écrit pour SpamAssassin |
| HTTP      | `spamscanner http`                       | Scripts, webhooks, MTA et services sur mesure                     |
| Pipe      | `spamscanner scan`, `spamscanner filter` | Pipes Postfix, procmail, maildrop, tâches cron                    |

[Postfix et Sendmail](postfix.md) ont leur propre page.


## Un remplaçant direct du spamd de SpamAssassin

`spamscanner spamd` répond au protocole spamd de SpamAssassin : `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` et, avec `--allow-tell`, `TELL`. Les logiciels écrits pour SpamAssassin fonctionnent sans modification ; arrêtez `spamd` et lancez Spam Scanner sur le même port.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Avec spamc :

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Les tests de bout en bout du dépôt utilisent le propre spamc de SpamAssassin contre lui.


## Exim

La condition ACL `spam` d’Exim communique avec spamd. Dans la configuration principale :

```text
spamd_address = 127.0.0.1 783
```

Dans l’ACL DATA (`acl_check_data` dans l’exim4 de Debian) :

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` répond par une erreur temporaire 4xx : les expéditeurs réessaient et une erreur peut être corrigée. Remplacez-le par `deny` pour un refus définitif une fois que les résultats semblent corrects.


## Haraka

Le plugin `spamassassin` de Haraka communique avec spamd. Activez-le dans `config/plugins` et définissez, dans `config/spamassassin.ini` :

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot : dossier Junk et apprentissage

Une règle Sieve range le courrier marqué dans Junk :

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Avec IMAPSieve, déplacer un message vers Junk ou hors de Junk peut entraîner le modèle. Lancez l’API HTTP avec un jeton et un fichier de modèle :

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

et faites pointer le milter ou le serveur spamd vers le même modèle avec `--model /var/lib/spamscanner/model.json` (ou `SPAMSCANNER_MODEL`). Redémarrez-le de temps en temps pour prendre en compte ce qui a été appris. Un script lancé par `sieve_pipe` envoie le message :

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Le [guide de signalement du spam](https://doc.dovecot.org/main/core/config/spam_reporting.html) de Dovecot décrit le reste de la configuration, qui est la même pour tout filtre antispam qui apprend à partir d’un script.


## procmail et maildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop :

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

`scan --headers` sort avec le code 1 pour le spam. Avec les règles ci-dessus, procmail et maildrop utilisent la sortie, pas le code de sortie.


## API HTTP

Tout programme capable d’envoyer une requête HTTP peut analyser du courrier :

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[L’API HTTP](http-api.md) liste tous les points d’accès.


## Dans un serveur de messagerie Node.js

Avec [smtp-server](https://nodemailer.com/extras/smtp-server/), les plugins Haraka ou tout autre serveur Node.js, appelez directement la bibliothèque :

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

Le `session.envelope` de smtp-server a déjà la forme `mailFrom` et `rcptTo` que lit Spam Scanner.
