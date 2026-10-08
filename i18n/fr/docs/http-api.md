<!-- source: faf44f093f8b -->

# API HTTP, serveur TCP et spamd


## API HTTP

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Elle écoute sur 127.0.0.1, sauf indication contraire de `--host`. Avec un jeton, chaque requête sauf `/health` nécessite `Authorization: Bearer <token>`. Placez-la derrière un proxy inverse avec TLS avant de l’exposer au-delà de la machine.

| Méthode et chemin  | Corps           | Réponse                                                              |
| ------------------ | --------------- | -------------------------------------------------------------------- |
| `GET /health`      |                 | `{"ok": true, "version": "7.0.0"}`                                   |
| `POST /scan`       | Le message brut | Le [résultat de l’analyse](api.md#the-result) en JSON                |
| `POST /check`      | Le message brut | Le message avec les en-têtes `X-Spam-*` ajoutés, en `message/rfc822` |
| `POST /learn/spam` | Le message brut | `{"ok": true, "learned": "spam"}` ; nécessite un jeton               |
| `POST /learn/ham`  | Le message brut | `{"ok": true, "learned": "ham"}` ; nécessite un jeton                |

Les paramètres de requête décrivent la session SMTP :

| Paramètre    | Signification                                                                   |
| ------------ | ------------------------------------------------------------------------------- |
| `ip`         | L’adresse IP du client                                                          |
| `hostname`   | Son nom DNS inverse vérifié                                                     |
| `helo`       | Son nom HELO ou EHLO                                                            |
| `from`       | L’expéditeur de l’enveloppe                                                     |
| `to`         | Un destinataire ; répétez le paramètre ou séparez-en plusieurs par des virgules |
| `verbose=1`  | `/scan` : renvoie aussi la liste des mots et l’objet                            |
| `subjectTag` | `/check` : ajoute un préfixe à l’objet du spam, par exemple `%5BSPAM%5D`        |

`/check` renvoie aussi `X-Spam-Flag`, `X-Spam-Score` et `X-Spam-Action` comme en-têtes de réponse : un client peut ainsi décider sans analyser le message.

Les messages de plus de 25 Mo obtiennent `413`. Une analyse qui échoue obtient `500` avec `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Avec `--out model.json`, ce que `/learn` enseigne est enregistré dans ce fichier après chaque requête. Sans cette option, l’apprentissage dure jusqu’au redémarrage du serveur.

Depuis Node.js :

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Depuis Python :

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## Serveur TCP

```sh
spamscanner server --port 7830
```

Envoyez le message brut, fermez le côté émission de la connexion, et lisez une ligne de JSON :

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Avec `--verbose`, la réponse est plutôt une ligne de texte : `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` ou `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Un serveur compatible avec SpamAssassin pour spamc, Exim, Haraka et les autres clients SpamAssassin. [Configurer Exim et Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Commande        | Réponse                                                                  |
| --------------- | ------------------------------------------------------------------------ |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                                |
| `SYMBOLS`       | Le verdict et les noms des tests déclenchés                              |
| `REPORT`        | Le verdict et un tableau des tests, des points et des raisons            |
| `REPORT_IFSPAM` | Comme `REPORT`, avec un rapport vide pour le ham                         |
| `PROCESS`       | Le verdict et le message avec les en-têtes `X-Spam-*`                    |
| `HEADERS`       | Le verdict et le bloc d’en-têtes du message avec les en-têtes `X-Spam-*` |
| `PING`          | `PONG`                                                                   |
| `SKIP`          | Rien                                                                     |
| `TELL`          | Apprend du spam ou du ham, avec `--allow-tell` ; enregistre dans `--out` |

Les requêtes compressées (`Compress: zlib`) sont refusées.
