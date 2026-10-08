<!-- source: faf44f093f8b -->

# HTTP-API, TCP-Server und spamd


## HTTP-API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Der Server lauscht auf 127.0.0.1, sofern `--host` nichts anderes angibt. Mit einem Token braucht jede Anfrage außer `/health` den Header `Authorization: Bearer <token>`. Stellen Sie ihn hinter einen Reverse Proxy mit TLS, bevor er außerhalb des Rechners erreichbar wird.

| Methode und Pfad   | Body               | Antwort                                                                  |
| ------------------ | ------------------ | ------------------------------------------------------------------------ |
| `GET /health`      |                    | `{"ok": true, "version": "7.0.0"}`                                       |
| `POST /scan`       | Die rohe Nachricht | Das [Scan-Ergebnis](api.md#the-result) als JSON                          |
| `POST /check`      | Die rohe Nachricht | Die Nachricht mit hinzugefügten `X-Spam-*`-Headern, als `message/rfc822` |
| `POST /learn/spam` | Die rohe Nachricht | `{"ok": true, "learned": "spam"}`; benötigt ein Token                    |
| `POST /learn/ham`  | Die rohe Nachricht | `{"ok": true, "learned": "ham"}`; benötigt ein Token                     |

Query-Parameter beschreiben die SMTP-Sitzung:

| Parameter    | Bedeutung                                                                         |
| ------------ | --------------------------------------------------------------------------------- |
| `ip`         | Die IP-Adresse des Clients                                                        |
| `hostname`   | Sein verifizierter Reverse-DNS-Name                                               |
| `helo`       | Sein Name bei HELO oder EHLO                                                      |
| `from`       | Der Absender im Umschlag                                                          |
| `to`         | Ein Empfänger; wiederholen oder mehrere durch Kommas trennen                      |
| `verbose=1`  | `/scan`: zusätzlich die Wortliste und den Betreff zurückgeben                     |
| `subjectTag` | `/check`: dem Betreff von Spam ein Präfix voranstellen, zum Beispiel `%5BSPAM%5D` |

`/check` gibt außerdem `X-Spam-Flag`, `X-Spam-Score` und `X-Spam-Action` als Response-Header zurück, sodass ein Client entscheiden kann, ohne die Nachricht zu parsen.

Nachrichten über 25 MB erhalten `413`. Ein fehlgeschlagener Scan erhält `500` mit `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Mit `--out model.json` wird das, was `/learn` beibringt, nach jeder Anfrage in dieser Datei gespeichert. Ohne diese Option gilt das Gelernte nur bis zum Neustart des Servers.

Aus Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Aus Python:

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


## TCP-Server

```sh
spamscanner server --port 7830
```

Senden Sie die rohe Nachricht, schließen Sie die Senderichtung der Verbindung und lesen Sie eine Zeile JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Mit `--verbose` ist die Antwort stattdessen eine Textzeile: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` oder `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Ein SpamAssassin-kompatibler Server für spamc, Exim, Haraka und andere SpamAssassin-Clients. [Exim und Haraka einrichten](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Befehl          | Antwort                                                              |
| --------------- | -------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                            |
| `SYMBOLS`       | Das Urteil und die Namen der ausgelösten Tests                       |
| `REPORT`        | Das Urteil und eine Tabelle mit Tests, Punkten und Begründungen      |
| `REPORT_IFSPAM` | Wie `REPORT`, mit leerem Bericht bei Ham                             |
| `PROCESS`       | Das Urteil und die Nachricht mit `X-Spam-*`-Headern                  |
| `HEADERS`       | Das Urteil und der Header-Block der Nachricht mit `X-Spam-*`-Headern |
| `PING`          | `PONG`                                                               |
| `SKIP`          | Nichts                                                               |
| `TELL`          | Lernt Spam oder Ham, mit `--allow-tell`; speichert in `--out`        |

Komprimierte Anfragen (`Compress: zlib`) werden abgelehnt.
