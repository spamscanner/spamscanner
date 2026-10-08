<!-- source: faf44f093f8b -->

# HTTP API, TCP-server en spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Hij luistert op 127.0.0.1, tenzij `--host` iets anders zegt. Met een token heeft elk verzoek behalve `/health` de header `Authorization: Bearer <token>` nodig. Zet hem achter een reverse proxy met TLS voordat je hem buiten de machine bereikbaar maakt.

| Methode en pad     | Body             | Antwoord                                                             |
| ------------------ | ---------------- | -------------------------------------------------------------------- |
| `GET /health`      |                  | `{"ok": true, "version": "7.0.0"}`                                   |
| `POST /scan`       | Het ruwe bericht | Het [scanresultaat](api.md#the-result) als JSON                      |
| `POST /check`      | Het ruwe bericht | Het bericht met toegevoegde `X-Spam-*`-headers, als `message/rfc822` |
| `POST /learn/spam` | Het ruwe bericht | `{"ok": true, "learned": "spam"}`; vereist een token                 |
| `POST /learn/ham`  | Het ruwe bericht | `{"ok": true, "learned": "ham"}`; vereist een token                  |

Queryparameters beschrijven de SMTP-sessie:

| Parameter    | Betekenis                                                                            |
| ------------ | ------------------------------------------------------------------------------------ |
| `ip`         | Het IP-adres van de client                                                           |
| `hostname`   | De geverifieerde reverse-DNS-naam                                                    |
| `helo`       | De HELO- of EHLO-naam                                                                |
| `from`       | De envelope-afzender                                                                 |
| `to`         | Een ontvanger; herhaal de parameter of scheid er meerdere met komma's                |
| `verbose=1`  | `/scan`: geef ook de woordenlijst en het onderwerp terug                             |
| `subjectTag` | `/check`: zet een voorvoegsel voor het onderwerp van spam, bijvoorbeeld `%5BSPAM%5D` |

`/check` geeft ook `X-Spam-Flag`, `X-Spam-Score` en `X-Spam-Action` terug als responseheaders, zodat een client kan beslissen zonder het bericht te parsen.

Berichten groter dan 25 MB krijgen `413`. Een scan die mislukt, krijgt `500` met `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Met `--out model.json` wordt wat `/learn` aanleert na elk verzoek in dat bestand opgeslagen. Zonder die optie blijft het geleerde bewaard tot de server herstart.

Vanuit Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Vanuit Python:

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


## TCP-server

```sh
spamscanner server --port 7830
```

Stuur het ruwe bericht, sluit de verzendkant van de verbinding en lees één regel JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Met `--verbose` is het antwoord in plaats daarvan een regel tekst: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` of `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Een met SpamAssassin compatibele server voor spamc, Exim, Haraka en andere SpamAssassin-clients. [Exim en Haraka instellen](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Opdracht        | Antwoord                                                             |
| --------------- | -------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                            |
| `SYMBOLS`       | Het oordeel en de namen van de tests die afgingen                    |
| `REPORT`        | Het oordeel en een tabel met tests, punten en redenen                |
| `REPORT_IFSPAM` | Zoals `REPORT`, met een leeg rapport voor ham                        |
| `PROCESS`       | Het oordeel en het bericht met `X-Spam-*`-headers                    |
| `HEADERS`       | Het oordeel en het headerblok van het bericht met `X-Spam-*`-headers |
| `PING`          | `PONG`                                                               |
| `SKIP`          | Niets                                                                |
| `TELL`          | Leert spam of ham, met `--allow-tell`; slaat op in `--out`           |

Gecomprimeerde verzoeken (`Compress: zlib`) worden geweigerd.
