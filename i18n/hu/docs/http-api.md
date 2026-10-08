<!-- source: faf44f093f8b -->

# HTTP API, TCP-szerver és spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

A 127.0.0.1 címen figyel, hacsak a `--host` mást nem ad meg. Token esetén a `/health` kivételével minden kéréshez `Authorization: Bearer <token>` szükséges. Mielőtt a gépen kívülről is elérhetővé válna, TLS-t használó fordított proxy mögé kell helyezni.

| Metódus és útvonal | Törzs         | Válasz                                                                  |
| ------------------ | ------------- | ----------------------------------------------------------------------- |
| `GET /health`      |               | `{"ok": true, "version": "7.0.0"}`                                      |
| `POST /scan`       | A nyers levél | A [vizsgálat eredménye](api.md#the-result) JSON-ként                    |
| `POST /check`      | A nyers levél | A levél a hozzáadott `X-Spam-*` fejlécekkel, `message/rfc822` típusként |
| `POST /learn/spam` | A nyers levél | `{"ok": true, "learned": "spam"}`; tokent igényel                       |
| `POST /learn/ham`  | A nyers levél | `{"ok": true, "learned": "ham"}`; tokent igényel                        |

A lekérdezési paraméterek az SMTP-munkamenetet írják le:

| Paraméter    | Jelentés                                                               |
| ------------ | ---------------------------------------------------------------------- |
| `ip`         | A kliens IP-címe                                                       |
| `hostname`   | Az ellenőrzött fordított DNS-neve                                      |
| `helo`       | A HELO vagy EHLO neve                                                  |
| `from`       | A boríték szerinti feladó                                              |
| `to`         | Egy címzett; ismételhető, vagy több is megadható vesszővel elválasztva |
| `verbose=1`  | `/scan`: a szólistát és a tárgyat is visszaadja                        |
| `subjectTag` | `/check`: előtag a spam tárgyához, például `%5BSPAM%5D`                |

A `/check` válaszfejlécként az `X-Spam-Flag`, az `X-Spam-Score` és az `X-Spam-Action` értékét is visszaadja, így a kliens a levél feldolgozása nélkül is dönthet.

A 25 MB-nál nagyobb levelek `413` választ kapnak. A sikertelen vizsgálat `500` választ kap `{"error": "..."}` törzzsel.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

A `--out model.json` kapcsolóval a `/learn` által tanítottak minden kérés után ebbe a fájlba kerülnek. Nélküle a tanultak a szerver újraindításáig maradnak meg.

Node.js-ből:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Pythonból:

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


## TCP-szerver

```sh
spamscanner server --port 7830
```

Küldje el a nyers levelet, zárja le a kapcsolat küldő oldalát, és olvasson be egy sor JSON-t:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

A `--verbose` kapcsolóval a válasz ehelyett egy szövegsor: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` vagy `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

SpamAssassin-kompatibilis szerver a spamc, az Exim, a Haraka és más SpamAssassin-kliensek számára. [Az Exim és a Haraka beállítása](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Parancs         | Válasz                                                                      |
| --------------- | --------------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                                   |
| `SYMBOLS`       | Az ítélet és a teljesült tesztek nevei                                      |
| `REPORT`        | Az ítélet és a tesztek, pontok és okok táblázata                            |
| `REPORT_IFSPAM` | Mint a `REPORT`, de ham esetén üres jelentéssel                             |
| `PROCESS`       | Az ítélet és a levél az `X-Spam-*` fejlécekkel                              |
| `HEADERS`       | Az ítélet és a levél fejlécblokkja az `X-Spam-*` fejlécekkel                |
| `PING`          | `PONG`                                                                      |
| `SKIP`          | Semmi                                                                       |
| `TELL`          | Spamet vagy hamet tanul a `--allow-tell` kapcsolóval; a `--out` fájlba ment |

A tömörített kéréseket (`Compress: zlib`) visszautasítja.
