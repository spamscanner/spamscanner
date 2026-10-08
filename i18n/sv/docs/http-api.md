<!-- source: faf44f093f8b -->

# HTTP-API, TCP-server och spamd


## HTTP-API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Det lyssnar på 127.0.0.1 om inte `--host` anger något annat. Med en token kräver varje förfrågan utom `/health` huvudet `Authorization: Bearer <token>`. Placera det bakom en omvänd proxy med TLS innan du gör det tillgängligt utanför datorn.

| Metod och sökväg   | Brödtext            | Svar                                                              |
| ------------------ | ------------------- | ----------------------------------------------------------------- |
| `GET /health`      |                     | `{"ok": true, "version": "7.0.0"}`                                |
| `POST /scan`       | Det råa meddelandet | [Skanningsresultatet](api.md#the-result) som JSON                 |
| `POST /check`      | Det råa meddelandet | Meddelandet med `X-Spam-*`-huvuden tillagda, som `message/rfc822` |
| `POST /learn/spam` | Det råa meddelandet | `{"ok": true, "learned": "spam"}`; kräver en token                |
| `POST /learn/ham`  | Det råa meddelandet | `{"ok": true, "learned": "ham"}`; kräver en token                 |

Frågeparametrar beskriver SMTP-sessionen:

| Parameter    | Betydelse                                                             |
| ------------ | --------------------------------------------------------------------- |
| `ip`         | Klientens IP-adress                                                   |
| `hostname`   | Dess verifierade namn i omvänd DNS                                    |
| `helo`       | Dess HELO- eller EHLO-namn                                            |
| `from`       | Kuvertets avsändare                                                   |
| `to`         | En mottagare; upprepa parametern eller separera flera med kommatecken |
| `verbose=1`  | `/scan`: returnera även ordlistan och ämnesraden                      |
| `subjectTag` | `/check`: prefix för ämnesraden på spam, till exempel `%5BSPAM%5D`    |

`/check` returnerar också `X-Spam-Flag`, `X-Spam-Score` och `X-Spam-Action` som svarshuvuden, så en klient kan avgöra utan att tolka meddelandet.

Meddelanden större än 25 MB får `413`. En skanning som misslyckas får `500` med `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Med `--out model.json` sparas det som `/learn` lär in till den filen efter varje förfrågan. Utan det varar inlärningen tills servern startas om.

Från Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Från Python:

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

Skicka det råa meddelandet, stäng anslutningens sändande sida och läs en rad JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Med `--verbose` är svaret i stället en textrad: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` eller `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

En SpamAssassin-kompatibel server för spamc, Exim, Haraka och andra SpamAssassin-klienter. [Konfigurera Exim och Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Kommando        | Svar                                                           |
| --------------- | -------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                      |
| `SYMBOLS`       | Utslaget och namnen på de tester som slog till                 |
| `REPORT`        | Utslaget och en tabell med tester, poäng och orsaker           |
| `REPORT_IFSPAM` | Som `REPORT`, med en tom rapport för ham                       |
| `PROCESS`       | Utslaget och meddelandet med `X-Spam-*`-huvuden                |
| `HEADERS`       | Utslaget och meddelandets huvudblock med `X-Spam-*`-huvuden    |
| `PING`          | `PONG`                                                         |
| `SKIP`          | Ingenting                                                      |
| `TELL`          | Lär in spam eller ham, med `--allow-tell`; sparar till `--out` |

Komprimerade förfrågningar (`Compress: zlib`) nekas.
