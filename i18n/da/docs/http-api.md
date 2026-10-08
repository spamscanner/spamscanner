<!-- source: faf44f093f8b -->

# HTTP API, TCP-server og spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Den lytter på 127.0.0.1, medmindre `--host` siger noget andet. Med et token kræver alle forespørgsler undtagen `/health` headeren `Authorization: Bearer <token>`. Sæt den bag en reverse proxy med TLS, før den gøres tilgængelig uden for maskinen.

| Metode og sti      | Brødtekst     | Svar                                                           |
| ------------------ | ------------- | -------------------------------------------------------------- |
| `GET /health`      |               | `{"ok": true, "version": "7.0.0"}`                             |
| `POST /scan`       | Den rå besked | [Scanningsresultatet](api.md#the-result) som JSON              |
| `POST /check`      | Den rå besked | Beskeden med `X-Spam-*`-headere tilføjet, som `message/rfc822` |
| `POST /learn/spam` | Den rå besked | `{"ok": true, "learned": "spam"}`; kræver et token             |
| `POST /learn/ham`  | Den rå besked | `{"ok": true, "learned": "ham"}`; kræver et token              |

Forespørgselsparametre beskriver SMTP-sessionen:

| Parameter    | Betydning                                                               |
| ------------ | ----------------------------------------------------------------------- |
| `ip`         | Klientens IP-adresse                                                    |
| `hostname`   | Dens verificerede reverse DNS-navn                                      |
| `helo`       | Dens HELO- eller EHLO-navn                                              |
| `from`       | Afsenderen i konvolutten                                                |
| `to`         | En modtager; gentag den, eller adskil flere med kommaer                 |
| `verbose=1`  | `/scan`: returnér også ordlisten og emnet                               |
| `subjectTag` | `/check`: sæt et præfiks foran emnet på spam, for eksempel `%5BSPAM%5D` |

`/check` returnerer også `X-Spam-Flag`, `X-Spam-Score` og `X-Spam-Action` som svarheadere, så en klient kan træffe en afgørelse uden at fortolke beskeden.

Beskeder større end 25 MB får `413`. En scanning, der fejler, får `500` med `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Med `--out model.json` gemmes det, `/learn` lærer, i den fil efter hver forespørgsel. Uden den varer indlæringen, indtil serveren genstartes.

Fra Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Fra Python:

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

Send den rå besked, luk forbindelsens afsenderside, og læs én linje JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Med `--verbose` er svaret i stedet en tekstlinje: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` eller `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

En SpamAssassin-kompatibel server til spamc, Exim, Haraka og andre SpamAssassin-klienter. [Opsætning af Exim og Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Kommando        | Svar                                                       |
| --------------- | ---------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                  |
| `SYMBOLS`       | Dommen og navnene på de test, der slog til                 |
| `REPORT`        | Dommen og en tabel over test, point og begrundelser        |
| `REPORT_IFSPAM` | Som `REPORT`, med en tom rapport for ham                   |
| `PROCESS`       | Dommen og beskeden med `X-Spam-*`-headere                  |
| `HEADERS`       | Dommen og beskedens headerblok med `X-Spam-*`-headere      |
| `PING`          | `PONG`                                                     |
| `SKIP`          | Intet                                                      |
| `TELL`          | Lærer spam eller ham, med `--allow-tell`; gemmer i `--out` |

Komprimerede forespørgsler (`Compress: zlib`) afvises.
