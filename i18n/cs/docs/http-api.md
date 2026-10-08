<!-- source: faf44f093f8b -->

# HTTP API, TCP server a spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Naslouchá na 127.0.0.1, pokud `--host` neurčí jinak. S tokenem vyžaduje každý požadavek kromě `/health` hlavičku `Authorization: Bearer <token>`. Než ho zpřístupníte mimo počítač, postavte ho za reverzní proxy s TLS.

| Metoda a cesta     | Tělo          | Odpověď                                                        |
| ------------------ | ------------- | -------------------------------------------------------------- |
| `GET /health`      |               | `{"ok": true, "version": "7.0.0"}`                             |
| `POST /scan`       | Surová zpráva | [Výsledek kontroly](api.md#the-result) jako JSON               |
| `POST /check`      | Surová zpráva | Zpráva s přidanými hlavičkami `X-Spam-*` jako `message/rfc822` |
| `POST /learn/spam` | Surová zpráva | `{"ok": true, "learned": "spam"}`; vyžaduje token              |
| `POST /learn/ham`  | Surová zpráva | `{"ok": true, "learned": "ham"}`; vyžaduje token               |

Parametry dotazu popisují relaci SMTP:

| Parametr     | Význam                                                             |
| ------------ | ------------------------------------------------------------------ |
| `ip`         | IP adresa klienta                                                  |
| `hostname`   | Jeho ověřené reverzní jméno DNS                                    |
| `helo`       | Jeho jméno z HELO nebo EHLO                                        |
| `from`       | Odesílatel v obálce                                                |
| `to`         | Příjemce; parametr opakujte, nebo více příjemců oddělte čárkami    |
| `verbose=1`  | `/scan`: vrátit také seznam slov a předmět                         |
| `subjectTag` | `/check`: přidat předponu k předmětu spamu, například `%5BSPAM%5D` |

`/check` vrací také `X-Spam-Flag`, `X-Spam-Score` a `X-Spam-Action` jako hlavičky odpovědi, takže klient se může rozhodnout bez rozebírání zprávy.

Zprávy větší než 25 MB dostanou `413`. Kontrola, která selže, dostane `500` s `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

S `--out model.json` se to, co `/learn` naučí, po každém požadavku uloží do tohoto souboru. Bez této volby naučené vydrží jen do restartu serveru.

Z Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Z Pythonu:

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


## TCP server

```sh
spamscanner server --port 7830
```

Pošlete surovou zprávu, zavřete odesílací stranu spojení a přečtěte jeden řádek JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

S `--verbose` je odpovědí místo toho řádek textu: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` nebo `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Server kompatibilní se SpamAssassinem pro spamc, Exim, Haraka a další klienty SpamAssassinu. [Nastavení Eximu a Haraky](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Příkaz          | Odpověď                                                    |
| --------------- | ---------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                  |
| `SYMBOLS`       | Verdikt a názvy testů, které se spustily                   |
| `REPORT`        | Verdikt a tabulka testů, bodů a důvodů                     |
| `REPORT_IFSPAM` | Jako `REPORT`, s prázdnou zprávou pro ham                  |
| `PROCESS`       | Verdikt a zpráva s hlavičkami `X-Spam-*`                   |
| `HEADERS`       | Verdikt a blok hlaviček zprávy s hlavičkami `X-Spam-*`     |
| `PING`          | `PONG`                                                     |
| `SKIP`          | Nic                                                        |
| `TELL`          | S `--allow-tell` se naučí spam nebo ham; ukládá do `--out` |

Komprimované požadavky (`Compress: zlib`) se odmítají.
