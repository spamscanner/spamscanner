<!-- source: faf44f093f8b -->

# HTTP API, serwer TCP i spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Nasłuchuje na 127.0.0.1, chyba że `--host` wskazuje inaczej. Z tokenem każde żądanie z wyjątkiem `/health` wymaga `Authorization: Bearer <token>`. Zanim udostępnisz go poza komputer, umieść go za reverse proxy z TLS.

| Metoda i ścieżka   | Treść żądania    | Odpowiedź                                                         |
| ------------------ | ---------------- | ----------------------------------------------------------------- |
| `GET /health`      |                  | `{"ok": true, "version": "7.0.0"}`                                |
| `POST /scan`       | Surowa wiadomość | [Wynik skanowania](api.md#the-result) jako JSON                   |
| `POST /check`      | Surowa wiadomość | Wiadomość z dodanymi nagłówkami `X-Spam-*`, jako `message/rfc822` |
| `POST /learn/spam` | Surowa wiadomość | `{"ok": true, "learned": "spam"}`; wymaga tokenu                  |
| `POST /learn/ham`  | Surowa wiadomość | `{"ok": true, "learned": "ham"}`; wymaga tokenu                   |

Parametry zapytania opisują sesję SMTP:

| Parametr     | Znaczenie                                                            |
| ------------ | -------------------------------------------------------------------- |
| `ip`         | Adres IP klienta                                                     |
| `hostname`   | Jego zweryfikowana odwrotna nazwa DNS                                |
| `helo`       | Jego nazwa z HELO lub EHLO                                           |
| `from`       | Nadawca z koperty                                                    |
| `to`         | Odbiorca; powtórz parametr lub rozdziel kilku odbiorców przecinkami  |
| `verbose=1`  | `/scan`: zwraca też listę słów i temat                               |
| `subjectTag` | `/check`: dopisuje prefiks do tematu spamu, na przykład `%5BSPAM%5D` |

`/check` zwraca też `X-Spam-Flag`, `X-Spam-Score` i `X-Spam-Action` jako nagłówki odpowiedzi, więc klient może zdecydować bez parsowania wiadomości.

Wiadomości większe niż 25 MB dostają `413`. Nieudane skanowanie dostaje `500` z `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Z `--out model.json` to, czego uczy `/learn`, jest zapisywane do tego pliku po każdym żądaniu. Bez tej opcji nauka trwa do restartu serwera.

Z Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Z Python:

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


## Serwer TCP

```sh
spamscanner server --port 7830
```

Wyślij surową wiadomość, zamknij stronę wysyłającą połączenia i odczytaj jedną linię JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Z `--verbose` odpowiedzią jest zamiast tego linia tekstu: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` lub `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Serwer zgodny ze SpamAssassin dla spamc, Exim, Haraka i innych klientów SpamAssassin. [Konfiguracja Exim i Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Polecenie       | Odpowiedź                                                      |
| --------------- | -------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                      |
| `SYMBOLS`       | Werdykt i nazwy testów, które zadziałały                       |
| `REPORT`        | Werdykt i tabela testów, punktów i powodów                     |
| `REPORT_IFSPAM` | Jak `REPORT`, z pustym raportem dla hamu                       |
| `PROCESS`       | Werdykt i wiadomość z nagłówkami `X-Spam-*`                    |
| `HEADERS`       | Werdykt i blok nagłówków wiadomości z nagłówkami `X-Spam-*`    |
| `PING`          | `PONG`                                                         |
| `SKIP`          | Nic                                                            |
| `TELL`          | Uczy się spamu lub hamu, z `--allow-tell`; zapisuje do `--out` |

Skompresowane żądania (`Compress: zlib`) są odrzucane.
