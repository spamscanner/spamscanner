<!-- source: 665fbc0d5adc -->

# HTTP API, TCP-server og spamd


## HTTP API

```sh
spamscanner http --port 7832    # token in SPAMSCANNER_TOKEN
```

HTTP-API-et leser tokenet sitt fra miljøvariabelen `SPAMSCANNER_TOKEN`. `--token` fungerer også, men andre brukere på maskinen kan se kommandolinjevalg i `ps`.

Den lytter på 127.0.0.1 med mindre `--host` sier noe annet. Med et token krever hver forespørsel unntatt `/health` hodet `Authorization: Bearer <token>`. Sett den bak en omvendt proxy med TLS før den gjøres tilgjengelig utenfor maskinen.

| Metode og sti      | Innhold          | Svar                                                          |
| ------------------ | ---------------- | ------------------------------------------------------------- |
| `GET /health`      |                  | `{"ok": true, "version": "..."}`                              |
| `POST /scan`       | Den rå meldingen | [Skanneresultatet](api.md#the-result) som JSON                |
| `POST /check`      | Den rå meldingen | Meldingen med `X-Spam-*`-hoder lagt til, som `message/rfc822` |
| `POST /learn/spam` | Den rå meldingen | `{"ok": true, "learned": "spam"}`; krever et token            |
| `POST /learn/ham`  | Den rå meldingen | `{"ok": true, "learned": "ham"}`; krever et token             |

Spørreparametere beskriver SMTP-økten:

| Parameter    | Betydning                                                                |
| ------------ | ------------------------------------------------------------------------ |
| `ip`         | Klientens IP-adresse                                                     |
| `hostname`   | Klientens verifiserte navn fra omvendt DNS                               |
| `helo`       | Navnet i HELO eller EHLO                                                 |
| `from`       | Konvoluttavsenderen                                                      |
| `to`         | En mottaker; gjenta den, eller skill flere med komma                     |
| `verbose=1`  | `/scan`: returner også ordlisten og emnet                                |
| `subjectTag` | `/check`: sett et prefiks foran emnet på spam, for eksempel `%5BSPAM%5D` |

Uten `ip` hoppes sjekkene av SPF, DKIM, DMARC, ARC og IP-blokkeringslister (`--auth`, `--dnsbl`) over.

`/check` returnerer også `X-Spam-Flag`, `X-Spam-Score` og `X-Spam-Action` som svarhoder, slik at en klient kan avgjøre uten å tolke meldingen.

Meldinger større enn 25 MiB (`--max-size`) får `413`, før innholdet leses når `Content-Length` oppgir størrelsen. En skanning som feiler, får `500` med `{"error": "..."}`. Serveren håndterer høyst 200 forespørsler samtidig (`--max-connections`), medregnet forespørsler i pipeline; flere får `503` med `Retry-After: 1`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Med `--out model.json` lagres det `/learn` lærer, i den filen etter hver forespørsel. Uten det varer læringen til serveren startes på nytt.

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

Send den rå meldingen, lukk sendesiden av tilkoblingen, og les én linje med JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Med `--verbose` er svaret i stedet en tekstlinje: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` eller `HAM -2.5/5.0 BAYES_00`.

TCP-serveren kjenner ikke klientens IP-adresse, så `--auth` og `--dnsbl` har ingen virkning. Den svarer først når klienten lukker sin sendeside (`nc -N` eller `nc -q 1`, eller `shutdown(SHUT_WR)` på en socket); en klient som holder den åpen, får ikke noe svar, og tilkoblingen lukkes etter 60 sekunder uten data. Den svarer med en feil på meldinger større enn 25 MiB (`--max-size`).


## spamd

```sh
spamscanner spamd --port 783
```

En SpamAssassin-kompatibel server for spamc, Exim, Haraka og andre SpamAssassin-klienter. [Oppsett av Exim og Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Kommando        | Svar                                                         |
| --------------- | ------------------------------------------------------------ |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                    |
| `SYMBOLS`       | Vurderingen og navnene på testene som slo ut                 |
| `REPORT`        | Vurderingen og en tabell over tester, poeng og begrunnelser  |
| `REPORT_IFSPAM` | Som `REPORT`, med en tom rapport for ham                     |
| `PROCESS`       | Vurderingen og meldingen med `X-Spam-*`-hoder                |
| `HEADERS`       | Vurderingen og meldingens hodeblokk med `X-Spam-*`-hoder     |
| `PING`          | `PONG`                                                       |
| `SKIP`          | Ingenting                                                    |
| `TELL`          | Lærer spam eller ham, med `--allow-tell`; lagrer til `--out` |

Komprimerte forespørsler (`Compress: zlib`) avvises.

spamd-klienter sender heller ikke klientens IP-adresse, så `--auth` og `--dnsbl` har ingen virkning. En melding større enn 25 MiB (`--max-size`) får `65` (`EX_DATAERR`), en melding kortere enn sin `Content-length` får `76` (`EX_PROTOCOL`), og tilkoblinger som ikke sender noe på 60 sekunder, lukkes.
