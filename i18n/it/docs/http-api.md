<!-- source: faf44f093f8b -->

# API HTTP, server TCP e spamd


## API HTTP

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

È in ascolto su 127.0.0.1, salvo diversa indicazione di `--host`. Con un token, ogni richiesta tranne `/health` richiede `Authorization: Bearer <token>`. Mettila dietro un reverse proxy con TLS prima di esporla al di fuori della macchina.

| Metodo e percorso  | Corpo               | Risposta                                                                    |
| ------------------ | ------------------- | --------------------------------------------------------------------------- |
| `GET /health`      |                     | `{"ok": true, "version": "7.0.0"}`                                          |
| `POST /scan`       | Il messaggio grezzo | Il [risultato dell'analisi](api.md#the-result) in JSON                      |
| `POST /check`      | Il messaggio grezzo | Il messaggio con le intestazioni `X-Spam-*` aggiunte, come `message/rfc822` |
| `POST /learn/spam` | Il messaggio grezzo | `{"ok": true, "learned": "spam"}`; richiede un token                        |
| `POST /learn/ham`  | Il messaggio grezzo | `{"ok": true, "learned": "ham"}`; richiede un token                         |

I parametri della query descrivono la sessione SMTP:

| Parametro    | Significato                                                          |
| ------------ | -------------------------------------------------------------------- |
| `ip`         | L'indirizzo IP del client                                            |
| `hostname`   | Il suo nome DNS inverso verificato                                   |
| `helo`       | Il suo nome HELO o EHLO                                              |
| `from`       | Il mittente dell'envelope                                            |
| `to`         | Un destinatario; ripetilo o separa più destinatari con virgole       |
| `verbose=1`  | `/scan`: restituisce anche l'elenco delle parole e l'oggetto         |
| `subjectTag` | `/check`: prefisso per l'oggetto dello spam, ad esempio `%5BSPAM%5D` |

`/check` restituisce anche `X-Spam-Flag`, `X-Spam-Score` e `X-Spam-Action` come intestazioni della risposta, quindi un client può decidere senza analizzare il messaggio.

I messaggi più grandi di 25 MB ricevono `413`. Un'analisi che fallisce riceve `500` con `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Con `--out model.json`, ciò che `/learn` insegna viene salvato in quel file dopo ogni richiesta. Senza, l'apprendimento dura fino al riavvio del server.

Da Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Da Python:

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


## Server TCP

```sh
spamscanner server --port 7830
```

Invia il messaggio grezzo, chiudi il lato di invio della connessione e leggi una riga di JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Con `--verbose`, la risposta è invece una riga di testo: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` o `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Un server compatibile con SpamAssassin per spamc, Exim, Haraka e altri client SpamAssassin. [Configurare Exim e Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Comando         | Risposta                                                                             |
| --------------- | ------------------------------------------------------------------------------------ |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                                            |
| `SYMBOLS`       | Il verdetto e i nomi dei test scattati                                               |
| `REPORT`        | Il verdetto e una tabella di test, punti e motivi                                    |
| `REPORT_IFSPAM` | Come `REPORT`, con un report vuoto per l'ham                                         |
| `PROCESS`       | Il verdetto e il messaggio con le intestazioni `X-Spam-*`                            |
| `HEADERS`       | Il verdetto e il blocco di intestazioni del messaggio con le intestazioni `X-Spam-*` |
| `PING`          | `PONG`                                                                               |
| `SKIP`          | Niente                                                                               |
| `TELL`          | Impara spam o ham, con `--allow-tell`; salva in `--out`                              |

Le richieste compresse (`Compress: zlib`) vengono rifiutate.
