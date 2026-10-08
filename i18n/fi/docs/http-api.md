<!-- source: faf44f093f8b -->

# HTTP API, TCP-palvelin ja spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Se kuuntelee osoitetta 127.0.0.1, ellei `--host` määrää muuta. Kun tunniste on asetettu, jokainen pyyntö polkua `/health` lukuun ottamatta tarvitsee otsakkeen `Authorization: Bearer <token>`. Aseta se TLS:ää käyttävän käänteisen välityspalvelimen taakse ennen kuin avaat sen koneen ulkopuolelle.

| Metodi ja polku    | Runko       | Vastaus                                                                  |
| ------------------ | ----------- | ------------------------------------------------------------------------ |
| `GET /health`      |             | `{"ok": true, "version": "7.0.0"}`                                       |
| `POST /scan`       | Raakaviesti | [Tarkistuksen tulos](api.md#the-result) JSON-muodossa                    |
| `POST /check`      | Raakaviesti | Viesti, johon on lisätty `X-Spam-*`-otsakkeet, muodossa `message/rfc822` |
| `POST /learn/spam` | Raakaviesti | `{"ok": true, "learned": "spam"}`; vaatii tunnisteen                     |
| `POST /learn/ham`  | Raakaviesti | `{"ok": true, "learned": "ham"}`; vaatii tunnisteen                      |

Kyselyparametrit kuvaavat SMTP-istunnon:

| Parametri    | Merkitys                                                                      |
| ------------ | ----------------------------------------------------------------------------- |
| `ip`         | Asiakkaan IP-osoite                                                           |
| `hostname`   | Sen varmennettu käänteisen DNS:n nimi                                         |
| `helo`       | Sen HELO- tai EHLO-nimi                                                       |
| `from`       | Kirjekuoren lähettäjä                                                         |
| `to`         | Vastaanottaja; toista se tai erota useita pilkuilla                           |
| `verbose=1`  | `/scan`: palauttaa myös sanaluettelon ja aiherivin                            |
| `subjectTag` | `/check`: lisää etuliitteen roskapostin aiheriville, esimerkiksi `%5BSPAM%5D` |

`/check` palauttaa myös `X-Spam-Flag`-, `X-Spam-Score`- ja `X-Spam-Action`-otsakkeet vastauksen otsakkeina, joten asiakas voi päättää jäsentämättä viestiä.

Yli 25 Mt:n viestit saavat vastauksen `413`. Epäonnistunut tarkistus saa vastauksen `500` ja rungon `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Valitsimella `--out model.json` se, mitä `/learn` opettaa, tallennetaan kyseiseen tiedostoon jokaisen pyynnön jälkeen. Ilman sitä opittu säilyy vain palvelimen uudelleenkäynnistykseen asti.

Node.js:stä:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Pythonista:

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


## TCP-palvelin

```sh
spamscanner server --port 7830
```

Lähetä raakaviesti, sulje yhteyden lähettävä puoli ja lue yksi JSON-rivi:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Valitsimella `--verbose` vastaus on sen sijaan tekstirivi: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` tai `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

SpamAssassin-yhteensopiva palvelin spamc:lle, Eximille, Harakalle ja muille SpamAssassin-asiakkaille. [Eximin ja Harakan määrittäminen](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Komento         | Vastaus                                                                               |
| --------------- | ------------------------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                                             |
| `SYMBOLS`       | Tuomio ja lauenneiden testien nimet                                                   |
| `REPORT`        | Tuomio ja taulukko testeistä, pisteistä ja syistä                                     |
| `REPORT_IFSPAM` | Kuten `REPORT`, mutta hamille tyhjä raportti                                          |
| `PROCESS`       | Tuomio ja viesti `X-Spam-*`-otsakkeineen                                              |
| `HEADERS`       | Tuomio ja viestin otsakelohko `X-Spam-*`-otsakkeineen                                 |
| `PING`          | `PONG`                                                                                |
| `SKIP`          | Ei mitään                                                                             |
| `TELL`          | Oppii roskapostin tai hamin valitsimella `--allow-tell`; tallentaa kohteeseen `--out` |

Pakatut pyynnöt (`Compress: zlib`) hylätään.
