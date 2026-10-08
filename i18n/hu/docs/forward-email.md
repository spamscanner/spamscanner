<!-- source: dc9016edd59e -->

# Forward Email

A Spam Scannert a [Forward Email](https://forwardemail.net), a nyílt forráskódú, adatvédelemre összpontosító e-mail-szolgáltatás fejlesztette a saját levelezőszerverei számára. A Forward Email nem naplózza a levelek tartalmát, ezért egyetlen külső szűrőszolgáltatás sem jöhetett szóba: a szűrőnek a saját szervereken kellett futnia, és minden döntését meg kellett tudnia indokolni anélkül, hogy bárki elolvasná a levelet.

Ez az oldal bemutatja, hogyan használja egy olyan levelezőszerver, mint a Forward Emailé, és mi változott a Spam Scanner 5-ös vagy 6-os verziójához írt kódok számára.


## Bejövő levelezőszerveren

A Forward Email az [smtp-server](https://nodemailer.com/extras/smtp-server/) segítségével fogadja a leveleket. A minta bármely erre épülő szerverhez:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

A `scanner.scan()` közvetlenül fogadja az SMTP-streamet. Ha a [mailauth](https://github.com/postalsys/mailauth) eredményei már rendelkezésre állnak, az `authentication` kihagyható, és elég csak az IP-címet átadni.

A 421-es vagy 451-es válasz hatására a küldő szerver sorba állítja a levelet, és később újra próbálkozik. Az új elutasítási szabályok kezdetben ideiglenes kóddal indulhatnak, és az eredmények ellenőrzése után válthatnak 550-re, anélkül hogy közben levél veszne el.


## Frissítés az 5-ös vagy 6-os verzióról

A 7-es verzió teljes újraírás. A konstruktor, a `scan()` és az 5-ös és 6-os verzióhoz írt kód által olvasott eredménymezők továbbra is működnek; az osztályozó, a modell és az opcionális TensorFlow-ellenőrzések megváltoztak.

### Ami változatlan

* `new SpamScanner(options)` és `await scanner.scan(source)`.
* A `require('spamscanner')` az osztályt adja vissza, és az `import SpamScanner from 'spamscanner'` is működik.
* `result.isSpam`, `result.message`, valamint `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` és `.idnHomographAttack`.
* A `results.phishing`, `.executables`, `.arbitrary` és `.viruses` minden eleme ugyanolyan üzenet-karakterlánccá alakul, mint korábban (`String(item)`, template literalok, `message.includes('adult-related content')`). Ezek most `type`, `message` és részletek mezőket tartalmazó objektumok.
* `getTokensAndMailFromSource()`, `getClassification()` és `getTokens()`.
* Ezek a beállítások az új nevükre képeződnek le: `clamscan` → `clamav`, `enableMacroDetection: false` → `macros: false`, `enableArbitraryDetection: false` → `arbitrary: false`, `enableAuthentication` az `authOptions` beállítással → `authentication` és `session`, `enableReputation` a `reputationOptions.apiUrl` beállítással → `reputation`, `strictIDNDetection` → `phishing.homograph.strictMode`, valamint `allowlist` és `denylist`. A `logger` és a `memoize` elfogadott, de figyelmen kívül marad.

### Ami megváltozott

| Korábban                                                                                            | Most                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A `scan('path/to/file.eml')` beolvasta a fájlt                                                      | A karakterlánc a levél szövege. A `scanFile(path)` használható, vagy Buffer adható át                                                                                                             |
| Szavakon alapuló naiv Bayes-modell (`classifier.json`), amely most nem tölthető be                  | Új osztályozó és modellformátum; újratanítás a `spamscanner train` paranccsal ([tanítás](training.md))                                                                                            |
| A toxicitás- és NSFW-ellenőrzések első használatkor a hálózatról töltöttek le TensorFlow-modelleket | Saját modell hozható: a `toxicity: {model}` és az `nsfw: {model}` bármely `classify()` metódussal rendelkező objektumot elfogad, például a `@tensorflow-models/toxicity` és az `nsfwjs` csomagból |
| A `results.arbitrary` minden illeszkedő mintát felsorolt                                            | Csak azokat a szabályokat sorolja fel, amelyek önmagukban elég erősek a spamként jelöléshez; minden szabály a `result.tests` mezőben található                                                    |
| Igen-nem válasz                                                                                     | `result.score`, `result.action` (`accept`, `tag` vagy `reject`) és `result.tests`, mindegyik ponttal és okkal                                                                                     |
| Az `isSpam` értékéről az osztályozó vagy bármely egyedi ellenőrzés döntött                          | Az `isSpam` 5 vagy több pontot jelent; a küszöbök és a pontok módosíthatók                                                                                                                        |
| Hírnév-ellenőrzés egy Forward Email-végponton                                                       | Általános hírnévszolgáltatás, kikapcsolva, amíg a `reputation.apiUrl` nincs beállítva                                                                                                             |

### Újdonságok

* [Nyelvi modellek](llm.md) a kétes esetekhez, helyben vagy szolgáltatónál.
* SPF, DKIM, DMARC és ARC; DNS-tiltólisták; a Cloudflare szűrő DNS-feloldói.
* Mellékletek tartalomalapú ellenőrzése: álcázott futtatható fájlok, archívumok, makrók, aktív PDF-ek.
* [Milter, HTTP API, TCP-szerver és spamd szerver](mail-servers.md), valamint [parancssor](cli.md).
* Tanítás, kiértékelés és tanulás a bejelentésekből, a parancssorból vagy az API-n keresztül.
