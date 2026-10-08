<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner byggdes av [Forward Email](https://forwardemail.net), e-posttjänsten med öppen källkod och fokus på integritet, för dess egna e-postservrar. Forward Email sparar inga loggar över meddelandeinnehåll, så ingen extern filtertjänst dugde: filtret måste köras på de egna servrarna och måste kunna förklara varje beslut utan att någon person läser e-posten.

Den här sidan visar hur en e-postserver som Forward Emails använder det, och vad som ändrats för kod som skrivits för Spam Scanner 5 eller 6.


## På en server för inkommande e-post

Forward Email tar emot e-post med [smtp-server](https://nodemailer.com/extras/smtp-server/). Mönstret, för alla servrar som bygger på det:

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

`scanner.scan()` tar emot SMTP-strömmen direkt. Om du redan har resultat från [mailauth](https://github.com/postalsys/mailauth), hoppa över `authentication` och skicka bara med IP-adressen.

Ett svar med 421 eller 451 gör att den sändande servern köar meddelandet och försöker igen senare. Nya avvisningsregler kan börja med en tillfällig kod och gå över till 550 när deras resultat har kontrollerats, utan att e-post går förlorad under tiden.


## Uppgradera från version 5 eller 6

Version 7 är omskriven från grunden. Konstruktorn, `scan()` och de resultatfält som kod för version 5 och 6 läser fungerar fortfarande; klassificeraren, modellen och de valfria TensorFlow-kontrollerna har ändrats.

### Fortfarande samma

* `new SpamScanner(options)` och `await scanner.scan(source)`.
* `require('spamscanner')` returnerar klassen, och `import SpamScanner from 'spamscanner'` fungerar.
* `result.isSpam`, `result.message` samt `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` och `.idnHomographAttack`.
* Varje post i `results.phishing`, `.executables`, `.arbitrary` och `.viruses` konverteras till samma slags meddelandesträng som tidigare (`String(item)`, mallsträngar, `message.includes('adult-related content')`). De är nu objekt med `type`, `message` och detaljer.
* `getTokensAndMailFromSource()`, `getClassification()` och `getTokens()`.
* Dessa alternativ motsvarar sina nya namn: `clamscan` blir `clamav`, `enableMacroDetection: false` blir `macros: false`, `enableArbitraryDetection: false` blir `arbitrary: false`, `enableAuthentication` med `authOptions` blir `authentication` och `session`, `enableReputation` med `reputationOptions.apiUrl` blir `reputation`, `strictIDNDetection` blir `phishing.homograph.strictMode`, samt `allowlist` och `denylist`. `logger` och `memoize` accepteras och ignoreras.

### Ändrat

| Tidigare                                                                                            | Nu                                                                                                                                                                                       |
| --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` läste filen                                                              | En sträng är meddelandetext. Använd `scanFile(path)` eller skicka en Buffer                                                                                                              |
| En naiv Bayes-modell av ord (`classifier.json`), som inte kan läsas in nu                           | En ny klassificerare och ett nytt modellformat; träna om med `spamscanner train` ([träning](training.md))                                                                                |
| Kontroller av toxicitet och NSFW laddade TensorFlow-modeller från nätverket vid första användningen | Ta med din egen modell: `toxicity: {model}` och `nsfw: {model}` tar emot vilket objekt som helst med en `classify()`-metod, till exempel från `@tensorflow-models/toxicity` och `nsfwjs` |
| `results.arbitrary` listade alla mönster som matchade                                               | Den listar regler som är starka nog att markera spam på egen hand; alla regler finns i `result.tests`                                                                                    |
| Ett ja- eller nej-svar                                                                              | `result.score`, `result.action` (`accept`, `tag` eller `reject`) och `result.tests`, var och en med poäng och en orsak                                                                   |
| `isSpam` avgjordes av klassificeraren eller en enskild kontroll                                     | `isSpam` är en poäng på 5 eller mer; gränsvärden och poäng kan ändras                                                                                                                    |
| Ryktekontroller mot en slutpunkt hos Forward Email                                                  | En generisk ryktestjänst, avstängd om inte `reputation.apiUrl` är satt                                                                                                                   |

### Nytt

* [Språkmodeller](llm.md) för gränsfall, lokala eller molnbaserade.
* SPF, DKIM, DMARC och ARC; DNS-blocklistor; Cloudflares filtrerande resolvrar.
* Kontroll av bilagor efter innehåll: förklädda körbara filer, arkiv, makron, aktiva PDF-filer.
* En [milter, ett HTTP-API, en TCP-server och en spamd-server](mail-servers.md), och en [kommandorad](cli.md).
* Träning, utvärdering och inlärning från rapporter, från kommandoraden eller API:t.
