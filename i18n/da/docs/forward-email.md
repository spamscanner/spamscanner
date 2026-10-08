<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner er bygget af [Forward Email](https://forwardemail.net), e-mailtjenesten med åben kildekode og fokus på privatliv, til deres egne mailservere. Forward Email gemmer ingen logs over beskedindhold, så ingen ekstern filtreringstjeneste kunne bruges: filteret skulle køre på deres egne servere og skulle forklare hver afgørelse, uden at et menneske læste posten.

Denne side viser, hvordan en mailserver som Forward Emails bruger det, og hvad der er ændret for kode, der er skrevet til Spam Scanner 5 eller 6.


## På en indgående mailserver

Forward Email modtager post med [smtp-server](https://nodemailer.com/extras/smtp-server/). Mønsteret for enhver server, der er bygget på den:

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

`scanner.scan()` accepterer SMTP-streamen direkte. Hvis du allerede har resultater fra [mailauth](https://github.com/postalsys/mailauth), så spring `authentication` over, og giv kun IP-adressen.

Et svar på 421 eller 451 får den afsendende server til at sætte beskeden i kø og prøve igen senere. Nye afvisningsregler kan starte med en midlertidig kode og gå over til 550, når deres resultater er blevet tjekket, uden at miste post i mellemtiden.


## Opgradering fra version 5 eller 6

Version 7 er skrevet forfra. Konstruktøren, `scan()` og de resultatfelter, som kode til version 5 og 6 læser, virker stadig; klassifikatoren, modellen og de valgfrie TensorFlow-tjek er ændret.

### Stadig det samme

* `new SpamScanner(options)` og `await scanner.scan(source)`.
* `require('spamscanner')` returnerer klassen, og `import SpamScanner from 'spamscanner'` virker.
* `result.isSpam`, `result.message` samt `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` og `.idnHomographAttack`.
* Hvert element i `results.phishing`, `.executables`, `.arbitrary` og `.viruses` konverteres til den samme slags beskedstreng som før (`String(item)`, template literals, `message.includes('adult-related content')`). De er nu objekter med `type`, `message` og detaljer.
* `getTokensAndMailFromSource()`, `getClassification()` og `getTokens()`.
* Disse indstillinger svarer til deres nye navne: `clamscan` til `clamav`, `enableMacroDetection: false` til `macros: false`, `enableArbitraryDetection: false` til `arbitrary: false`, `enableAuthentication` med `authOptions` til `authentication` og `session`, `enableReputation` med `reputationOptions.apiUrl` til `reputation`, `strictIDNDetection` til `phishing.homograph.strictMode` samt `allowlist` og `denylist`. `logger` og `memoize` accepteres og ignoreres.

### Ændret

| Før                                                                                    | Nu                                                                                                                                                                          |
| -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` læste filen                                                 | En streng er beskedtekst. Brug `scanFile(path)`, eller giv en Buffer                                                                                                        |
| En naiv Bayes-model over ord (`classifier.json`), som ikke kan indlæses nu             | En ny klassifikator og et nyt modelformat; træn igen med `spamscanner train` ([træning](training.md))                                                                       |
| Tjek for toksicitet og NSFW indlæste TensorFlow-modeller fra netværket ved første brug | Medbring din egen model: `toxicity: {model}` og `nsfw: {model}` tager ethvert objekt med en `classify()`-metode, for eksempel fra `@tensorflow-models/toxicity` og `nsfwjs` |
| `results.arbitrary` viste alle mønstre, der matchede                                   | Den viser de regler, der er stærke nok til at markere spam alene; alle regler står i `result.tests`                                                                         |
| Et ja-eller-nej-svar                                                                   | `result.score`, `result.action` (`accept`, `tag` eller `reject`) og `result.tests`, hver med point og en begrundelse                                                        |
| `isSpam` blev afgjort af klassifikatoren eller et enkelt tjek                          | `isSpam` er en score på 5 eller mere; grænser og point kan ændres                                                                                                           |
| Omdømmetjek mod et endpoint hos Forward Email                                          | En generisk omdømmetjeneste, slået fra, medmindre `reputation.apiUrl` er sat                                                                                                |

### Nyt

* [Sprogmodeller](llm.md) til tvivlstilfælde, lokale eller hostede.
* SPF, DKIM, DMARC og ARC; DNS-blokeringslister; Cloudflares filtrerende resolvere.
* Tjek af vedhæftede filer ud fra indholdet: forklædte programfiler, arkiver, makroer, aktive PDF'er.
* En [milter, et HTTP API, en TCP-server og en spamd-server](mail-servers.md) og en [kommandolinje](cli.md).
* Træning, evaluering og indlæring fra rapporter, fra kommandolinjen eller API'et.
