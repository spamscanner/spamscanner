<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner ble laget av [Forward Email](https://forwardemail.net), e-posttjenesten med åpen kildekode og fokus på personvern, for selskapets egne e-postservere. Forward Email lagrer ingen logger over meldingsinnhold, så ingen ekstern filtreringstjeneste kunne brukes: filteret måtte kjøre på egne servere og måtte forklare hver avgjørelse uten at et menneske leste e-posten.

Denne siden viser hvordan en e-postserver som Forward Emails bruker det, og hva som er endret for kode skrevet for Spam Scanner 5 eller 6.


## På en server for innkommende e-post

Forward Email mottar e-post med [smtp-server](https://nodemailer.com/extras/smtp-server/). Mønsteret, for enhver server bygget på den:

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

`scanner.scan()` tar imot SMTP-strømmen direkte. Hvis du allerede har resultater fra [mailauth](https://github.com/postalsys/mailauth), kan du hoppe over `authentication` og bare sende med IP-adressen.

Et svar med 421 eller 451 får avsenderserveren til å legge meldingen i kø og prøve igjen senere. Nye avvisningsregler kan starte med en midlertidig kode og gå over til 550 når resultatene er kontrollert, uten at e-post går tapt i mellomtiden.


## Oppgradering fra versjon 5 eller 6

Versjon 7 er skrevet om fra bunnen av. Konstruktøren, `scan()` og resultatfeltene som kode for versjon 5 og 6 leser, virker fortsatt; klassifisereren, modellen og de valgfrie TensorFlow-sjekkene er endret.

### Fortsatt det samme

* `new SpamScanner(options)` og `await scanner.scan(source)`.
* `require('spamscanner')` returnerer klassen, og `import SpamScanner from 'spamscanner'` virker.
* `result.isSpam`, `result.message` og `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` og `.idnHomographAttack`.
* Hvert element i `results.phishing`, `.executables`, `.arbitrary` og `.viruses` gjøres om til samme type meldingsstreng som før (`String(item)`, malstrenger, `message.includes('adult-related content')`). De er nå objekter med `type`, `message` og detaljer.
* `getTokensAndMailFromSource()`, `getClassification()` og `getTokens()`.
* Disse alternativene er knyttet til sine nye navn: `clamscan` til `clamav`, `enableMacroDetection: false` til `macros: false`, `enableArbitraryDetection: false` til `arbitrary: false`, `enableAuthentication` med `authOptions` til `authentication` og `session`, `enableReputation` med `reputationOptions.apiUrl` til `reputation`, `strictIDNDetection` til `phishing.homograph.strictMode`, samt `allowlist` og `denylist`. `logger` og `memoize` godtas og ignoreres.

### Endret

| Før                                                                                       | Nå                                                                                                                                                                            |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` leste filen                                                    | En streng er meldingstekst. Bruk `scanFile(path)` eller send en Buffer                                                                                                        |
| En naiv Bayes-modell av ord (`classifier.json`), som ikke kan lastes inn nå               | En ny klassifiserer og et nytt modellformat; tren på nytt med `spamscanner train` ([trening](training.md))                                                                    |
| Sjekkene for toksisitet og NSFW lastet inn TensorFlow-modeller fra nettet ved første bruk | Ta med din egen modell: `toxicity: {model}` og `nsfw: {model}` tar imot ethvert objekt med en `classify()`-metode, for eksempel fra `@tensorflow-models/toxicity` og `nsfwjs` |
| `results.arbitrary` listet opp alle mønstre som traff                                     | Den lister opp regler som er sterke nok til å merke spam alene; alle regler finnes i `result.tests`                                                                           |
| Et ja-eller-nei-svar                                                                      | `result.score`, `result.action` (`accept`, `tag` eller `reject`) og `result.tests`, hver med poeng og en begrunnelse                                                          |
| `isSpam` ble avgjort av klassifisereren eller en hvilken som helst enkeltsjekk            | `isSpam` er en poengsum på 5 eller mer; terskler og poeng kan endres                                                                                                          |
| Omdømmesjekker mot et endepunkt hos Forward Email                                         | En generell omdømmetjeneste, av med mindre `reputation.apiUrl` er satt                                                                                                        |

### Nytt

* [Språkmodeller](llm.md) for vanskelige tilfeller, lokale eller driftede.
* SPF, DKIM, DMARC og ARC; DNS-blokkeringslister; Cloudflares filtrerende resolvere.
* Vedleggssjekker ut fra innhold: forkledde kjørbare filer, arkiver, makroer, aktive PDF-er.
* En [milter, et HTTP API, en TCP-server og en spamd-server](mail-servers.md), og en [kommandolinje](cli.md).
* Trening, evaluering og læring fra rapporter, fra kommandolinjen eller API-et.
