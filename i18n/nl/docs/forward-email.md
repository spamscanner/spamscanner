<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner is gebouwd door [Forward Email](https://forwardemail.net), de opensource e-maildienst die privacy voorop stelt, voor de eigen mailservers. Forward Email bewaart geen logs van berichtinhoud, dus een externe filterdienst kwam niet in aanmerking: het filter moest op de eigen servers draaien en elke beslissing uitleggen zonder dat iemand de mail las.

Deze pagina laat zien hoe een mailserver zoals die van Forward Email het gebruikt, en wat er veranderd is voor code die voor Spam Scanner 5 of 6 is geschreven.


## Op een inkomende mailserver

Forward Email ontvangt mail met [smtp-server](https://nodemailer.com/extras/smtp-server/). Het patroon, voor elke server die daarop is gebouwd:

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

`scanner.scan()` accepteert de SMTP-stream direct. Heb je al resultaten van [mailauth](https://github.com/postalsys/mailauth), sla `authentication` dan over en geef alleen het IP-adres mee.

Een antwoord 421 of 451 laat de verzendende server het bericht in de wachtrij zetten en later opnieuw proberen. Nieuwe weigerregels kunnen met een tijdelijke code beginnen en naar 550 gaan zodra hun resultaten zijn gecontroleerd, zonder dat er in de tussentijd mail verloren gaat.


## Upgraden vanaf versie 5 of 6

Versie 7 is herschreven. De constructor, `scan()` en de resultaatvelden die code voor versie 5 en 6 leest, werken nog; de classifier, het model en de optionele TensorFlow-controles zijn veranderd.

### Nog hetzelfde

* `new SpamScanner(options)` en `await scanner.scan(source)`.
* `require('spamscanner')` geeft de klasse terug, en `import SpamScanner from 'spamscanner'` werkt.
* `result.isSpam`, `result.message`, en `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` en `.idnHomographAttack`.
* Elk item in `results.phishing`, `.executables`, `.arbitrary` en `.viruses` wordt omgezet naar hetzelfde soort berichtstring als voorheen (`String(item)`, template literals, `message.includes('adult-related content')`). Het zijn nu objecten met `type`, `message` en details.
* `getTokensAndMailFromSource()`, `getClassification()` en `getTokens()`.
* Deze opties worden omgezet naar hun nieuwe namen: `clamscan` naar `clamav`, `enableMacroDetection: false` naar `macros: false`, `enableArbitraryDetection: false` naar `arbitrary: false`, `enableAuthentication` met `authOptions` naar `authentication` en `session`, `enableReputation` met `reputationOptions.apiUrl` naar `reputation`, `strictIDNDetection` naar `phishing.homograph.strictMode`, en `allowlist` en `denylist`. `logger` en `memoize` worden geaccepteerd en genegeerd.

### Veranderd

| Voorheen                                                                                           | Nu                                                                                                                                                                          |
| -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` las het bestand                                                         | Een string is berichttekst. Gebruik `scanFile(path)` of geef een Buffer mee                                                                                                 |
| Een naive-Bayesmodel van woorden (`classifier.json`), nu niet meer te laden                        | Een nieuwe classifier en een nieuw modelformaat; train opnieuw met `spamscanner train` ([training](training.md))                                                            |
| Controles op toxiciteit en NSFW laadden bij het eerste gebruik TensorFlow-modellen via het netwerk | Lever je eigen model: `toxicity: {model}` en `nsfw: {model}` accepteren elk object met een methode `classify()`, bijvoorbeeld uit `@tensorflow-models/toxicity` en `nsfwjs` |
| `results.arbitrary` noemde elk patroon dat overeenkwam                                             | Het noemt regels die sterk genoeg zijn om op zichzelf spam te markeren; alle regels staan in `result.tests`                                                                 |
| Een antwoord ja of nee                                                                             | `result.score`, `result.action` (`accept`, `tag` of `reject`) en `result.tests`, elk met punten en een reden                                                                |
| `isSpam` bepaald door de classifier of een enkele controle                                         | `isSpam` is een score van 5 of meer; drempels en punten zijn aan te passen                                                                                                  |
| Reputatiecontroles tegen een endpoint van Forward Email                                            | Een generieke reputatiedienst, uit tenzij `reputation.apiUrl` is ingesteld                                                                                                  |

### Nieuw

* [Taalmodellen](llm.md) voor twijfelgevallen, lokaal of gehost.
* SPF, DKIM, DMARC en ARC; DNS-blocklists; de filterende resolvers van Cloudflare.
* Controles op bijlagen op basis van inhoud: vermomde uitvoerbare bestanden, archieven, macro's, actieve pdf's.
* Een [milter, HTTP API, TCP-server en spamd-server](mail-servers.md), en een [opdrachtregel](cli.md).
* Trainen, evalueren en leren van meldingen, vanaf de opdrachtregel of via de API.
