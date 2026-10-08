<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner wurde von [Forward Email](https://forwardemail.net), dem quelloffenen E-Mail-Dienst mit Fokus auf Datenschutz, für die eigenen Mailserver entwickelt. Forward Email protokolliert keine Nachrichteninhalte, daher kam kein externer Filterdienst in Frage: Der Filter musste auf den eigenen Servern laufen und jede Entscheidung begründen, ohne dass ein Mensch die E-Mail liest.

Diese Seite zeigt, wie ein Mailserver wie der von Forward Email ihn einsetzt und was sich für Code geändert hat, der für Spam Scanner 5 oder 6 geschrieben wurde.


## Auf einem Mailserver für eingehende E-Mails

Forward Email empfängt E-Mails mit [smtp-server](https://nodemailer.com/extras/smtp-server/). Das Muster für jeden darauf aufbauenden Server:

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

`scanner.scan()` nimmt den SMTP-Stream direkt entgegen. Liegen bereits Ergebnisse von [mailauth](https://github.com/postalsys/mailauth) vor, lassen Sie `authentication` weg und übergeben nur die IP-Adresse.

Eine Antwort mit 421 oder 451 veranlasst den sendenden Server, die Nachricht in die Warteschlange zu stellen und es später erneut zu versuchen. Neue Ablehnungsregeln können mit einem temporären Code beginnen und auf 550 wechseln, sobald ihre Ergebnisse geprüft sind, ohne dass zwischendurch E-Mails verloren gehen.


## Aktualisieren von Version 5 oder 6

Version 7 ist eine Neuentwicklung. Der Konstruktor, `scan()` und die Ergebnisfelder, die Code für Version 5 und 6 liest, funktionieren weiterhin. Geändert haben sich der Klassifikator, das Modell und die optionalen TensorFlow-Prüfungen.

### Unverändert

* `new SpamScanner(options)` und `await scanner.scan(source)`.
* `require('spamscanner')` gibt die Klasse zurück, und `import SpamScanner from 'spamscanner'` funktioniert.
* `result.isSpam`, `result.message` sowie `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` und `.idnHomographAttack`.
* Jeder Eintrag in `results.phishing`, `.executables`, `.arbitrary` und `.viruses` wird wie bisher in dieselbe Art Meldungsstring umgewandelt (`String(item)`, Template-Literale, `message.includes('adult-related content')`). Die Einträge sind jetzt Objekte mit `type`, `message` und Details.
* `getTokensAndMailFromSource()`, `getClassification()` und `getTokens()`.
* Diese Optionen werden auf ihre neuen Namen abgebildet: `clamscan` auf `clamav`, `enableMacroDetection: false` auf `macros: false`, `enableArbitraryDetection: false` auf `arbitrary: false`, `enableAuthentication` mit `authOptions` auf `authentication` und `session`, `enableReputation` mit `reputationOptions.apiUrl` auf `reputation`, `strictIDNDetection` auf `phishing.homograph.strictMode` sowie `allowlist` und `denylist`. `logger` und `memoize` werden akzeptiert und ignoriert.

### Geändert

| Vorher                                                                                      | Jetzt                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` las die Datei                                                    | Ein String ist Nachrichtentext. Verwenden Sie `scanFile(path)` oder übergeben Sie einen Buffer                                                                                              |
| Ein naives Bayes-Modell aus Wörtern (`classifier.json`), heute nicht mehr ladbar            | Ein neuer Klassifikator und ein neues Modellformat; mit `spamscanner train` neu trainieren ([Training](training.md))                                                                        |
| Toxizitäts- und NSFW-Prüfungen luden TensorFlow-Modelle bei der ersten Nutzung aus dem Netz | Eigenes Modell mitbringen: `toxicity: {model}` und `nsfw: {model}` nehmen jedes Objekt mit einer `classify()`-Methode entgegen, zum Beispiel aus `@tensorflow-models/toxicity` und `nsfwjs` |
| `results.arbitrary` listete jedes passende Muster auf                                       | Es listet Regeln auf, die allein stark genug sind, um Spam zu markieren; alle Regeln stehen in `result.tests`                                                                               |
| Eine Ja-oder-Nein-Antwort                                                                   | `result.score`, `result.action` (`accept`, `tag` oder `reject`) und `result.tests`, jeweils mit Punkten und einer Begründung                                                                |
| `isSpam` wurde vom Klassifikator oder einer einzelnen Prüfung bestimmt                      | `isSpam` bedeutet einen Score von 5 oder mehr; Schwellenwerte und Punkte lassen sich ändern                                                                                                 |
| Reputationsprüfungen gegen einen Endpunkt von Forward Email                                 | Ein generischer Reputationsdienst, ausgeschaltet, solange `reputation.apiUrl` nicht gesetzt ist                                                                                             |

### Neu

* [Sprachmodelle](llm.md) für knappe Fälle, lokal oder gehostet.
* SPF, DKIM, DMARC und ARC; DNS-Blocklisten; die filternden Resolver von Cloudflare.
* Anhangsprüfungen nach Inhalt: getarnte ausführbare Dateien, Archive, Makros, aktive PDFs.
* Ein [Milter, eine HTTP-API, ein TCP-Server und ein spamd-Server](mail-servers.md) sowie eine [Kommandozeile](cli.md).
* Training, Evaluierung und Lernen aus Meldungen, über die Kommandozeile oder die API.
