<!-- source: dc9016edd59e -->

# Forward Email

Spam Scannerin on tehnyt [Forward Email](https://forwardemail.net), avoimen lähdekoodin yksityisyyteen keskittyvä sähköpostipalvelu, omille postipalvelimilleen. Forward Email ei tallenna lokeja viestien sisällöstä, joten mikään ulkopuolinen suodatuspalvelu ei kelvannut: suodattimen piti toimia omilla palvelimilla ja perustella jokainen päätös ilman, että kukaan lukee postia.

Tämä sivu näyttää, miten Forward Emailin kaltainen postipalvelin sitä käyttää ja mikä muuttui Spam Scannerin versioille 5 tai 6 kirjoitetun koodin kannalta.


## Saapuvan postin palvelimella

Forward Email vastaanottaa postia [smtp-serverillä](https://nodemailer.com/extras/smtp-server/). Malli mille tahansa sen päälle rakennetulle palvelimelle:

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

`scanner.scan()` hyväksyy SMTP-virran suoraan. Jos [mailauthin](https://github.com/postalsys/mailauth) tulokset ovat jo käytettävissä, jätä `authentication` pois ja välitä pelkkä IP-osoite.

Vastaus 421 tai 451 saa lähettävän palvelimen asettamaan viestin jonoon ja yrittämään myöhemmin uudelleen. Uudet hylkäyssäännöt voivat aloittaa väliaikaisella koodilla ja siirtyä koodiin 550, kun niiden tulokset on tarkistettu, menettämättä postia siinä välissä.


## Päivittäminen versiosta 5 tai 6

Versio 7 on kirjoitettu uudelleen. Konstruktori, `scan()` ja tulosten kentät, joita versioiden 5 ja 6 koodi lukee, toimivat edelleen; luokitin, malli ja valinnaiset TensorFlow-tarkistukset muuttuivat.

### Ennallaan

* `new SpamScanner(options)` ja `await scanner.scan(source)`.
* `require('spamscanner')` palauttaa luokan, ja `import SpamScanner from 'spamscanner'` toimii.
* `result.isSpam`, `result.message` sekä `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` ja `.idnHomographAttack`.
* Jokainen kohteiden `results.phishing`, `.executables`, `.arbitrary` ja `.viruses` alkio muuntuu samanlaiseksi viestimerkkijonoksi kuin ennenkin (`String(item)`, mallimerkkijonot, `message.includes('adult-related content')`). Ne ovat nyt olioita, joilla on `type`, `message` ja yksityiskohdat.
* `getTokensAndMailFromSource()`, `getClassification()` ja `getTokens()`.
* Nämä valinnat vastaavat uusia nimiään: `clamscan` on nyt `clamav`, `enableMacroDetection: false` on `macros: false`, `enableArbitraryDetection: false` on `arbitrary: false`, `enableAuthentication` yhdessä `authOptions`:n kanssa on `authentication` ja `session`, `enableReputation` yhdessä `reputationOptions.apiUrl`:n kanssa on `reputation`, `strictIDNDetection` on `phishing.homograph.strictMode`, sekä `allowlist` ja `denylist`. `logger` ja `memoize` hyväksytään ja ohitetaan.

### Muuttunut

| Ennen                                                                                             | Nyt                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` luki tiedoston                                                         | Merkkijono on viestin tekstiä. Käytä `scanFile(path)` tai välitä Buffer                                                                                                               |
| Sanoihin perustuva naiivi Bayes-malli (`classifier.json`), jota ei voi enää ladata                | Uusi luokitin ja mallimuoto; kouluta uudelleen komennolla `spamscanner train` ([koulutus](training.md))                                                                               |
| Toksisuus- ja NSFW-tarkistukset latasivat TensorFlow-mallit verkosta ensimmäisellä käyttökerralla | Tuo oma mallisi: `toxicity: {model}` ja `nsfw: {model}` ottavat minkä tahansa olion, jolla on `classify()`-metodi, esimerkiksi kirjastoista `@tensorflow-models/toxicity` ja `nsfwjs` |
| `results.arbitrary` luetteli jokaisen täsmänneen mallin                                           | Se luettelee säännöt, jotka ovat yksinään tarpeeksi vahvoja merkitsemään roskapostin; kaikki säännöt ovat kohteessa `result.tests`                                                    |
| Kyllä tai ei -vastaus                                                                             | `result.score`, `result.action` (`accept`, `tag` tai `reject`) ja `result.tests`, kukin pisteineen ja syineen                                                                         |
| `isSpam` määräytyi luokittimen tai minkä tahansa yksittäisen tarkistuksen perusteella             | `isSpam` tarkoittaa vähintään 5 pistettä; rajoja ja pisteitä voi muuttaa                                                                                                              |
| Mainetarkistukset Forward Emailin rajapintaa vasten                                               | Yleinen mainepalvelu, pois käytöstä, ellei `reputation.apiUrl` ole asetettu                                                                                                           |

### Uutta

* [Kielimallit](llm.md) epäselviin tapauksiin, paikallisesti tai palveluna.
* SPF, DKIM, DMARC ja ARC; DNS-estolistat; Cloudflaren suodattavat DNS-palvelut.
* Liitteiden tarkistus sisällön perusteella: naamioidut suoritettavat tiedostot, arkistot, makrot, aktiiviset PDF:t.
* [Milter, HTTP API, TCP-palvelin ja spamd-palvelin](mail-servers.md) sekä [komentorivi](cli.md).
* Koulutus, arviointi ja oppiminen raporteista komentoriviltä tai API:n kautta.
