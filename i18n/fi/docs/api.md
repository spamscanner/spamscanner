<!-- source: b19ea85ceb6d -->

# API-viite

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Luo yksi skanneri ja käytä sitä uudelleen: se lataa mallin kerran ja tallentaa DNS- ja kielimallivastaukset välimuistiin.

Tyyppimäärittelyt ovat mukana. Ne vaativat TypeScriptin 4.7 tai uudemman `import`-käytössä ja 5.3 tai uudemman `require`-käytössä.


## Valinnat

Jokaisen valinnan voi antaa konstruktorille. Useimmat voi antaa myös `scan()`-kutsulle yksittäistä viestiä varten, jolloin ne yhdistetään konstruktorin valintojen päälle. Arvolla `undefined` annetut valinnat säilyttävät oletusarvonsa. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` ja `strictIDNDetection` luetaan vain konstruktorissa; `classifier`-valinnassa annettu mallitiedosto tai -olio luetaan siellä, joten puuttuva tai vioittunut malli heittää virheen heti.

| Valinta                 | Oletus                           | Merkitys                                                                                                                                                                                                       |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Pistemäärä, josta alkaen viesti on roskapostia                                                                                                                                                                 |
| `rejectThreshold`       | `15`                             | Pistemäärä, josta alkaen `action` on `reject`                                                                                                                                                                  |
| `scores`                | `{}`                             | Pisteet testiä kohden: asetusavaimet tai testien nimet ([testit ja pisteet](scoring.md))                                                                                                                       |
| `classifier`            | mukana tuleva malli              | `Classifier`, malliolio, mallitiedoston polku tai `false`                                                                                                                                                      |
| `classifierOptions`     | `{}`                             | Mukana tulevan mallin valinnat (katso [Luokitin](#classifier))                                                                                                                                                 |
| `allowedLanguages`      | `[]`                             | ISO 639-1 -koodit (`no` luetaan muodossa `nb`, `fil` muodossa `tl` ja vanhat `iw`, `in`, `ji` muodoissa `he`, `id`, `yi`); muut kielet saavat testin `LANGUAGE_NOT_ALLOWED`                                    |
| `phishing.cloudflare`   | `true`                           | Kysy Cloudflaren suodattavilta DNS-palveluilta linkkien isännistä                                                                                                                                              |
| `phishing.adult`        | `true`                           | Kysy myös perhepalvelulta, joka estää aikuissivustot                                                                                                                                                           |
| `phishing.maxHosts`     | `25`                             | Viestiä kohden tarkistettavien linkki-isäntien määrä                                                                                                                                                           |
| `phishing.maxLength`    | `1000000`                        | Linkkien etsimiseksi luettavat tekstin merkit (HTML:stä kaksinkertainen määrä); pidempi teksti asettaa `results.linksTruncated`; `Infinity` tai mikä tahansa muu kuin positiivinen luku tarkoittaa oletusarvoa |
| `phishing.homograph`    | `{}`                             | `brands` (korvaa sisäänrakennetun luettelon), `extraBrands`, `allowlist` (verkkotunnukset, joita ei koskaan merkitä), `strictMode`                                                                             |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS-estolistojen vyöhykkeet asiakkaan IP-osoitteelle ja linkkien verkkotunnuksille                                                                                                                             |
| `dns`                   | `{servers: null, timeout: 3000}` | DNS-tarkistusten nimipalvelimet (oletus: järjestelmän omat)                                                                                                                                                    |
| `attachments`           | `true`                           | Tarkasta liitteet                                                                                                                                                                                              |
| `macros`                | `true`                           | Merkitse makrot, aktiiviset PDF:t ja RTF-objektit                                                                                                                                                              |
| `arbitrary`             | `true`                           | Aja [säännöt](scoring.md#rules)                                                                                                                                                                                |
| `authentication`        | `false`                          | `true` tai `{dnsServers, timeout, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([pisteytys](scoring.md#authentication))                                                                            |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; vastaukset säilytetään palvelu- ja otsakekohtaisesti, ja `cacheSize` koskee koko skanneria                                |
| `allowlist`, `denylist` |                                  | IP-osoitteet, verkkotunnukset tai osoitteet; lyhenne valinnalle `reputation` → [Sallittujen lista ja estolista](#allowlist-and-denylist)                                                                       |
| `clamav`                | `false`                          | `true` (oletussocket), `{socket}` tai `{host, port}`, jossa `timeout`: millisekunnit kaikille viestin liitteille (`60000`)                                                                                     |
| `llm`                   | `null`                           | [Kielimallin asetukset](llm.md#any-server-port-and-authentication), sekä `mode`, `minScore`, `maxScore`                                                                                                        |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: malli, jonka `classify([text])` vastaa kuten `@tensorflow-models/toxicity`                                                                                                         |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: malli, jonka `classify(imageBuffer)` vastaa kuten `nsfwjs`                                                                                                                         |
| `maxLength`             | `100000`                         | Luettavan leipätekstin merkkimäärä                                                                                                                                                                             |
| `timeout`               | `10000`                          | Kullekin verkkotarkistukselle sallitut millisekunnit; todennus ja kuvamalli saavat yhteensä näin paljon aikaa (ClamAV:lla on oma `clamav.timeout`)                                                             |
| `session`               | `{}`                             | SMTP-istunnon oletustiedot                                                                                                                                                                                     |

`scan()` ottaa myös valinnan `session`:

```js
await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',             // the client's IP address
    resolvedClientHostname: 'mx.example.com', // its verified reverse DNS name
    helo: 'mx.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

Palvelin, joka on jo tarkistanut SPF:n, DKIM:n, DMARCin ja ARC:n (kirjastolla [mailauth](https://github.com/postalsys/mailauth)), voi välittää tuloksensa valintana `authenticationResults`, jolloin ne pisteytetään tarkistamatta niitä uudelleen:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Sallittujen lista ja estolista

Estolista vertaa asiakkaan IP-osoitetta ja isäntänimeä, From-, kirjekuoren lähettäjä- ja Reply-To-osoitteita sekä niiden verkkotunnuksia, olivatpa ne mitä tahansa: estetyn verkkotunnuksen alainen nimi täsmää siihen, vaikka se ei olisi kelvollinen isäntänimi (kuten `a_b!.evil.example` tai nimi, jossa on yli 63 merkin pituinen osa), viimeisten 127 osansa ja 253 merkkinsä perusteella. Sallittujen lista, samoin kuin mainepalvelun sallittujen lista ja luotetut lähteet, vertaa vain sitä, mitä lähettäjä ei voi väärentää: asiakkaan IP-osoitetta ja varmennettua isäntänimeä (`remoteAddress`, `resolvedClientHostname`), From-osoitetta, kun DMARC hyväksyy sen verkkotunnuksen tai hyväksytty DKIM-allekirjoitus on linjassa sen kanssa (ja sen verkkotunnus on kelvollinen isäntänimi; väljästi, kuten DMARCissa: From-verkkotunnuksella ja allekirjoittavalla tai SPF-verkkotunnuksella on sama rekisteröitävä verkkotunnus, jota mailauth kutsuu DMARC-verkkotunnukseksi; aliverkkotunnuksen, kuten `news.example.com`, nimeävä merkintä kelpaa vain, kun kyseinen verkkotunnus, sen alainen tai sen yläpuolinen verkkotunnus on allekirjoittanut viestin tai läpäissyt SPF:n, ei toinen aliverkkotunnus kuten `evil.example.com` eikä julkinen pääte; rekisteröitävän verkkotunnuksen DMARC-hyväksyntä ilman mailauthin linjaustietoja kelpaa vain merkinnälle, joka nimeää rekisteröitävän verkkotunnuksen; tiukassa linjauksessa, kun verkkotunnuksen DMARC-tietueessa on `adkim=s` tai `aspf=s` millä tahansa kirjainkoolla tai välistyksellä, kelpaa vain From-verkkotunnuksen itsensä allekirjoitus tai SPF-hyväksyntä, ja ilman sellaista DMARC epäonnistuu), sekä kirjekuoren lähettäjää, kun SPF hyväksyy sen verkkotunnuksen. DKIM-allekirjoitus, joka kattaa vain viestirungon alun (rungon pituus, `l=`, on lyhyempi kuin runko: kuka tahansa voi lisätä tekstiä sen perään), ei kelpaa mihinkään, kuten ei myöskään sellaiseen perustuva DMARC-hyväksyntä, eikä mikään allekirjoitus kelpaa, kun DMARC epäonnistuu. Kohteessa `authenticationResults` annetut tulokset kelpaavat vain, kun ne nimeävät verkkotunnuksen, jolle ne hyväksyttiin, eikä verkkotunnus, joka ei ole isäntänimi (kuten `bank.example/x.attacker.example`, jonka URL-jäsentimet lukevat muodossa `bank.example`), kelpaa millekään, kuten ei myöskään sellaiseen perustuva DMARC-hyväksyntä. Kansainväliset verkkotunnukset täsmäävät kummassa tahansa muodossa: `bücher.example` tai `xn--bcher-kva.example`. Reply-To ei koskaan kelpaa. Salliaksesi verkkotunnuksen ota `authentication` käyttöön tai anna `authenticationResults`.

Jokainen merkintä on yksi IP-osoite, verkkotunnus tai sähköpostiosoite, ja sitä verrataan tarkasti: verkkotunnusmerkintä kattaa myös sen aliverkkotunnukset ja niiden osoitteet, mutta osoitealueita (`192.0.2.0/24`), jokerimerkkejä (`*.example.com`) tai kuvioita (`@example.com`) ei ole. IPv6-osoitteet täsmäävät missä tahansa muodossa (`2001:0db8::0001` on `2001:db8::1`, RFC 5952:n muoto), IPv6:een kuvattu IPv4-osoite (`::ffff:192.0.2.1`) täsmää IPv4-osoitteeseen, ja IPv6:ksi käännetty tai NAT64-etuliitteen alainen IPv4-osoite kirjoitetaan sen kanssa pistemuodossa (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), niin merkinnöissä kuin asiakkaiden osoitteissa.


## Metodit

| Metodi                               | Palauttaa                                                                            |
| ------------------------------------ | ------------------------------------------------------------------------------------ |
| `scan(source, options)`              | Tuloksen. `source` on Buffer, merkkijono, Uint8Array tai luettava virta              |
| `scanFile(path, options)`            | Viestitiedoston tuloksen                                                             |
| `learn(source, 'spam' \| 'ham')`     | Opettaa luokittimelle yhden viestin                                                  |
| `unlearn(source, 'spam' \| 'ham')`   | Kumoaa metodin `learn`                                                               |
| `saveModel(path, options)`           | Kirjoittaa luokittimen tiedostoon (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Käytössä olevan `Classifier`-olion tai `null`                                        |
| `getClassification(features)`        | Luokittimen tuomion metodin `getFeatures` piirteille                                 |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` viestistä          |
| `getTokens(text, locale)`            | Tekstin sanat                                                                        |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                           |
| `parse(source)`                      | `{raw, mail}`, jossa `mail` tulee mailparserilta (katso alta)                        |

`scan`, `parse`, `learn`, `unlearn` ja `getTokensAndMailFromSource` lukevat kaikki viestin samalla tavalla: MIME-jäsentimen rajat (yli 1000 osaa, osan otsake yli 1 Mt) ylittävästä viestistä luetaan niin paljon kuin jäsennin sallii. Teksti, jonka ensimmäinen rivi ei ole otsakekenttä (`Name: value` tai `From`-rivi, jolla jokainen viesti alkaa mbox-tiedostoissa), luetaan otsakkeettoman viestin rungoksi, joten `mail.text` on kyseinen teksti. Muut virheet heitetään.

Metodin `getFeatures` tuloksessa `text` on teksti, jonka sähköpostiohjelma näyttää ja josta sanat luetaan, ja `hidden` kertoo, kuinka monta merkkiä tekstiä HTML piilottaa. mailparser ei tässä tee HTML:stä tekstiä: `mail.text` sisältää vain pelkkää tekstiä olevat osat, ja se on tyhjä pelkästä HTML:stä koostuvassa viestissä; teksti, jonka sen HTML näyttää, on `getFeatures(mail).text`.

`scanner.metrics` sisältää arvot `totalScans`, `averageTime` ja `lastScanTime`.


## Tulos

```js
{
  isSpam: true,
  score: 16.25,
  threshold: 5,
  rejectThreshold: 15,
  action: 'reject',                       // 'accept', 'tag' or 'reject'
  message: 'Spam (BAYES_999, PHISHING_LOOKALIKE_DOMAIN, DECEPTIVE_LINK, FROM_NAME_BRAND)',
  tests: [
    {name: 'BAYES_999', score: 6.25, description: 'Classifier spam probability 99.9%'},
    {name: 'PHISHING_LOOKALIKE_DOMAIN', score: 5, description: '"paypa1-secure.top" imitates paypal by swapping characters'},
    // ...
  ],
  results: {
    classification: {probability, category, spam, ham, clues, coverage},
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    virusScanErrors: [], // attachments ClamAV could not scan: {filename, error}
    virusScanSkipped: [], // attachments larger than clamd accepts, not scanned: {filename, reason}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value, answers} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'], // the links checked, of the whole message up to phishing.maxLength
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser; mail.text: the plain text parts only */},
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

Kohteissa `phishing`, `attachments`, `executables`, `macros`, `viruses` ja `arbitrary` olevat löydökset ovat olioita, joilla on `type` ja `message`. `String(finding)` on viesti. Liitetyn viestin (`message/rfc822`, `.eml`) liitteet nimetään sen mukaan: `fw.eml/invoice.exe`. Virus, jonka ClamAV löytää tällaisesta liitteestä, raportoidaan vain sille, ei uudelleen sen sisältävälle liitetylle viestille. `virusScanErrors` luettelee liitteet, joita ClamAV ei voinut tarkistaa, muodossa `{filename, error}`: tällainen viesti voi sisältää viruksen, joten pidätä se toimittamisen sijaan. Milter ja sisältösuodatin lykkäävät sitä, ellei `onError` (`--on-error`) ole `accept`, ja jokainen palvelin merkitsee tällaisen eteenpäin välittämänsä viestin otsakkeella `X-Spam-Virus-Scan: failed`. `virusScanSkipped` luettelee liitteet, jotka ovat suurempia kuin clamd hyväksyy (sen `StreamMaxLength`), muodossa `{filename, reason}`: clamd hylkää ne joka yrityksellä, joten ne eivät ole virheitä, samoin kuin clamav-milter ohittaa tiedoston, joka ylittää sen `MaxFileSize`-rajan. Sen muiden rajojen (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`) ylitykset, joihin arkistopommi yltää, ovat virheitä.

Jokainen `dnsbl`-kohde sisältää listan `answers`-vastaukset (osoitteita alueelta 127.0.0.0/8; kukin lista dokumentoi niiden merkityksen). Vastaukset, joita listat antavat kyselyihin, jotka ne hylkäävät tai joihin ne eivät voi vastata, eivät ole listauksia, ei asiakkaan osoitteelle eikä linkkien verkkotunnuksille (`uribl`-löydökset kohteessa `phishing`): 127.255.255.x Spamhausilla (kuten 127.255.255.254 julkisen nimipalvelimen kautta tehdylle kyselylle ja 127.255.255.255 liian monille kyselyille), 127.0.1.255 Spamhaus DBL:llä, 127.0.0.255 millä tahansa listalla sekä 127.0.0.1 SURBLilla ja URIBLilla, jotka antavat sen estämilleen nimipalvelimille.


## Exportit

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export

import ArfParser from 'spamscanner/arf';
```

### Luokitin

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Valinta                                | Oletus         | Merkitys                                                                                                                                                                          |
| -------------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsonin s ja x: kuinka voimakkaasti harvinaisia piirteitä vedetään kohti arvoa 0,5                                                                                             |
| `minDistance`                          | `0.1`          | Piirteet, jotka ovat tätä lähempänä arvoa 0,5, ohitetaan                                                                                                                          |
| `maxClues`                             | `150`          | Viestiä kohden yhdistettävät vahvimmat piirteet                                                                                                                                   |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | `unsure`-alueen rajat                                                                                                                                                             |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Ham-viestit, joita kielellä tarvitaan täyteen varmuuteen, ja viidesosa niin monta roskapostiviestiä; vähemmän, kun `languageShare` kaikesta hamista tai roskapostista on vähemmän |
| `languagePrior`                        | `true`         | Punnitse sanoja niiden oman kielen määriä vasten                                                                                                                                  |

Käytettävissä ovat myös `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` ja `entries()`. `Classifier.fromJSON` tarkistaa mallin ja heittää vioittuneesta datasta `TypeError`-virheen, joka alkaa `Corrupt classifier model`. JSONissa ei ole arvoa `Infinity`, joten version 7.0.3 arvoksi `Infinity` tallentama asetus luetaan takaisin arvona `null`: se luetaan arvona `Infinity` asetuksille `maxClues`, `minDistance` ja `minLanguageExamples`, arvona `-Infinity` asetukselle `hamCutoff` (ei koskaan ham) ja arvona `Infinity` asetukselle `spamCutoff` (ei koskaan spam) sekä oletusarvona muille. `toJSON` tallentaa rajan, joka on 0:n ja 1:n ulkopuolella, arvona -1 tai 2, mikä toimii samoin. `loadModel` lukee tiedoston uudelleen, kun se muuttuu, ja `saveModel` kirjoittaa väliaikaisen tiedoston kautta.

### Koulutus

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` ottaa `{label, features}`-kohteita tai funktion `readExamples(sources)` tuloksen, joka lukee samat lähteet kuin `train`, ja palauttaa määrät, tarkkuuden (precision), saannin (recall), F1:n, osuvuuden (accuracy) sekä väärien positiivisten, väärien negatiivisten ja epävarmojen osuudet.

### Palvelimet

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

Milterin `onError` on sen vastaus, kun tarkistus epäonnistuu tai ClamAV ei voinut tarkistaa liitettä: `'tempfail'` (oletus) tai `'accept'`, joka välittää viestin eteenpäin merkittynä otsakkeella `X-Spam-Virus-Scan: failed` ilman lähettäjän lisäämiä `X-Spam-*`-otsakkeita.

### ARF-raportit

`spamscanner/arf` lukee ja kirjoittaa väärinkäytöspalauteraportteja (RFC 5965), muotoa, jolla postilaatikkopalvelujen tarjoajat ilmoittavat roskapostivalituksista:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders?.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()` palauttaa `null` sen sijaan, että heittäisi virheen viesteille, jotka eivät ole raportteja, ja `isArfMessage(mail)` tarkistaa jäsennetyn viestin. `originalHeaders` on `null` raportissa, jossa ei ole alkuperäistä viestiä. `create()` palauttaa merkkijonon, tai `Buffer`-olion, jos `originalMessage` on sellainen, jolloin sen tavut säilyvät merkistöstä riippumatta.
