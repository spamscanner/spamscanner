<!-- source: b3cc9f949acd -->

# API-viite

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Luo yksi skanneri ja käytä sitä uudelleen: se lataa mallin kerran ja tallentaa DNS- ja kielimallivastaukset välimuistiin.


## Valinnat

Jokaisen valinnan voi antaa konstruktorille. Useimmat voi antaa myös `scan()`-kutsulle yksittäistä viestiä varten, jolloin ne yhdistetään konstruktorin valintojen päälle.

| Valinta                 | Oletus                           | Merkitys                                                                                                                           |
| ----------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Pistemäärä, josta alkaen viesti on roskapostia                                                                                     |
| `rejectThreshold`       | `15`                             | Pistemäärä, josta alkaen `action` on `reject`                                                                                      |
| `scores`                | `{}`                             | Pisteet testiä kohden: asetusavaimet tai testien nimet ([testit ja pisteet](scoring.md))                                           |
| `classifier`            | mukana tuleva malli              | `Classifier`, malliolio, mallitiedoston polku tai `false`                                                                          |
| `classifierOptions`     | `{}`                             | Mukana tulevan mallin valinnat (katso [Luokitin](#classifier))                                                                     |
| `allowedLanguages`      | `[]`                             | ISO 639-1 -koodit; muut kielet saavat testin `LANGUAGE_NOT_ALLOWED`                                                                |
| `phishing.cloudflare`   | `true`                           | Kysy Cloudflaren suodattavilta DNS-palveluilta linkkien isännistä                                                                  |
| `phishing.adult`        | `true`                           | Kysy myös perhepalvelulta, joka estää aikuissivustot                                                                               |
| `phishing.maxHosts`     | `25`                             | Viestiä kohden tarkistettavien linkki-isäntien määrä                                                                               |
| `phishing.homograph`    | `{}`                             | `brands` (korvaa sisäänrakennetun luettelon), `extraBrands`, `allowlist` (verkkotunnukset, joita ei koskaan merkitä), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS-estolistojen vyöhykkeet asiakkaan IP-osoitteelle ja linkkien verkkotunnuksille                                                 |
| `dns`                   | `{servers: null, timeout: 3000}` | DNS-tarkistusten nimipalvelimet (oletus: järjestelmän omat)                                                                        |
| `attachments`           | `true`                           | Tarkasta liitteet                                                                                                                  |
| `macros`                | `true`                           | Merkitse makrot, aktiiviset PDF:t ja RTF-objektit                                                                                  |
| `arbitrary`             | `true`                           | Aja [säännöt](scoring.md#rules)                                                                                                    |
| `authentication`        | `false`                          | `true` tai `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                                            |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                                  |
| `allowlist`, `denylist` |                                  | IP-osoitteet, verkkotunnukset tai osoitteet; lyhenne valinnalle `reputation`                                                       |
| `clamav`                | `false`                          | `true` (oletussocket), `{socket}` tai `{host, port}`                                                                               |
| `llm`                   | `null`                           | [Kielimallin asetukset](llm.md#any-server-port-and-authentication), sekä `mode`, `minScore`, `maxScore`                            |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: malli, jonka `classify([text])` vastaa kuten `@tensorflow-models/toxicity`                             |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: malli, jonka `classify(imageBuffer)` vastaa kuten `nsfwjs`                                             |
| `maxLength`             | `100000`                         | Luettavan leipätekstin merkkimäärä                                                                                                 |
| `timeout`               | `10000`                          | Kullekin verkkotarkistukselle sallitut millisekunnit                                                                               |
| `session`               | `{}`                             | SMTP-istunnon oletustiedot                                                                                                         |

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
| `getFeatures(mail)`                  | `{features, words, language, script, links}` jäsennetylle viestille                  |
| `getTokens(text, locale)`            | Tekstin sanat                                                                        |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                           |
| `parse(source)`                      | `{raw, mail}`, jossa `mail` tulee mailparserilta                                     |

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
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'],
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser */},
  version: '7.0.0',
  metrics: {totalTime: 42},
}
```

Kohteissa `phishing`, `attachments`, `executables`, `macros`, `viruses` ja `arbitrary` olevat löydökset ovat olioita, joilla on `type` ja `message`. `String(finding)` on viesti.


## Exportit

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';

import ArfParser from 'spamscanner/arf';
```

### Luokitin

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Valinta                                | Oletus         | Merkitys                                                                              |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsonin s ja x: kuinka voimakkaasti harvinaisia piirteitä vedetään kohti arvoa 0,5 |
| `minDistance`                          | `0.1`          | Piirteet, jotka ovat tätä lähempänä arvoa 0,5, ohitetaan                              |
| `maxClues`                             | `150`          | Viestiä kohden yhdistettävät vahvimmat piirteet                                       |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | `unsure`-alueen rajat                                                                 |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Kunkin luokan viestit, joita kielellä tarvitaan täyteen varmuuteen                    |
| `languagePrior`                        | `true`         | Punnitse sanoja niiden oman kielen määriä vasten                                      |

Käytettävissä ovat myös `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` ja `entries()`.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARF-raportit

`spamscanner/arf` lukee ja kirjoittaa väärinkäytöspalauteraportteja (RFC 5965), muotoa, jolla postilaatikkopalvelujen tarjoajat ilmoittavat roskapostivalituksista:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()` palauttaa `null` sen sijaan, että heittäisi virheen viesteille, jotka eivät ole raportteja, ja `isArfMessage(mail)` tarkistaa jäsennetyn viestin.
