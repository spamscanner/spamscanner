<!-- source: b19ea85ceb6d -->

# API-referentie

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Maak één scanner aan en hergebruik die: hij laadt het model één keer en cachet DNS-antwoorden en antwoorden van het taalmodel.

Typedeclaraties zijn inbegrepen. Ze vereisen TypeScript 4.7 of hoger met `import`, en 5.3 of hoger met `require`.


## Opties

Elke optie kan aan de constructor worden meegegeven. De meeste kunnen ook voor één bericht aan `scan()` worden meegegeven, en worden dan over die van de constructor heen samengevoegd. Opties die als `undefined` worden doorgegeven, houden hun standaardwaarde. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` en `strictIDNDetection` worden alleen door de constructor gelezen; een modelbestand of modelobject in `classifier` wordt daar ingelezen, zodat een ontbrekend of beschadigd model meteen een fout geeft.

| Optie                   | Standaard                        | Betekenis                                                                                                                                                                                          |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Score waarbij een bericht spam is                                                                                                                                                                  |
| `rejectThreshold`       | `15`                             | Score waarbij `action` gelijk is aan `reject`                                                                                                                                                      |
| `scores`                | `{}`                             | Punten per test: instellingssleutels of testnamen ([tests en scores](scoring.md))                                                                                                                  |
| `classifier`            | meegeleverd model                | Een `Classifier`, een modelobject, het pad van een modelbestand, of `false`                                                                                                                        |
| `classifierOptions`     | `{}`                             | Opties voor het meegeleverde model (zie [Classifier](#classifier))                                                                                                                                 |
| `allowedLanguages`      | `[]`                             | ISO 639-1-codes (`no` wordt gelezen als `nb`, `fil` als `tl`, en de oude `iw`, `in`, `ji` als `he`, `id`, `yi`); andere talen krijgen `LANGUAGE_NOT_ALLOWED`                                       |
| `phishing.cloudflare`   | `true`                           | Vraag de filterende resolvers van Cloudflare naar linkhosts                                                                                                                                        |
| `phishing.adult`        | `true`                           | Vraag het ook aan de gezinsresolver, die volwassenensites blokkeert                                                                                                                                |
| `phishing.maxHosts`     | `25`                             | Aantal linkhosts dat per bericht wordt opgezocht                                                                                                                                                   |
| `phishing.maxLength`    | `1000000`                        | Tekens van de tekst die op links worden gelezen (het dubbele bij HTML); langere tekst zet `results.linksTruncated`; `Infinity`, of iets anders dan een positief getal, betekent de standaardwaarde |
| `phishing.homograph`    | `{}`                             | `brands` (vervangt de ingebouwde lijst), `extraBrands`, `allowlist` (domeinen die nooit worden gemarkeerd), `strictMode`                                                                           |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zones van DNS-blocklists voor het IP-adres van de client en voor linkdomeinen                                                                                                                      |
| `dns`                   | `{servers: null, timeout: 3000}` | Nameservers voor DNS-controles (standaard: die van het systeem)                                                                                                                                    |
| `attachments`           | `true`                           | Bijlagen inspecteren                                                                                                                                                                               |
| `macros`                | `true`                           | Macro's, actieve pdf's en RTF-objecten markeren                                                                                                                                                    |
| `arbitrary`             | `true`                           | De [regels](scoring.md#rules) uitvoeren                                                                                                                                                            |
| `authentication`        | `false`                          | `true`, of `{dnsServers, timeout, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([scoring](scoring.md#authentication))                                                                  |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; antwoorden worden per dienst en headers bewaard, en `cacheSize` geldt voor de hele scanner                    |
| `allowlist`, `denylist` |                                  | IP-adressen, domeinen of adressen; verkorte vorm van `reputation` → [Toestaanlijst en blokkeerlijst](#allowlist-and-denylist)                                                                      |
| `clamav`                | `false`                          | `true` (standaardsocket), `{socket}` of `{host, port}`, met `timeout`: milliseconden voor alle bijlagen van een bericht samen (`60000`)                                                            |
| `llm`                   | `null`                           | [Instellingen voor het taalmodel](llm.md#any-server-port-and-authentication), met `mode`, `minScore`, `maxScore`                                                                                   |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: een model waarvan `classify([text])` antwoordt zoals `@tensorflow-models/toxicity`                                                                                     |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: een model waarvan `classify(imageBuffer)` antwoordt zoals `nsfwjs`                                                                                                     |
| `maxLength`             | `100000`                         | Aantal tekens bodytekst dat wordt gelezen                                                                                                                                                          |
| `timeout`               | `10000`                          | Toegestane milliseconden per netwerkcontrole; authenticatie en het beeldmodel krijgen in totaal zo lang (ClamAV heeft een eigen `clamav.timeout`)                                                  |
| `session`               | `{}`                             | Standaardgegevens van de SMTP-sessie                                                                                                                                                               |

`scan()` accepteert ook `session`:

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

Een server die SPF, DKIM, DMARC en ARC al heeft gecontroleerd (met [mailauth](https://github.com/postalsys/mailauth)), kan de resultaten als `authenticationResults` meegeven; die worden dan gescoord in plaats van opnieuw gecontroleerd:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Toestaanlijst en blokkeerlijst

De blokkeerlijst vergelijkt het IP-adres en de hostnaam van de client, de From-, envelopafzender- en Reply-To-adressen en hun domeinen, wat ze ook zijn: een naam onder een geblokkeerd domein komt ermee overeen, ook als het geen geldige hostnaam is (zoals `a_b!.evil.example`, of een naam met een label van meer dan 63 tekens), op basis van de laatste 127 labels en 253 tekens. De toestaanlijst, en de toestaanlijst en vertrouwde bronnen van een reputatiedienst, vergelijken alleen wat een afzender niet kan vervalsen: het IP-adres en de geverifieerde hostnaam van de client (`remoteAddress`, `resolvedClientHostname`), een From-adres wanneer DMARC slaagt voor het domein of een geldige DKIM-handtekening ermee is uitgelijnd (en het een geldige hostnaam is; relaxed, zoals bij DMARC: het From-domein en het ondertekenende of SPF-domein hebben hetzelfde registreerbare domein, dat mailauth als het DMARC-domein noemt; een vermelding die een subdomein noemt, zoals `news.example.com`, telt alleen wanneer dat domein, een domein daaronder of een bovenliggend domein het bericht ondertekende of voor SPF slaagde, niet een ander subdomein zoals `evil.example.com`, en ook geen publiek achtervoegsel; een DMARC-pass voor het registreerbare domein zonder de uitlijningsgegevens van mailauth telt alleen voor een vermelding die het registreerbare domein noemt; bij strikte uitlijning, `adkim=s` of `aspf=s` in het DMARC-record van het domein, in welke hoofdletters of spatiëring ook, telt alleen een handtekening of SPF-pass van het From-domein zelf, en zonder die faalt DMARC), en de envelopafzender wanneer SPF slaagt voor het domein. Een DKIM-handtekening van alleen het begin van de body (een bodylengte, `l=`, korter dan de body: iedereen kan er tekst achter zetten) telt nergens voor, net als een DMARC-pass die op zo'n handtekening berust, en geen enkele handtekening telt wanneer DMARC faalt. Resultaten die in `authenticationResults` worden doorgegeven, tellen alleen mee als ze het domein noemen waarvoor ze slaagden, en een domein dat geen hostnaam is (zoals `bank.example/x.attacker.example`, dat URL-parsers lezen als `bank.example`) telt nergens voor, net als een DMARC-pass die op zo'n domein berust. Internationale domeinen komen in beide vormen overeen: `bücher.example` of `xn--bcher-kva.example`. Reply-To telt nooit mee. Zet `authentication` aan of geef `authenticationResults` door om een domein toe te staan.

Elke vermelding is één IP-adres, domein of e-mailadres, exact vergeleken: een domeinvermelding dekt ook de subdomeinen ervan en de adressen daarop, maar er zijn geen adresbereiken (`192.0.2.0/24`), jokertekens (`*.example.com`) of patronen (`@example.com`). IPv6-adressen komen in elke vorm overeen (`2001:0db8::0001` is `2001:db8::1`, de vorm van RFC 5952), een IPv4-adres dat in IPv6 is gemapt (`::ffff:192.0.2.1`) komt overeen met het IPv4-adres, en een IPv4-adres dat naar IPv6 is vertaald of onder het NAT64-voorvoegsel staat, wordt geschreven met dat IPv4-adres in puntnotatie (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), in vermeldingen en clientadressen gelijk.


## Methoden

| Methode                              | Geeft terug                                                                                |
| ------------------------------------ | ------------------------------------------------------------------------------------------ |
| `scan(source, options)`              | Het resultaat. `source` is een Buffer, string, Uint8Array of readable stream               |
| `scanFile(path, options)`            | Het resultaat voor een berichtbestand                                                      |
| `learn(source, 'spam' \| 'ham')`     | Leert de classifier één bericht                                                            |
| `unlearn(source, 'spam' \| 'ham')`   | Maakt `learn` ongedaan                                                                     |
| `saveModel(path, options)`           | Schrijft de classifier naar een bestand (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | De `Classifier` die in gebruik is, of `null`                                               |
| `getClassification(features)`        | Het oordeel van de classifier voor kenmerken uit `getFeatures`                             |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` van een bericht          |
| `getTokens(text, locale)`            | De woorden van een tekst                                                                   |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                                 |
| `parse(source)`                      | `{raw, mail}`, met `mail` uit mailparser (zie hieronder)                                   |

`scan`, `parse`, `learn`, `unlearn` en `getTokensAndMailFromSource` lezen een bericht allemaal op dezelfde manier: een bericht buiten de limieten van de MIME-parser (meer dan 1000 delen, een header van een deel boven 1 MB) wordt gelezen voor zover de parser toelaat. Tekst waarvan de eerste regel geen headerveld is (`Name: value`, of de `From`-regel waarmee elk bericht in mbox-bestanden begint), wordt gelezen als de body van een bericht zonder header, dus `mail.text` is die tekst. Andere fouten worden gegooid.

In `getFeatures` is `text` de tekst die een mailclient toont, waaruit de woorden worden gelezen, en `hidden` hoeveel tekens tekst de HTML verbergt. mailparser maakt hier geen tekst van HTML: `mail.text` bevat alleen de platte-tekstdelen en is leeg bij een bericht dat alleen uit HTML bestaat; de tekst die de HTML toont, is `getFeatures(mail).text`.

`scanner.metrics` bevat `totalScans`, `averageTime` en `lastScanTime`.


## Het resultaat

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

Bevindingen in `phishing`, `attachments`, `executables`, `macros`, `viruses` en `arbitrary` zijn objecten met een `type` en een `message`. `String(finding)` is het bericht. Bijlagen van een bijgevoegd bericht (`message/rfc822`, `.eml`) krijgen de naam daarvan: `fw.eml/invoice.exe`. Een virus dat ClamAV in zo'n bijlage vindt, wordt alleen voor die bijlage gemeld, niet nog eens voor het bijgevoegde bericht dat haar bevat. `virusScanErrors` somt de bijlagen op die ClamAV niet kon scannen, als `{filename, error}`: zo'n bericht kan een virus bevatten, houd het dus vast in plaats van het af te leveren. De milter en het contentfilter stellen zo'n bericht uit, tenzij `onError` (`--on-error`) `accept` is, en elke server markeert zo'n bericht dat hij doorgeeft met `X-Spam-Virus-Scan: failed`. `virusScanSkipped` somt de bijlagen op die groter zijn dan clamd accepteert (zijn `StreamMaxLength`), als `{filename, reason}`: clamd weigert ze bij elke poging, dus gelden ze, zoals clamav-milter een bestand boven zijn `MaxFileSize` overslaat, niet als fout. De andere limieten van clamd (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), die een archiefbom bereikt, gelden wel als fout.

Elk `dnsbl`-item bevat de `answers` van de lijst (adressen in 127.0.0.0/8, waarvan elke lijst de betekenis documenteert). De antwoorden die lijsten geven op vragen die ze weigeren of niet kunnen beantwoorden, zijn geen vermeldingen, voor het adres van de client of voor linkdomeinen (`uribl`-bevindingen in `phishing`): 127.255.255.x bij Spamhaus (zoals 127.255.255.254 voor een vraag via een publieke resolver, en 127.255.255.255 voor te veel vragen), 127.0.1.255 bij de Spamhaus DBL, 127.0.0.255 bij elke lijst, en 127.0.0.1 bij SURBL en URIBL, die dat antwoord geven aan resolvers die ze blokkeren.


## Exports

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

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Optie                                  | Standaard      | Betekenis                                                                                                                                                                      |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `strength`, `unknown`                  | `0.45`, `0.5`  | De s en x van Robinson: hoe sterk zeldzame kenmerken naar 0,5 worden getrokken                                                                                                 |
| `minDistance`                          | `0.1`          | Kenmerken die dichter bij 0,5 liggen dan dit, worden genegeerd                                                                                                                 |
| `maxClues`                             | `150`          | Aantal sterkste kenmerken dat per bericht wordt gecombineerd                                                                                                                   |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Grenzen van het bereik `unsure`                                                                                                                                                |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Aantal hamberichten in een taal dat nodig is voor volledige zekerheid, en een vijfde daarvan aan spamberichten; minder wanneer `languageShare` van alle ham of spam kleiner is |
| `languagePrior`                        | `true`         | Woorden wegen tegen de aantallen van hun eigen taal                                                                                                                            |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` en `entries()` zijn ook beschikbaar. `Classifier.fromJSON` controleert het model en gooit bij beschadigde gegevens een `TypeError` die begint met `Corrupt classifier model`. JSON kent geen `Infinity`, dus een optie die versie 7.0.3 als `Infinity` heeft opgeslagen, wordt teruggelezen als `null`: die wordt gelezen als `Infinity` voor `maxClues`, `minDistance` en `minLanguageExamples`, als `-Infinity` voor `hamCutoff` (nooit ham) en `Infinity` voor `spamCutoff` (nooit spam), en als de standaardwaarde voor de andere. `toJSON` slaat een drempel buiten 0 en 1 op als -1 of 2, wat hetzelfde werkt. `loadModel` leest een bestand opnieuw wanneer het verandert, en `saveModel` schrijft via een tijdelijk bestand.

### Training

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` accepteert items met `{label, features}`, of `readExamples(sources)`, dat dezelfde bronnen leest als `train`, en geeft aantallen, precisie, recall, F1, accuracy en de percentages fout-positieven, fout-negatieven en onzekere berichten terug.

### Servers

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

De `onError` van de milter is zijn antwoord wanneer een scan mislukt of ClamAV een bijlage niet kon scannen: `'tempfail'` (de standaard) of `'accept'`, dat het bericht doorgeeft gemarkeerd met `X-Spam-Virus-Scan: failed`, zonder de `X-Spam-*`-headers die de afzender toevoegde.

### ARF-rapporten

`spamscanner/arf` leest en schrijft abuse feedback reports (RFC 5965), het formaat dat mailboxproviders gebruiken om spamklachten te melden:

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

`ArfParser.tryParse()` geeft `null` terug in plaats van een fout te gooien bij berichten die geen rapport zijn, en `isArfMessage(mail)` controleert een geparsed bericht. `originalHeaders` is `null` bij een rapport zonder het oorspronkelijke bericht. `create()` geeft een string terug, of een `Buffer` als `originalMessage` er een is, zodat de bytes behouden blijven, welke tekenset ze ook hebben.
