<!-- source: b19ea85ceb6d -->

# API-referanse

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Opprett én skanner og gjenbruk den: den laster inn modellen én gang og mellomlagrer svar fra DNS og språkmodeller.

Typedeklarasjoner er inkludert. De krever TypeScript 4.7 eller nyere med `import`, og 5.3 eller nyere med `require`.


## Alternativer

Alle alternativer kan sendes til konstruktøren. De fleste kan også sendes til `scan()` for én melding, og flettes da inn over konstruktørens. Alternativer gitt som `undefined` beholder standardverdien. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` og `strictIDNDetection` leses bare av konstruktøren; en modellfil eller et modellobjekt gitt som `classifier` leses der, så en manglende eller skadet modell gir feil med en gang.

| Alternativ              | Standard                         | Betydning                                                                                                                                                                            |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `threshold`             | `5`                              | Poengsum der en melding er spam                                                                                                                                                      |
| `rejectThreshold`       | `15`                             | Poengsum der `action` er `reject`                                                                                                                                                    |
| `scores`                | `{}`                             | Poeng per test: innstillingsnøkler eller testnavn ([tester og poeng](scoring.md))                                                                                                    |
| `classifier`            | medfølgende modell               | En `Classifier`, et modellobjekt, en sti til en modellfil eller `false`                                                                                                              |
| `classifierOptions`     | `{}`                             | Alternativer for den medfølgende modellen (se [Klassifiserer](#classifier))                                                                                                          |
| `allowedLanguages`      | `[]`                             | ISO 639-1-koder (`no` leses som `nb`, `fil` som `tl`, og de gamle `iw`, `in`, `ji` som `he`, `id`, `yi`); andre språk får `LANGUAGE_NOT_ALLOWED`                                     |
| `phishing.cloudflare`   | `true`                           | Spør Cloudflares filtrerende resolvere om vertene i lenker                                                                                                                           |
| `phishing.adult`        | `true`                           | Spør også familieresolveren, som blokkerer voksennettsteder                                                                                                                          |
| `phishing.maxHosts`     | `25`                             | Lenkeverter som slås opp per melding                                                                                                                                                 |
| `phishing.maxLength`    | `1000000`                        | Tegn i teksten som leses for lenker (dobbelt så mange i HTML); lengre tekst setter `results.linksTruncated`; `Infinity`, eller noe annet enn et positivt tall, betyr standardverdien |
| `phishing.homograph`    | `{}`                             | `brands` (erstatter den innebygde listen), `extraBrands`, `allowlist` (domener som aldri flagges), `strictMode`                                                                      |
| `dnsbl`                 | `{ip: [], domain: []}`           | Soner for DNS-blokkeringslister for klientens IP og for domener i lenker                                                                                                             |
| `dns`                   | `{servers: null, timeout: 3000}` | Navneservere for DNS-sjekker (standard: systemets)                                                                                                                                   |
| `attachments`           | `true`                           | Undersøk vedlegg                                                                                                                                                                     |
| `macros`                | `true`                           | Flagg makroer, aktive PDF-er og RTF-objekter                                                                                                                                         |
| `arbitrary`             | `true`                           | Kjør [reglene](scoring.md#rules)                                                                                                                                                     |
| `authentication`        | `false`                          | `true`, eller `{dnsServers, timeout, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([poengsetting](scoring.md#authentication))                                            |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; svar lagres per tjeneste og headere, og `cacheSize` gjelder for hele skanneren                  |
| `allowlist`, `denylist` |                                  | IP-adresser, domener eller adresser; kortform for `reputation` → [Tillatelsesliste og blokkeringsliste](#allowlist-and-denylist)                                                     |
| `clamav`                | `false`                          | `true` (standard-socket), `{socket}` eller `{host, port}`, med `timeout`: millisekunder for alle vedleggene i en melding til sammen (`60000`)                                        |
| `llm`                   | `null`                           | [Innstillinger for språkmodellen](llm.md#any-server-port-and-authentication), med `mode`, `minScore`, `maxScore`                                                                     |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: en modell der `classify([text])` svarer som `@tensorflow-models/toxicity`                                                                                |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: en modell der `classify(imageBuffer)` svarer som `nsfwjs`                                                                                                |
| `maxLength`             | `100000`                         | Antall tegn av brødteksten som leses                                                                                                                                                 |
| `timeout`               | `10000`                          | Millisekunder tillatt for hver nettverkssjekk; autentisering og bildemodellen får så lang tid totalt (ClamAV har sin egen `clamav.timeout`)                                          |
| `session`               | `{}`                             | Standardopplysninger om SMTP-økten                                                                                                                                                   |

`scan()` tar også imot `session`:

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

En server som allerede har sjekket SPF, DKIM, DMARC og ARC (med [mailauth](https://github.com/postalsys/mailauth)), kan sende resultatene som `authenticationResults`, og da gis de poeng i stedet for å sjekkes på nytt:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Tillatelsesliste og blokkeringsliste

Blokkeringslisten sammenligner klientens IP-adresse og vertsnavn, From-, konvoluttavsender- og Reply-To-adressene og domenene deres, uansett hva de er: et navn under et blokkert domene samsvarer med det selv om det ikke er et gyldig vertsnavn (som `a_b!.evil.example`, eller et navn med en etikett på mer enn 63 tegn), etter de siste 127 etikettene og 253 tegnene. Tillatelseslisten, og et omdømmetjenestes tillatelsesliste og sannhetskilder, sammenligner bare det en avsender ikke kan forfalske: klientens IP-adresse og verifiserte vertsnavn (`remoteAddress`, `resolvedClientHostname`), en From-adresse når DMARC godkjenner domenet eller en gyldig DKIM-signatur er justert med den (og det er et gyldig vertsnavn; avslappet, som i DMARC: From-domenet og det signerende domenet eller SPF-domenet har samme registrerbare domene, som mailauth oppgir som DMARC-domenet; en oppføring som angir et underdomene, som `news.example.com`, teller bare når det domenet, et domene under det eller et overordnet domene signerte meldingen eller besto SPF, ikke et annet underdomene som `evil.example.com`, og heller ikke et offentlig suffiks; en DMARC-godkjenning for det registrerbare domenet uten mailauths justeringsdetaljer teller bare for en oppføring som angir det registrerbare domenet; ved streng justering, `adkim=s` eller `aspf=s` i domenets DMARC-post, uansett store og små bokstaver eller mellomrom, teller bare en signatur eller SPF-godkjenning for selve From-domenet, og uten en slik feiler DMARC), og konvoluttavsenderen når SPF godkjenner domenet. En DKIM-signatur av bare begynnelsen av meldingsteksten (en tekstlengde, `l=`, kortere enn meldingsteksten: hvem som helst kan legge til tekst etter den) teller ikke for noe, det gjør heller ikke en DMARC-godkjenning som bygger på en slik signatur, og ingen signatur teller når DMARC feiler. Resultater som gis i `authenticationResults`, teller bare når de oppgir domenet de ble godkjent for, og et domene som ikke er et vertsnavn (som `bank.example/x.attacker.example`, som URL-parsere leser som `bank.example`), teller ikke for noe, og det gjør heller ikke en DMARC-godkjenning som bygger på et slikt domene. Internasjonale domener samsvarer i begge former: `bücher.example` eller `xn--bcher-kva.example`. Reply-To teller aldri. For å tillate et domene, slå på `authentication` eller gi `authenticationResults`.

Hver oppføring er én IP-adresse, ett domene eller én e-postadresse, sammenlignet nøyaktig: en domeneoppføring dekker også underdomenene og adressene på dem, men det finnes ingen adresseområder (`192.0.2.0/24`), jokertegn (`*.example.com`) eller mønstre (`@example.com`). IPv6-adresser samsvarer i alle former (`2001:0db8::0001` er `2001:db8::1`, formen i RFC 5952), en IPv4-adresse tilordnet i IPv6 (`::ffff:192.0.2.1`) samsvarer med IPv4-adressen, og en IPv4-adresse oversatt til IPv6 eller under NAT64-prefikset skrives med IPv4-adressen i punktnotasjon (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), både i oppføringer og i klientadresser.


## Metoder

| Metode                               | Returnerer                                                                            |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Resultatet. `source` er en Buffer, en streng, en Uint8Array eller en lesbar strøm     |
| `scanFile(path, options)`            | Resultatet for en meldingsfil                                                         |
| `learn(source, 'spam' \| 'ham')`     | Lærer klassifisereren opp på én melding                                               |
| `unlearn(source, 'spam' \| 'ham')`   | Angrer `learn`                                                                        |
| `saveModel(path, options)`           | Skriver klassifisereren til en fil (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | `Classifier` som er i bruk, eller `null`                                              |
| `getClassification(features)`        | Klassifisererens vurdering av egenskaper fra `getFeatures`                            |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` for en melding      |
| `getTokens(text, locale)`            | Ordene i en tekst                                                                     |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                            |
| `parse(source)`                      | `{raw, mail}`, med `mail` fra mailparser (se nedenfor)                                |

`scan`, `parse`, `learn`, `unlearn` og `getTokensAndMailFromSource` leser alle en melding på samme måte: en melding som går ut over MIME-parserens grenser (mer enn 1000 deler, en dels header over 1 MB), leses så langt parseren tillater. Tekst der første linje ikke er et headerfelt (`Name: value`, eller `From`-linjen som starter hver melding i mbox-filer), leses som meldingsteksten i en melding uten header, så `mail.text` er den teksten. Andre feil kastes.

I `getFeatures` er `text` teksten en e-postklient viser, som ordene leses fra, og `hidden` hvor mange tegn tekst HTML-en skjuler. mailparser lager ikke tekst av HTML her: `mail.text` inneholder bare rentekstdelene, og er tom for en melding som bare består av HTML; teksten HTML-en viser, er `getFeatures(mail).text`.

`scanner.metrics` inneholder `totalScans`, `averageTime` og `lastScanTime`.


## Resultatet

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

Funn i `phishing`, `attachments`, `executables`, `macros`, `viruses` og `arbitrary` er objekter med en `type` og en `message`. `String(finding)` er meldingen. Vedlegg i en vedlagt melding (`message/rfc822`, `.eml`) får navn etter den: `fw.eml/invoice.exe`. Et virus ClamAV finner i et slikt vedlegg, rapporteres bare for det, ikke på nytt for den vedlagte meldingen som inneholder det. `virusScanErrors` lister vedleggene ClamAV ikke kunne skanne, som `{filename, error}`: en slik melding kan inneholde virus, så hold den tilbake i stedet for å levere den. Milteren og innholdsfilteret utsetter en slik melding med mindre `onError` (`--on-error`) er `accept`, og alle servere merker en slik melding de sender videre, med `X-Spam-Virus-Scan: failed`. `virusScanSkipped` lister vedleggene som er større enn clamd godtar (dens `StreamMaxLength`), som `{filename, reason}`: clamd avviser dem ved hvert forsøk, så de regnes, slik clamav-milter hopper over en fil over sin `MaxFileSize`, ikke som feil. De andre grensene til clamd (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), som en arkivbombe når, regnes som feil.

Hvert `dnsbl`-element har listens `answers` (adresser i 127.0.0.0/8, der hver liste dokumenterer betydningen). Svarene lister gir på spørringer de avviser eller ikke kan besvare, er ikke oppføringer, verken for klientens adresse eller for lenkedomener (`uribl`-funn i `phishing`): 127.255.255.x hos Spamhaus (som 127.255.255.254 for en spørring gjennom en offentlig resolver, og 127.255.255.255 for for mange spørringer), 127.0.1.255 hos Spamhaus DBL, 127.0.0.255 hos alle lister, og 127.0.0.1 hos SURBL og URIBL, som gir det svaret til resolvere de blokkerer.


## Eksporter

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

### Klassifiserer

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Alternativ                             | Standard       | Betydning                                                                                                                                               |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsons s og x: hvor sterkt sjeldne egenskaper trekkes mot 0,5                                                                                        |
| `minDistance`                          | `0.1`          | Egenskaper nærmere 0,5 enn dette ignoreres                                                                                                              |
| `maxClues`                             | `150`          | De sterkeste egenskapene som kombineres per melding                                                                                                     |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Grensene for `unsure`-området                                                                                                                           |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Ham-meldinger som trengs på et språk for full tillit, og en femtedel så mange spam-meldinger; færre når `languageShare` av all ham eller spam er mindre |
| `languagePrior`                        | `true`         | Vei ord mot tellingene for deres eget språk                                                                                                             |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` og `entries()` er også tilgjengelige. `Classifier.fromJSON` kontrollerer modellen og kaster en `TypeError` som begynner med `Corrupt classifier model` ved skadede data. JSON har ingen `Infinity`, så et alternativ lagret som `Infinity` av versjon 7.0.3 leses tilbake som `null`: det leses som `Infinity` for `maxClues`, `minDistance` og `minLanguageExamples`, som `-Infinity` for `hamCutoff` (aldri ham) og `Infinity` for `spamCutoff` (aldri spam), og som standardverdien for de andre. `toJSON` lagrer en terskel utenfor 0 og 1 som -1 eller 2, noe som virker på samme måte. `loadModel` leser en fil på nytt når den endres, og `saveModel` skriver via en midlertidig fil.

### Trening

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` tar imot `{label, features}`-elementer, eller `readExamples(sources)`, som leser de samme kildene som `train`, og returnerer antall, presisjon, gjenkalling, F1, nøyaktighet og andelene falske positiver, falske negativer og usikre.

### Servere

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

Milterens `onError` er svaret når en skanning mislykkes eller ClamAV ikke kunne skanne et vedlegg: `'tempfail'` (standard) eller `'accept'`, som sender meldingen videre merket med `X-Spam-Virus-Scan: failed`, uten `X-Spam-*`-headerne avsenderen la til.

### ARF-rapporter

`spamscanner/arf` leser og skriver rapporter om misbruk (RFC 5965), formatet e-postleverandører bruker til å rapportere spamklager:

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

`ArfParser.tryParse()` returnerer `null` i stedet for å kaste en feil for meldinger som ikke er rapporter, og `isArfMessage(mail)` sjekker en tolket melding. `originalHeaders` er `null` for en rapport uten den opprinnelige meldingen. `create()` returnerer en streng, eller en `Buffer` når `originalMessage` er det, slik at bytene bevares uansett tegnsett.
