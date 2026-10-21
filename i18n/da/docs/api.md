<!-- source: e15795fd8287 -->

# API-reference

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Opret én scanner, og genbrug den: den indlæser modellen én gang og cacher svar fra DNS og sprogmodeller.

Typeerklæringer følger med. De kræver TypeScript 4.7 eller nyere med `import` og 5.3 eller nyere med `require`.


## Indstillinger

Alle indstillinger kan gives til konstruktøren. De fleste kan også gives til `scan()` for en enkelt besked, og de flettes da oven på konstruktørens. Indstillinger givet som `undefined` beholder deres standardværdier. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` og `strictIDNDetection` læses kun af konstruktøren; en modelfil eller et modelobjekt givet som `classifier` læses dér, så en manglende eller beskadiget model giver fejl med det samme.

| Indstilling             | Standard                         | Betydning                                                                                                                                                                        |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Score, hvor en besked er spam                                                                                                                                                    |
| `rejectThreshold`       | `15`                             | Score, hvor `action` er `reject`                                                                                                                                                 |
| `scores`                | `{}`                             | Point pr. test: indstillingsnøgler eller testnavne ([test og scorer](scoring.md))                                                                                                |
| `classifier`            | medfølgende model                | En `Classifier`, et modelobjekt, en sti til en modelfil eller `false`                                                                                                            |
| `classifierOptions`     | `{}`                             | Indstillinger for den medfølgende model (se [Classifier](#classifier))                                                                                                           |
| `allowedLanguages`      | `[]`                             | ISO 639-1-koder (`no` læses som `nb`, `fil` som `tl` og de gamle `iw`, `in`, `ji` som `he`, `id`, `yi`); andre sprog får `LANGUAGE_NOT_ALLOWED`                                  |
| `phishing.cloudflare`   | `true`                           | Spørg Cloudflares filtrerende resolvere om værter i links                                                                                                                        |
| `phishing.adult`        | `true`                           | Spørg også familieresolveren, som blokerer voksenwebsteder                                                                                                                       |
| `phishing.maxHosts`     | `25`                             | Værter i links, der slås op pr. besked                                                                                                                                           |
| `phishing.maxLength`    | `1000000`                        | Tegn i teksten, der læses for links (dobbelt så mange i HTML); længere tekst sætter `results.linksTruncated`; `Infinity` eller andet end et positivt tal betyder standardværdien |
| `phishing.homograph`    | `{}`                             | `brands` (erstatter den indbyggede liste), `extraBrands`, `allowlist` (domæner, der aldrig markeres), `strictMode`                                                               |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS-blokeringslistezoner for klientens IP og for domæner i links                                                                                                                 |
| `dns`                   | `{servers: null, timeout: 3000}` | Navneservere til DNS-tjek (standard: systemets)                                                                                                                                  |
| `attachments`           | `true`                           | Undersøg vedhæftede filer                                                                                                                                                        |
| `macros`                | `true`                           | Markér makroer, aktive PDF'er og RTF-objekter                                                                                                                                    |
| `arbitrary`             | `true`                           | Kør [reglerne](scoring.md#rules)                                                                                                                                                 |
| `authentication`        | `false`                          | `true` eller `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([pointgivning](scoring.md#authentication))                          |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; svar gemmes pr. tjeneste og headers, og `cacheSize` gælder for hele scanneren               |
| `allowlist`, `denylist` |                                  | IP-adresser, domæner eller adresser; kortform for `reputation` → [Tilladelsesliste og blokeringsliste](#allowlist-and-denylist)                                                  |
| `clamav`                | `false`                          | `true` (standardsocket), `{socket}` eller `{host, port}`, med `timeout`: millisekunder for alle en beskeds vedhæftninger (`60000`)                                               |
| `llm`                   | `null`                           | [Indstillinger for sprogmodellen](llm.md#any-server-port-and-authentication) med `mode`, `minScore`, `maxScore`                                                                  |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: en model, hvis `classify([text])` svarer som `@tensorflow-models/toxicity`                                                                           |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: en model, hvis `classify(imageBuffer)` svarer som `nsfwjs`                                                                                           |
| `maxLength`             | `100000`                         | Antal tegn af brødteksten, der læses                                                                                                                                             |
| `timeout`               | `10000`                          | Millisekunder, der er tilladt for hvert netværkstjek; godkendelse og billedmodellen får så lang tid i alt (ClamAV har sin egen `clamav.timeout`)                                 |
| `session`               | `{}`                             | Standardoplysninger om SMTP-sessionen                                                                                                                                            |

`scan()` tager også `session`:

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

En server, der allerede har tjekket SPF, DKIM, DMARC og ARC (med [mailauth](https://github.com/postalsys/mailauth)), kan give sine resultater videre som `authenticationResults`, og så scores de i stedet for at blive tjekket igen:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Tilladelsesliste og blokeringsliste

Blokeringslisten matcher klientens IP-adresse og værtsnavn, From-, kuvertafsender- og Reply-To-adresserne og deres domæner, hvad de end er: et navn under et blokeret domæne matcher det, selv om det ikke er et gyldigt værtsnavn (såsom `a_b!.evil.example`, eller et med en etiket på mere end 63 tegn), ud fra dets sidste 127 etiketter og 253 tegn. Tilladelseslisten, og en omdømmetjenestes tilladelsesliste og sandhedskilder, matcher kun det, en afsender ikke kan forfalske: klientens IP-adresse og verificerede værtsnavn (`remoteAddress`, `resolvedClientHostname`), en From-adresse når DMARC består for dens domæne eller en gyldig DKIM-signatur er justeret med den (og dens domæne er et gyldigt værtsnavn; løst, som i DMARC: From-domænet og det signerende eller SPF-domænet har samme registrerbare domæne, som mailauth angiver som DMARC-domænet; en post, der nævner et underdomæne, såsom `news.example.com`, tæller kun, når det domæne, et under det eller et over det har signeret beskeden eller bestået SPF, ikke et andet underdomæne såsom `evil.example.com` og heller ikke et offentligt suffiks; en DMARC-godkendelse for det registrerbare domæne uden mailauths justeringsdetaljer tæller kun for en post, der nævner det registrerbare domæne; ved streng justering, `adkim=s` eller `aspf=s` i domænets DMARC-post med vilkårlige store og små bogstaver og mellemrum, tæller kun en signatur eller SPF-godkendelse af selve From-domænet, og DMARC fejler uden en sådan), og kuvertafsenderen når SPF består for dens domæne. En DKIM-signatur af kun starten af brødteksten (en brødtekstlængde, `l=`, kortere end brødteksten: enhver kan tilføje tekst efter den) tæller for intet, og det samme gør en DMARC-godkendelse, der hviler på en sådan, og ingen signatur tæller, når DMARC fejler, og heller ikke for et From-felt, der er for langt til at blive læst helt (`mail.from.truncated`). Resultater givet i `authenticationResults` tæller kun, når de nævner det domæne, de bestod for, og et domæne, der ikke er et værtsnavn (såsom `bank.example/x.attacker.example`, som URL-parsere læser som `bank.example`), tæller for intet, og det samme gør en DMARC-godkendelse, der hviler på et sådant. Internationale domæner matcher i begge former: `bücher.example` eller `xn--bcher-kva.example`. Reply-To tæller aldrig. For at tillade et domæne skal du slå `authentication` til eller give `authenticationResults`.

Hver post er én IP-adresse, ét domæne eller én e-mailadresse og matches præcist: en domænepost dækker også dets underdomæner og adresserne på dem, men der er ingen adresseintervaller (`192.0.2.0/24`), jokertegn (`*.example.com`) eller mønstre (`@example.com`). IPv6-adresser matcher i enhver form (`2001:0db8::0001` er `2001:db8::1`, formen fra RFC 5952), en IPv4-adresse afbildet i IPv6 (`::ffff:192.0.2.1`) matcher IPv4-adressen, og en IPv4-adresse oversat til IPv6 eller under NAT64-præfikset skrives med det i punktumnotation (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), i både poster og klientadresser.


## Metoder

| Metode                               | Returnerer                                                                            |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Resultatet. `source` er en Buffer, en streng, et Uint8Array eller en læsbar stream    |
| `scanFile(path, options)`            | Resultatet for en beskedfil                                                           |
| `learn(source, 'spam' \| 'ham')`     | Lærer klassifikatoren én besked                                                       |
| `unlearn(source, 'spam' \| 'ham')`   | Fortryder `learn`                                                                     |
| `saveModel(path, options)`           | Skriver klassifikatoren til en fil (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Den `Classifier`, der er i brug, eller `null`                                         |
| `getClassification(features)`        | Klassifikatorens dom for features fra `getFeatures`                                   |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` for en besked       |
| `getTokens(text, locale)`            | Ordene i en tekst                                                                     |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                            |
| `parse(source)`                      | `{raw, mail, error}`, med `mail` fra mailparser (se nedenfor)                         |

`scan`, `parse`, `learn`, `unlearn` og `getTokensAndMailFromSource` læser alle en besked på samme måde: en besked ud over MIME-parserens grænser (mere end 1000 dele, en dels header over 1 MB) læses så langt, parseren tillader. Adressefelter (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To og List-\*) i beskeden, dens dele og vedhæftede beskeder læses op til 16 KB hver, 2000 kommaer og semikoloner og 16 indlejrede grupper og 64 KB i alt for hver besked, altid til slutningen af en hel adresse, så der ikke læses nogen adresse, som feltet ikke angiver; et afkortet felt markeres `truncated` (`mail.to.truncated`), og et afkortet From-felt giver ingen kredit for afsenderens godkendelse. Tekst, hvis første linje ikke er et headerfelt (`Name: value`, eller den `From`-linje, der indleder hver besked i mbox-filer), læses som brødteksten i en besked uden header, så `mail.text` er den tekst. Andre fejl kastes. `parse` angiver parserens grænse, som en meddelelse overskrider, i `error`, ligesom `scan` angiver den i `parseError`, og null for en meddelelse, der er læst helt.

I `getFeatures` er `text` den tekst, en mailklient viser, og som ordene læses fra, og `hidden` hvor mange tegn tekst HTML'en skjuler. mailparser laver ikke tekst af HTML her: `mail.text` indeholder kun de rene tekstdele og er tom for en besked med kun HTML; den tekst, dens HTML viser, er `getFeatures(mail).text`.

`scanner.metrics` indeholder `totalScans`, `averageTime` og `lastScanTime`.


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
    unopenedAttachments: [], // attached messages not opened, past the limits they are read within: {filename, reason}
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

Fund i `phishing`, `attachments`, `executables`, `macros`, `viruses` og `arbitrary` er objekter med en `type` og en `message`. `String(finding)` er beskeden. Vedhæftninger i en vedhæftet besked (`message/rfc822`, `.eml`) navngives efter den: `fw.eml/invoice.exe`. En virus, som ClamAV finder i en sådan vedhæftning, rapporteres kun for den, ikke igen for den vedhæftede besked, der bærer den. `virusScanErrors` viser de vedhæftninger, ClamAV ikke kunne scanne, som `{filename, error}`: en sådan besked kan indeholde virus, så hold den tilbage i stedet for at levere den. Milteren og indholdsfilteret udsætter den, medmindre `onError` (`--on-error`) er `accept`, og hver server markerer en sådan besked, den sender videre, med `X-Spam-Virus-Scan: failed`. `virusScanSkipped` viser dem, der er større, end clamd accepterer (dens `StreamMaxLength`), som `{filename, reason}`: clamd afviser dem ved hvert forsøg, så de er ikke fejl, ligesom clamav-milter springer en fil over sin `MaxFileSize` over. Dens andre grænser (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), som en arkivbombe når, er fejl. Vedhæftede meddelelser åbnes tre niveauer dybt, for højst 100 vedhæftninger i dem og 25 MB i alt; `unopenedAttachments` viser dem, der ikke er åbnet ud over disse grænser, som `{filename, reason}`, og hvis vedhæftninger ikke er undersøgt. Det tæller ikke med i scoren, da videresendte meddelelser kan være indlejret sådan, men en kalder, der har brug for en meddelelse læst helt, for eksempel for at blokere et program i den, kan afvise en med nogen.

Hvert `dnsbl`-element indeholder listens `answers` (adresser i 127.0.0.0/8, hvis betydning hver liste dokumenterer). De svar, lister giver på forespørgsler, de afviser eller ikke kan besvare, er ikke listninger, hverken for klientens adresse eller for linkdomæner (`uribl`-fund i `phishing`): 127.255.255.x hos Spamhaus (såsom 127.255.255.254 for en forespørgsel gennem en offentlig resolver og 127.255.255.255 for for mange forespørgsler), 127.0.1.255 hos Spamhaus DBL, 127.0.0.255 hos enhver liste og 127.0.0.1 hos SURBL og URIBL, som svarer det til resolvere, de blokerer.


## Eksporter

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, unwrapLink, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export
// unwrapLink(address): the URL a link goes to, through Safe Links and
// Proofpoint URL Defense, as the scanner reads it (null for no URL)

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Indstilling                            | Standard       | Betydning                                                                                                                                                |
| -------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsons s og x: hvor kraftigt sjældne features trækkes mod 0,5                                                                                         |
| `minDistance`                          | `0.1`          | Features, der ligger tættere på 0,5 end dette, ignoreres                                                                                                 |
| `maxClues`                             | `150`          | De stærkeste features, der kombineres pr. besked                                                                                                         |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Grænserne for `unsure`-intervallet                                                                                                                       |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Ham-beskeder, der kræves på et sprog for fuld sikkerhed, og en femtedel så mange spambeskeder; færre, når `languageShare` af al ham eller spam er mindre |
| `languagePrior`                        | `true`         | Vej ord mod tallene for deres eget sprog                                                                                                                 |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` og `entries()` er også tilgængelige. `Classifier.fromJSON` kontrollerer modellen og kaster en `TypeError`, der begynder med `Corrupt classifier model`, ved beskadigede data. JSON har ingen `Infinity`, så en indstilling gemt som `Infinity` af version 7.0.3 læses tilbage som `null`: den læses som `Infinity` for `maxClues`, `minDistance` og `minLanguageExamples`, som `-Infinity` for `hamCutoff` (aldrig ham) og `Infinity` for `spamCutoff` (aldrig spam) og som standardværdien for de øvrige. `toJSON` gemmer en grænseværdi ud over 0 og 1 som -1 eller 2, hvilket virker på samme måde. `loadModel` læser en fil igen, når den ændres, og `saveModel` skriver via en ny midlertidig fil, skrevet til disken, før den erstatter modellen, som beholder sine rettigheder.

### Træning

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` tager `{label, features}`-elementer eller `readExamples(sources)`, som læser de samme kilder som `train`, og returnerer optællinger, præcision, genkaldelse, F1, nøjagtighed samt andelen af falske positiver, falske negativer og usikre.

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

Milterens `onError` er dens svar, når en scanning fejler, eller ClamAV ikke kunne scanne en vedhæftning: `'tempfail'` (standard) eller `'accept'`, som sender beskeden videre markeret med `X-Spam-Virus-Scan: failed`, uden de `X-Spam-*`-headers, afsenderen tilføjede.

### ARF-rapporter

`spamscanner/arf` læser og skriver rapporter om misbrugsfeedback (RFC 5965), det format, som postkasseudbydere bruger til at indberette spamklager:

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

`parse()` tager en Buffer, et Uint8Array eller en streng. `ArfParser.tryParse()` returnerer `null` i stedet for at kaste en fejl for beskeder, der ikke er rapporter, og `isArfMessage(mail)` tjekker en fortolket besked. `originalHeaders` er `null` for en rapport uden den oprindelige besked. `create()` returnerer en streng, eller en `Buffer`, når `originalMessage` er en, så dens bytes bevares uanset tegnsæt.
