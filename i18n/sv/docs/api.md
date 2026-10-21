<!-- source: 9134d1cd102c -->

# API-referens

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Skapa en skanner och återanvänd den: den läser in modellen en gång och cachar svar från DNS och språkmodellen.

Typdeklarationer ingår. De kräver TypeScript 4.7 eller senare med `import`, och 5.3 eller senare med `require`.


## Alternativ

Alla alternativ kan skickas till konstruktorn. De flesta kan också skickas till `scan()` för ett enskilt meddelande, och slås då ihop ovanpå konstruktorns. Alternativ som skickas som `undefined` behåller sitt standardvärde. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` och `strictIDNDetection` läses bara av konstruktorn; en modellfil eller ett modellobjekt i `classifier` läses där, så en saknad eller skadad modell ger fel direkt.

| Alternativ              | Standard                         | Betydelse                                                                                                                                                                                |
| ----------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Poäng där ett meddelande är spam                                                                                                                                                         |
| `rejectThreshold`       | `15`                             | Poäng där `action` är `reject`                                                                                                                                                           |
| `scores`                | `{}`                             | Poäng per test: inställningsnycklar eller testnamn ([tester och poäng](scoring.md))                                                                                                      |
| `classifier`            | medföljande modell               | En `Classifier`, ett modellobjekt, en sökväg till en modellfil eller `false`                                                                                                             |
| `classifierOptions`     | `{}`                             | Alternativ för den medföljande modellen (se [Klassificerare](#classifier))                                                                                                               |
| `allowedLanguages`      | `[]`                             | ISO 639-1-koder (`no` läses som `nb`, `fil` som `tl` och de gamla `iw`, `in`, `ji` som `he`, `id`, `yi`); andra språk får `LANGUAGE_NOT_ALLOWED`                                         |
| `phishing.cloudflare`   | `true`                           | Fråga Cloudflares filtrerande resolvrar om länkarnas värdar                                                                                                                              |
| `phishing.adult`        | `true`                           | Fråga även familjeresolvern, som blockerar webbplatser med vuxeninnehåll                                                                                                                 |
| `phishing.maxHosts`     | `25`                             | Antal länkvärdar som slås upp per meddelande                                                                                                                                             |
| `phishing.maxLength`    | `1000000`                        | Tecken i texten som läses efter länkar (dubbelt så många i HTML); längre text sätter `results.linksTruncated`; `Infinity`, eller något annat än ett positivt tal, betyder standardvärdet |
| `phishing.homograph`    | `{}`                             | `brands` (ersätter den inbyggda listan), `extraBrands`, `allowlist` (domäner som aldrig flaggas), `strictMode`                                                                           |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS-blocklistzoner för klientens IP och för länkdomäner                                                                                                                                  |
| `dns`                   | `{servers: null, timeout: 3000}` | Namnservrar för DNS-kontroller (standard: systemets)                                                                                                                                     |
| `attachments`           | `true`                           | Granska bilagor                                                                                                                                                                          |
| `macros`                | `true`                           | Flagga makron, aktiva PDF-filer och RTF-objekt                                                                                                                                           |
| `arbitrary`             | `true`                           | Kör [reglerna](scoring.md#rules)                                                                                                                                                         |
| `authentication`        | `false`                          | `true`, eller `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([poängsättning](scoring.md#authentication))                                |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; svar sparas per tjänst och headers, och `cacheSize` gäller hela skannern                            |
| `allowlist`, `denylist` |                                  | IP-adresser, domäner eller adresser; kortform för `reputation` → [Tillåtelselista och spärrlista](#allowlist-and-denylist)                                                               |
| `clamav`                | `false`                          | `true` (standardsocket), `{socket}` eller `{host, port}`, med `timeout`: millisekunder för alla ett meddelandes bilagor tillsammans (`60000`)                                            |
| `llm`                   | `null`                           | [Inställningar för språkmodellen](llm.md#any-server-port-and-authentication), med `mode`, `minScore`, `maxScore`                                                                         |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: en modell vars `classify([text])` svarar som `@tensorflow-models/toxicity`                                                                                   |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: en modell vars `classify(imageBuffer)` svarar som `nsfwjs`                                                                                                   |
| `maxLength`             | `100000`                         | Antal tecken i brödtexten som läses                                                                                                                                                      |
| `timeout`               | `10000`                          | Millisekunder som tillåts för varje nätverkskontroll; autentiseringen och bildmodellen får så lång tid totalt (ClamAV har en egen `clamav.timeout`)                                      |
| `session`               | `{}`                             | Standardvärden för SMTP-sessionen                                                                                                                                                        |

`scan()` tar också emot `session`:

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

En server som redan har kontrollerat SPF, DKIM, DMARC och ARC (med [mailauth](https://github.com/postalsys/mailauth)) kan skicka med resultaten som `authenticationResults`, och då poängsätts de i stället för att kontrolleras igen:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Tillåtelselista och spärrlista

Spärrlistan jämför klientens IP-adress och värdnamn, adresserna i From, kuvertavsändaren och Reply-To samt deras domäner, vad de än är: ett namn under en spärrlistad domän matchar den även om det inte är ett giltigt värdnamn (som `a_b!.evil.example`, eller ett med en etikett på mer än 63 tecken), genom sina sista 127 etiketter och 253 tecken. Tillåtelselistan, och en ryktestjänsts tillåtelselista och sanningskällor, jämför bara det en avsändare inte kan förfalska: klientens IP-adress och verifierade värdnamn (`remoteAddress`, `resolvedClientHostname`), en From-adress när DMARC godkänns för dess domän eller en giltig DKIM-signatur är justerad med den (och är ett giltigt värdnamn; avslappnat, som i DMARC: From-domänen och den signerande domänen eller SPF-domänen har samma registrerbara domän, som mailauth anger som DMARC-domänen; en post som anger en underdomän, som `news.example.com`, räknas bara när den domänen, en under den eller en överordnad domän signerade meddelandet eller godkändes av SPF, inte en annan underdomän som `evil.example.com`, och inte heller ett publikt suffix; ett DMARC-godkännande för den registrerbara domänen utan mailauths justeringsuppgifter räknas bara för en post som anger den registrerbara domänen; vid strikt justering, `adkim=s` eller `aspf=s` i domänens DMARC-post, oavsett skiftläge eller mellanrum, räknas bara en signatur eller ett SPF-godkännande för själva From-domänen, och DMARC misslyckas utan ett sådant), och kuvertavsändaren när SPF godkänns för dess domän. En DKIM-signatur av bara början av meddelandetexten (en textlängd, `l=`, kortare än texten: vem som helst kan lägga till text efter den) räknas inte för något, inte heller ett DMARC-godkännande som vilar på en sådan, och ingen signatur räknas när DMARC misslyckas, och inte heller för ett From-fält som är för långt för att läsas i sin helhet (`mail.from.truncated`). Resultat som skickas i `authenticationResults` räknas bara när de anger den domän de godkändes för, och en domän som inte är ett värdnamn (som `bank.example/x.attacker.example`, som URL-tolkare läser som `bank.example`) räknas inte för någon, och inte heller ett DMARC-godkännande som vilar på en sådan. Internationella domäner matchar i båda formerna: `bücher.example` eller `xn--bcher-kva.example`. Reply-To räknas aldrig. För att tillåta en domän, slå på `authentication` eller skicka `authenticationResults`.

Varje post är en IP-adress, domän eller e-postadress, som matchas exakt: en domänpost omfattar också dess underdomäner och adresserna på dem, men det finns inga adressintervall (`192.0.2.0/24`), jokertecken (`*.example.com`) eller mönster (`@example.com`). IPv6-adresser matchar i alla former (`2001:0db8::0001` är `2001:db8::1`, formen i RFC 5952), en IPv4-adress mappad i IPv6 (`::ffff:192.0.2.1`) matchar IPv4-adressen, och en IPv4-adress översatt till IPv6 eller under NAT64-prefixet skrivs tillsammans med det i punktform (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), i poster och klientadresser lika.


## Metoder

| Metod                                | Returnerar                                                                             |
| ------------------------------------ | -------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Resultatet. `source` är en Buffer, en sträng, en Uint8Array eller en läsbar ström      |
| `scanFile(path, options)`            | Resultatet för en meddelandefil                                                        |
| `learn(source, 'spam' \| 'ham')`     | Lär klassificeraren ett meddelande                                                     |
| `unlearn(source, 'spam' \| 'ham')`   | Ångrar `learn`                                                                         |
| `saveModel(path, options)`           | Skriver klassificeraren till en fil (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Den `Classifier` som används, eller `null`                                             |
| `getClassification(features)`        | Klassificerarens utslag för egenskaper från `getFeatures`                              |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` för ett meddelande   |
| `getTokens(text, locale)`            | Orden i en text                                                                        |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                             |
| `parse(source)`                      | `{raw, mail, error}`, med `mail` från mailparser (se nedan)                            |

`scan`, `parse`, `learn`, `unlearn` och `getTokensAndMailFromSource` läser alla ett meddelande på samma sätt: ett som överskrider MIME-tolkarens gränser (fler än 1000 delar, en dels header över 1 MB) läses så långt tolkaren tillåter. Adressfält (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To och List-\*), i meddelandet, dess delar och bifogade meddelanden, läses upp till 16 KB vardera, 2000 kommatecken och semikolon och 16 nästlade grupper, och 64 KB totalt för varje meddelande, alltid till slutet av en hel adress, så att ingen adress läses som fältet inte anger; ett avkortat fält markeras `truncated` (`mail.to.truncated`), och ett avkortat From-fält ger ingen tillgodoräkning för avsändarens autentisering. Text vars första rad inte är ett headerfält (`Name: value`, eller den `From`-rad som inleder varje meddelande i mbox-filer) läses som meddelandetexten i ett meddelande utan header, så `mail.text` är den texten. Andra fel kastas. `parse` anger parserns gräns som ett meddelande överskrider i `error`, som `scan` anger den i `parseError`, och null för ett meddelande som lästs helt.

I `getFeatures` är `text` den text som ett e-postprogram visar, som orden läses ur, och `hidden` hur många tecken text som HTML-koden döljer. mailparser gör inte text av HTML här: `mail.text` innehåller bara de rena textdelarna och är tom för ett meddelande som bara består av HTML; den text som dess HTML visar är `getFeatures(mail).text`.

`scanner.metrics` innehåller `totalScans`, `averageTime` och `lastScanTime`.


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

Fynd i `phishing`, `attachments`, `executables`, `macros`, `viruses` och `arbitrary` är objekt med en `type` och ett `message`. `String(finding)` är meddelandet. Bilagor i ett bifogat meddelande (`message/rfc822`, `message/global`, `.eml`, `.u8msg`) får dess namn: `fw.eml/invoice.exe`. Ett virus som ClamAV hittar i en sådan bilaga rapporteras bara för den, inte igen för det bifogade meddelande som bär den. `virusScanErrors` listar de bilagor ClamAV inte kunde skanna, som `{filename, error}`: ett sådant meddelande kan innehålla virus, så håll kvar det i stället för att leverera det. Miltern och innehållsfiltret skjuter upp det om inte `onError` (`--on-error`) är `accept`, och varje server märker ett sådant meddelande som den skickar vidare med `X-Spam-Virus-Scan: failed`. `virusScanSkipped` listar de bilagor som är större än clamd accepterar (dess `StreamMaxLength`), som `{filename, reason}`: clamd nekar dem vid varje försök, så precis som när clamav-milter hoppar över en fil över sin `MaxFileSize` räknas de inte som fel. Dess andra gränser (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), som en arkivbomb når, räknas som fel. Bifogade meddelanden öppnas tre nivåer djupt, för högst 100 bilagor i dem och 25 MB totalt; `unopenedAttachments` listar de som inte öppnats bortom dessa gränser, som `{filename, reason}`, vars bilagor inte granskats. Det påverkar inte poängen, eftersom vidarebefordrade meddelanden kan vara kapslade så, men den som behöver ett meddelande läst helt, till exempel för att blockera ett program det bär, kan avvisa ett som har någon. Högst 100 bifogade meddelanden öppnas totalt.

Varje `dnsbl`-post bär listans `answers` (adresser i 127.0.0.0/8, vars betydelse varje lista dokumenterar). De svar listor ger på frågor som de nekar eller inte kan besvara är inga listningar, varken för klientens adress eller för länkdomäner (`uribl`-fynd i `phishing`): 127.255.255.x hos Spamhaus (som 127.255.255.254 för en fråga via en publik resolver, och 127.255.255.255 för för många frågor), 127.0.1.255 hos Spamhaus DBL, 127.0.0.255 hos alla listor, och 127.0.0.1 hos SURBL och URIBL, som ger det svaret till resolvrar de blockerar.


## Exporter

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

### Klassificerare

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Alternativ                             | Standard       | Betydelse                                                                                                                                                             |
| -------------------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsons s och x: hur starkt sällsynta egenskaper dras mot 0,5                                                                                                       |
| `minDistance`                          | `0.1`          | Egenskaper som ligger närmare 0,5 än detta ignoreras                                                                                                                  |
| `maxClues`                             | `150`          | Antal starkaste egenskaper som kombineras per meddelande                                                                                                              |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Gränserna för intervallet `unsure`                                                                                                                                    |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Antal ham-meddelanden på ett språk som krävs för full konfidens, och en femtedel så många spam-meddelanden; färre när `languageShare` av all ham eller spam är mindre |
| `languagePrior`                        | `true`         | Väg ord mot räkningen för deras eget språk                                                                                                                            |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` och `entries()` finns också. `Classifier.fromJSON` kontrollerar modellen och kastar ett `TypeError` som börjar med `Corrupt classifier model` vid skadade data. JSON har ingen `Infinity`, så ett alternativ som version 7.0.3 sparade som `Infinity` läses tillbaka som `null`: det läses som `Infinity` för `maxClues`, `minDistance` och `minLanguageExamples`, som `-Infinity` för `hamCutoff` (aldrig ham) och `Infinity` för `spamCutoff` (aldrig spam), och som standardvärdet för de övriga. `toJSON` sparar en gräns utanför 0 och 1 som -1 eller 2, vilket fungerar likadant. `loadModel` läser en fil igen när den ändras, och `saveModel` skriver via en ny tillfällig fil, som skrivs till disk innan den ersätter modellen, vilken behåller sina behörigheter.

### Träning

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` tar emot poster av formen `{label, features}`, eller `readExamples(sources)`, som läser samma källor som `train`, och returnerar antal, precision, täckning (recall), F1, träffsäkerhet samt andelar falska positiva, falska negativa och osäkra.

### Servrar

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

Milterns `onError` är dess svar när en skanning misslyckas eller ClamAV inte kunde skanna en bilaga: `'tempfail'` (standard) eller `'accept'`, som skickar meddelandet vidare märkt med `X-Spam-Virus-Scan: failed`, utan de `X-Spam-*`-headers som avsändaren lade till.

### ARF-rapporter

`spamscanner/arf` läser och skriver rapporter om missbruk (RFC 5965), formatet som e-postleverantörer använder för att rapportera spamklagomål:

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

`parse()` tar en Buffer, Uint8Array eller sträng. `ArfParser.tryParse()` returnerar `null` i stället för att kasta ett fel för meddelanden som inte är rapporter, och `isArfMessage(mail)` kontrollerar ett tolkat meddelande. `originalHeaders` är `null` för en rapport utan det ursprungliga meddelandet. `create()` returnerar en sträng, eller en `Buffer` när `originalMessage` är en, så att dess byte bevaras oavsett teckenuppsättning.
