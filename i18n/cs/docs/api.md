<!-- source: 9134d1cd102c -->

# Reference API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Vytvořte jeden scanner a používejte ho opakovaně: model načte jednou a ukládá do mezipaměti odpovědi DNS i jazykového modelu.

Deklarace typů jsou součástí balíčku. Vyžadují TypeScript 4.7 nebo novější s `import` a 5.3 nebo novější s `require`.


## Volby

Každou volbu lze předat konstruktoru. Většinu lze předat také `scan()` pro jednu zprávu, kde se sloučí s volbami konstruktoru a mají přednost. Volby předané jako `undefined` si ponechají výchozí hodnoty. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` a `strictIDNDetection` čte pouze konstruktor; soubor nebo objekt modelu zadaný v `classifier` se načte tam, takže chybějící nebo poškozený model vyhodí chybu hned.

| Volba                   | Výchozí                          | Význam                                                                                                                                                                            |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Skóre, od kterého je zpráva spam                                                                                                                                                  |
| `rejectThreshold`       | `15`                             | Skóre, od kterého je `action` rovno `reject`                                                                                                                                      |
| `scores`                | `{}`                             | Body za test: klíče nastavení nebo názvy testů ([testy a skóre](scoring.md))                                                                                                      |
| `classifier`            | přibalený model                  | `Classifier`, objekt modelu, cesta k souboru modelu nebo `false`                                                                                                                  |
| `classifierOptions`     | `{}`                             | Volby přibaleného modelu (viz [Klasifikátor](#classifier))                                                                                                                        |
| `allowedLanguages`      | `[]`                             | Kódy ISO 639-1 (`no` se čte jako `nb`, `fil` jako `tl` a staré `iw`, `in`, `ji` jako `he`, `id`, `yi`); ostatní jazyky dostanou `LANGUAGE_NOT_ALLOWED`                            |
| `phishing.cloudflare`   | `true`                           | Ptát se filtrovacích resolverů Cloudflare na hostitele z odkazů                                                                                                                   |
| `phishing.adult`        | `true`                           | Ptát se také rodinného resolveru, který blokuje weby pro dospělé                                                                                                                  |
| `phishing.maxHosts`     | `25`                             | Počet hostitelů z odkazů vyhledaných na jednu zprávu                                                                                                                              |
| `phishing.maxLength`    | `1000000`                        | Znaky textu čtené kvůli odkazům (z HTML dvojnásobek); delší text nastaví `results.linksTruncated`; `Infinity` nebo cokoli jiného než kladné číslo znamená výchozí hodnotu         |
| `phishing.homograph`    | `{}`                             | `brands` (nahradí vestavěný seznam), `extraBrands`, `allowlist` (domény, které se nikdy neoznačí), `strictMode`                                                                   |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zóny DNS blocklistů pro IP adresu klienta a pro domény v odkazech                                                                                                                 |
| `dns`                   | `{servers: null, timeout: 3000}` | Jmenné servery pro kontroly DNS (výchozí: systémové)                                                                                                                              |
| `attachments`           | `true`                           | Prohlížet přílohy                                                                                                                                                                 |
| `macros`                | `true`                           | Označovat makra, aktivní PDF a objekty RTF                                                                                                                                        |
| `arbitrary`             | `true`                           | Spouštět [pravidla](scoring.md#rules)                                                                                                                                             |
| `authentication`        | `false`                          | `true` nebo `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([hodnocení](scoring.md#authentication))                               |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; odpovědi se ukládají zvlášť pro každou službu a hlavičky a `cacheSize` platí pro celý skener |
| `allowlist`, `denylist` |                                  | IP adresy, domény nebo adresy; zkratka pro `reputation` → [Seznam povolených a seznam zakázaných](#allowlist-and-denylist)                                                        |
| `clamav`                | `false`                          | `true` (výchozí socket), `{socket}` nebo `{host, port}`, s `timeout`: milisekundy pro všechny přílohy zprávy (`60000`)                                                            |
| `llm`                   | `null`                           | [Nastavení jazykového modelu](llm.md#any-server-port-and-authentication) s `mode`, `minScore`, `maxScore`                                                                         |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: model, jehož `classify([text])` odpovídá jako `@tensorflow-models/toxicity`                                                                           |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: model, jehož `classify(imageBuffer)` odpovídá jako `nsfwjs`                                                                                           |
| `maxLength`             | `100000`                         | Počet přečtených znaků textu těla                                                                                                                                                 |
| `timeout`               | `10000`                          | Milisekundy povolené pro každou síťovou kontrolu; ověřování a model obrázků mají tolik času celkem (ClamAV má vlastní `clamav.timeout`)                                           |
| `session`               | `{}`                             | Výchozí údaje o relaci SMTP                                                                                                                                                       |

`scan()` přijímá také `session`:

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

Server, který už SPF, DKIM, DMARC a ARC ověřil (pomocí [mailauth](https://github.com/postalsys/mailauth)), může své výsledky předat jako `authenticationResults` a ty se pak bodují, místo aby se ověřovaly znovu:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Seznam povolených a seznam zakázaných

Seznam zakázaných odpovídá IP adrese a názvu hostitele klienta, adresám From, odesílatele obálky a Reply-To a jejich doménám, ať jsou jakékoli: název pod zakázanou doménou jí odpovídá, i když není platným názvem hostitele (například `a_b!.evil.example` nebo název s návěštím delším než 63 znaků), podle svých posledních 127 návěští a 253 znaků. Seznam povolených, stejně jako seznam povolených a důvěryhodné zdroje služby reputace, odpovídá jen tomu, co odesílatel nemůže podvrhnout: IP adrese a ověřenému názvu hostitele klienta (`remoteAddress`, `resolvedClientHostname`), adrese From, když pro její doménu projde DMARC nebo je s ní zarovnán platný podpis DKIM (a její doména je platným názvem hostitele; volně, jako v DMARC: doména From a podepisující doména nebo doména SPF mají stejnou registrovatelnou doménu, kterou mailauth uvádí jako doménu DMARC; záznam, který uvádí subdoménu, například `news.example.com`, se počítá, jen když tato doména, doména pod ní nebo doména nad ní zprávu podepsala nebo prošla SPF, ne jiná subdoména jako `evil.example.com`, ani veřejná přípona; úspěch DMARC pro registrovatelnou doménu bez údajů mailauth o zarovnání se počítá jen pro záznam, který uvádí registrovatelnou doménu; při striktním zarovnání, `adkim=s` nebo `aspf=s` v záznamu DMARC domény při jakékoli velikosti písmen a jakýchkoli mezerách, se počítá jen podpis nebo úspěch SPF samotné domény From a bez něj DMARC selže), a odesílateli obálky, když pro jeho doménu projde SPF. Podpis DKIM jen začátku těla (délka těla, `l=`, kratší než tělo: kdokoli za něj může přidat text) se nepočítá vůbec, stejně jako úspěch DMARC, který na něm stojí, a když DMARC selže, nepočítá se žádný podpis, stejně jako u pole From příliš dlouhého na to, aby se dalo přečíst celé (`mail.from.truncated`). Výsledky předané v `authenticationResults` se počítají, jen když uvádějí doménu, pro kterou prošly, a doména, která není názvem hostitele (například `bank.example/x.attacker.example`, kterou parsery URL čtou jako `bank.example`), se nepočítá pro žádnou, stejně jako úspěch DMARC, který na takové doméně stojí. Mezinárodní domény odpovídají v obou podobách: `bücher.example` nebo `xn--bcher-kva.example`. Reply-To se nepočítá nikdy. Chcete-li povolit doménu, zapněte `authentication` nebo předejte `authenticationResults`.

Každý záznam je jedna IP adresa, doména nebo e-mailová adresa a porovnává se přesně: záznam domény pokrývá i její subdomény a adresy na nich, ale neexistují rozsahy adres (`192.0.2.0/24`), zástupné znaky (`*.example.com`) ani vzory (`@example.com`). Adresy IPv6 odpovídají v jakémkoli zápisu (`2001:0db8::0001` je `2001:db8::1`, zápis podle RFC 5952), adresa IPv4 namapovaná do IPv6 (`::ffff:192.0.2.1`) odpovídá adrese IPv4 a adresa IPv4 přeložená do IPv6 nebo pod prefixem NAT64 se s ním zapisuje v tečkovém zápisu (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), a to v záznamech i v adresách klientů.


## Metody

| Metoda                               | Vrací                                                                             |
| ------------------------------------ | --------------------------------------------------------------------------------- |
| `scan(source, options)`              | Výsledek. `source` je Buffer, řetězec, Uint8Array nebo čitelný stream             |
| `scanFile(path, options)`            | Výsledek pro soubor se zprávou                                                    |
| `learn(source, 'spam' \| 'ham')`     | Naučí klasifikátor jednu zprávu                                                   |
| `unlearn(source, 'spam' \| 'ham')`   | Vrátí zpět `learn`                                                                |
| `saveModel(path, options)`           | Zapíše klasifikátor do souboru (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Používaný `Classifier` nebo `null`                                                |
| `getClassification(features)`        | Verdikt klasifikátoru pro příznaky z `getFeatures`                                |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` zprávy          |
| `getTokens(text, locale)`            | Slova textu                                                                       |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                        |
| `parse(source)`                      | `{raw, mail, error}`, kde `mail` pochází z mailparseru (viz níže)                 |

`scan`, `parse`, `learn`, `unlearn` a `getTokensAndMailFromSource` čtou zprávu všechny stejně: zpráva, která překračuje limity parseru MIME (více než 1000 částí, hlavička části nad 1 MB), se čte, kam až parser dovolí. Adresní pole (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To a List-\*) zprávy, jejích částí a přiložených zpráv se čtou do 16 KB každé, 2000 čárek a středníků a 16 vnořených skupin a celkem 64 KB na zprávu, vždy až do konce celé adresy, takže se nepřečte žádná adresa, kterou pole neuvádí; zkrácené pole je označeno `truncated` (`mail.to.truncated`) a zkrácené pole From nedává žádný kredit za ověření odesílatele. Text, jehož první řádek není polem hlavičky (`Name: value`, nebo řádek `From`, kterým v souborech mbox začíná každá zpráva), se čte jako tělo zprávy bez hlavičky, takže `mail.text` je tento text. Ostatní chyby se vyhodí. `parse` uvádí v `error` limit parseru, který zpráva překračuje, stejně jako ho `scan` uvádí v `parseError`, a null pro zprávu přečtenou celou.

V `getFeatures` je `text` text, který zobrazí poštovní klient a ze kterého se čtou slova, a `hidden` počet znaků textu, které HTML skrývá. mailparser zde z HTML text nevytváří: `mail.text` obsahuje jen části s prostým textem a u zprávy pouze z HTML je prázdný; text, který zobrazuje její HTML, je `getFeatures(mail).text`.

`scanner.metrics` obsahuje `totalScans`, `averageTime` a `lastScanTime`.


## Výsledek

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

Nálezy v `phishing`, `attachments`, `executables`, `macros`, `viruses` a `arbitrary` jsou objekty s `type` a `message`. `String(finding)` je zpráva. Přílohy přiložené zprávy (`message/rfc822`, `message/global`, `.eml`, `.u8msg`) se pojmenují podle ní: `fw.eml/invoice.exe`. Virus, který ClamAV v takové příloze najde, se hlásí jen u ní, ne znovu u přiložené zprávy, která ji nese. `virusScanErrors` uvádí přílohy, které ClamAV nedokázal zkontrolovat, jako `{filename, error}`: taková zpráva může obsahovat virus, proto ji raději zadržte, než abyste ji doručili. Milter i obsahový filtr ji odloží, pokud `onError` (`--on-error`) není `accept`, a každý server takovou zprávu, kterou předá dál, označí hlavičkou `X-Spam-Virus-Scan: failed`. `virusScanSkipped` uvádí přílohy větší, než clamd přijme (jeho `StreamMaxLength`), jako `{filename, reason}`: clamd je odmítne při každém pokusu, proto se nepovažují za selhání, stejně jako clamav-milter přeskočí soubor nad svým `MaxFileSize`. Jeho ostatní limity (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), kterých dosáhne archivní bomba, jsou selhání. Přiložené zprávy se otevírají do tří úrovní, nejvýše se 100 přílohami v nich a celkem 25 MB; `unopenedAttachments` vypisuje ty, které kvůli těmto limitům otevřeny nebyly, jako `{filename, reason}`, a jejichž přílohy nebyly zkontrolovány. Do skóre se nezapočítává, protože přeposlané zprávy mohou být takto vnořené, ale volající, který potřebuje zprávu přečtenou celou, například aby zablokoval program, který nese, může zprávu s jakoukoli takovou položkou odmítnout. Celkem se otevře nejvýše 100 přiložených zpráv.

Každá položka `dnsbl` nese `answers` seznamu (adresy v 127.0.0.0/8, jejichž význam každý seznam dokumentuje). Odpovědi, které seznamy dávají na dotazy, jež odmítají nebo nemohou zodpovědět, nejsou záznamy, ani pro adresu klienta, ani pro domény odkazů (nálezy `uribl` v `phishing`): 127.255.255.x u Spamhausu (například 127.255.255.254 pro dotaz přes veřejný resolver a 127.255.255.255 pro příliš mnoho dotazů), 127.0.1.255 u Spamhaus DBL, 127.0.0.255 u jakéhokoli seznamu a 127.0.0.1 u SURBL a URIBL, které ji odpovídají resolverům, jež blokují.


## Exporty

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

### Klasifikátor

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Volba                                  | Výchozí        | Význam                                                                                                                                      |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsonovy parametry s a x: jak silně se vzácné příznaky táhnou k 0,5                                                                      |
| `minDistance`                          | `0.1`          | Příznaky bližší k 0,5 než tato hodnota se ignorují                                                                                          |
| `maxClues`                             | `150`          | Počet nejsilnějších příznaků kombinovaných na jednu zprávu                                                                                  |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Hranice rozsahu `unsure`                                                                                                                    |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Počet zpráv ham v jazyce potřebný pro plnou důvěru a pětina tolika zpráv spam; méně, když je `languageShare` všech zpráv ham nebo spam méně |
| `languagePrior`                        | `true`         | Vážit slova podle počtů v jejich vlastním jazyce                                                                                            |

K dispozici jsou také `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` a `entries()`. `Classifier.fromJSON` model kontroluje a u poškozených dat vyhodí `TypeError` začínající `Corrupt classifier model`. JSON nezná `Infinity`, proto se volba, kterou verze 7.0.3 uložila jako `Infinity`, načte zpět jako `null`: čte se jako `Infinity` pro `maxClues`, `minDistance` a `minLanguageExamples`, jako `-Infinity` pro `hamCutoff` (nikdy ham) a `Infinity` pro `spamCutoff` (nikdy spam) a u ostatních jako výchozí hodnota. `toJSON` ukládá práh mimo 0 a 1 jako -1 nebo 2, což funguje stejně. `loadModel` načte soubor znovu, když se změní, a `saveModel` zapisuje přes nový dočasný soubor, uložený na disk dříve, než nahradí model, který si ponechá svá oprávnění.

### Trénování

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` přijímá položky `{label, features}` nebo `readExamples(sources)`, které čte stejné zdroje jako `train`, a vrací počty, přesnost, úplnost, F1, správnost a míru falešně pozitivních, falešně negativních a nejistých výsledků.

### Servery

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` milteru určuje jeho odpověď, když kontrola selže nebo ClamAV nedokázal zkontrolovat přílohu: `'tempfail'` (výchozí) nebo `'accept'`, které zprávu předá dál označenou `X-Spam-Virus-Scan: failed`, bez hlaviček `X-Spam-*`, které přidal odesílatel.

### Hlášení ARF

`spamscanner/arf` čte a zapisuje hlášení o zneužití (RFC 5965), formát, kterým poskytovatelé poštovních schránek hlásí stížnosti na spam:

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

`parse()` přijímá Buffer, Uint8Array nebo řetězec. `ArfParser.tryParse()` u zpráv, které nejsou hlášeními, vrací `null` místo vyhození výjimky, a `isArfMessage(mail)` zkontroluje rozebranou zprávu. U hlášení bez původní zprávy je `originalHeaders` rovno `null`. `create()` vrací řetězec, nebo `Buffer`, pokud je jím `originalMessage`, takže se její bajty zachovají bez ohledu na znakovou sadu.
