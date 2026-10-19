<!-- source: 581d018dd514 -->

# API-referencia

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Érdemes egyetlen szkennert létrehozni és újrahasználni: a modellt egyszer tölti be, a DNS- és nyelvimodell-válaszokat pedig gyorsítótárazza.

A típusdeklarációk a csomag részei. Ezekhez `import` esetén TypeScript 4.7 vagy újabb, `require` esetén 5.3 vagy újabb szükséges.


## Beállítások

Minden beállítás átadható a konstruktornak. A legtöbb egyetlen levélre a `scan()` számára is átadható, ekkor a konstruktor beállításai fölé kerülnek. Az `undefined` értékkel átadott beállítások megtartják alapértéküket. A `classifier`, `classifierOptions`, `dns`, `phishing.homograph` és `strictIDNDetection` beállítást csak a konstruktor olvassa; a `classifier`-ként megadott modellfájlt vagy -objektumot is ott tölti be, így a hiányzó vagy sérült modell azonnal hibát dob.

| Beállítás               | Alapértelmezés                   | Jelentés                                                                                                                                                                                                      |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Az a pontszám, amelytől egy levél spam                                                                                                                                                                        |
| `rejectThreshold`       | `15`                             | Az a pontszám, amelytől az `action` értéke `reject`                                                                                                                                                           |
| `scores`                | `{}`                             | Pontok tesztenként: beállításkulcsok vagy tesztnevek ([tesztek és pontszámok](scoring.md))                                                                                                                    |
| `classifier`            | beépített modell                 | Egy `Classifier`, egy modellobjektum, egy modellfájl elérési útja vagy `false`                                                                                                                                |
| `classifierOptions`     | `{}`                             | A beépített modell beállításai (lásd: [Osztályozó](#classifier))                                                                                                                                              |
| `allowedLanguages`      | `[]`                             | ISO 639-1 kódok (a `no` `nb`, a `fil` `tl`, a régi `iw`, `in`, `ji` pedig `he`, `id`, `yi` kódként olvasódik); a többi nyelv `LANGUAGE_NOT_ALLOWED` találatot kap                                             |
| `phishing.cloudflare`   | `true`                           | A Cloudflare szűrő DNS-feloldóinak megkérdezése a hivatkozások gépneveiről                                                                                                                                    |
| `phishing.adult`        | `true`                           | A felnőtt oldalakat blokkoló családi DNS-feloldó megkérdezése is                                                                                                                                              |
| `phishing.maxHosts`     | `25`                             | Levelenként lekérdezett hivatkozás-gépnevek száma                                                                                                                                                             |
| `phishing.maxLength`    | `1000000`                        | A linkek kereséséhez olvasott szövegkarakterek (HTML-ből kétszer annyi); hosszabb szöveg beállítja a `results.linksTruncated` értéket; az `Infinity` vagy bármi, ami nem pozitív szám, az alapértéket jelenti |
| `phishing.homograph`    | `{}`                             | `brands` (a beépített lista cseréje), `extraBrands`, `allowlist` (soha meg nem jelölt domainek), `strictMode`                                                                                                 |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS-tiltólista-zónák a kliens IP-címéhez és a hivatkozások domainjeihez                                                                                                                                       |
| `dns`                   | `{servers: null, timeout: 3000}` | Névszerverek a DNS-ellenőrzésekhez (alapértelmezés: a rendszeré)                                                                                                                                              |
| `attachments`           | `true`                           | A mellékletek vizsgálata                                                                                                                                                                                      |
| `macros`                | `true`                           | Makrók, aktív PDF-ek és RTF-objektumok megjelölése                                                                                                                                                            |
| `arbitrary`             | `true`                           | A [szabályok](scoring.md#rules) futtatása                                                                                                                                                                     |
| `authentication`        | `false`                          | `true` vagy `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([pontozás](scoring.md#authentication))                                                            |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; a válaszokat szolgáltatásonként és fejlécenként tárolja, a `cacheSize` pedig az egész szkennerre vonatkozik              |
| `allowlist`, `denylist` |                                  | IP-címek, domainek vagy címek; a `reputation` rövidítése → [Engedélyezési lista és tiltólista](#allowlist-and-denylist)                                                                                       |
| `clamav`                | `false`                          | `true` (alapértelmezett socket), `{socket}` vagy `{host, port}`, `timeout` értékkel: ezredmásodperc egy levél összes mellékletére (`60000`)                                                                   |
| `llm`                   | `null`                           | [Nyelvimodell-beállítások](llm.md#any-server-port-and-authentication), `mode`, `minScore` és `maxScore` értékkel                                                                                              |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: olyan modell, amelynek `classify([text])` válasza a `@tensorflow-models/toxicity` válaszához hasonló                                                                              |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: olyan modell, amelynek `classify(imageBuffer)` válasza az `nsfwjs` válaszához hasonló                                                                                             |
| `maxLength`             | `100000`                         | A beolvasott levéltörzs karaktereinek száma                                                                                                                                                                   |
| `timeout`               | `10000`                          | Az egyes hálózati ellenőrzésekre engedélyezett idő ezredmásodpercben; a hitelesítés és a képmodell összesen ennyi időt kap (a ClamAV-nek saját `clamav.timeout` értéke van)                                   |
| `session`               | `{}`                             | Alapértelmezett SMTP-munkamenet-adatok                                                                                                                                                                        |

A `scan()` a `session` beállítást is fogadja:

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

Az a szerver, amely már ellenőrizte az SPF-et, a DKIM-et, a DMARC-ot és az ARC-ot (a [mailauth](https://github.com/postalsys/mailauth) segítségével), átadhatja az eredményeit az `authenticationResults` beállításban, és ilyenkor ezeket nem ellenőrzi újra, hanem pontozza őket:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Engedélyezési lista és tiltólista

A tiltólista az ügyfél IP-címét és gépnevét, a From, a borítékfeladó és a Reply-To címet, valamint ezek tartományát veti össze, bármik legyenek is: egy tiltólistás tartomány alatti név akkor is egyezik vele, ha nem érvényes gépnév (például `a_b!.evil.example`, vagy egy 63 karakternél hosszabb címkét tartalmazó név), az utolsó 127 címkéje és 253 karaktere alapján. Az engedélyezési lista, és egy hírnévszolgáltatás engedélyezési listája és megbízható forrásai, csak azt vetik össze, amit a feladó nem tud hamisítani: az ügyfél IP-címét és ellenőrzött gépnevét (`remoteAddress`, `resolvedClientHostname`), a From címet, ha a tartományára a DMARC sikeres, vagy egy érvényes DKIM-aláírás igazodik hozzá (és érvényes gépnév; lazán, mint a DMARC-ban: a From tartomány és az aláíró vagy SPF-tartomány regisztrálható tartománya ugyanaz, ezt a mailauth DMARC-tartományként nevezi meg; egy altartományt, például `news.example.com` tartományt megnevező bejegyzés csak akkor számít, ha ez a tartomány, egy alatta vagy egy felette lévő tartomány aláírta a levelet vagy sikeres volt rá az SPF, nem pedig egy másik altartomány, például `evil.example.com`, sem nyilvános utótag; a regisztrálható tartományra sikeres DMARC a mailauth igazodási adatai nélkül csak a regisztrálható tartományt megnevező bejegyzésre számít; szigorú igazodásnál, ha a tartomány DMARC-rekordjában `adkim=s` vagy `aspf=s` áll, bármilyen kis- és nagybetűkkel vagy szóközökkel, csak magának a From tartománynak az aláírása vagy sikeres SPF-je számít, és enélkül a DMARC sikertelen), és a borítékfeladót, ha a tartományára az SPF sikeres. Egy csak a levéltörzs elejére vonatkozó DKIM-aláírás (a törzshossz, `l=`, rövidebb a törzsnél: utána bárki hozzáírhat szöveget) semmit sem számít, ahogy az ilyenre épülő sikeres DMARC sem, és ha a DMARC sikertelen, egyetlen aláírás sem számít, ahogy a túl hosszú, egészében be nem olvasható From mező esetén sem (`mail.from.truncated`). Az `authenticationResults` értékben átadott eredmények csak akkor számítanak, ha megnevezik a tartományt, amelyre sikeresek voltak, és egy olyan tartomány, amely nem gépnév (például `bank.example/x.attacker.example`, amelyet az URL-elemzők `bank.example` tartományként olvasnak), semmire sem számít, ahogy az ilyenre épülő sikeres DMARC sem. A nemzetközi tartományok mindkét alakban egyeznek: `bücher.example` vagy `xn--bcher-kva.example`. A Reply-To sosem számít. Egy tartomány engedélyezéséhez kapcsolja be az `authentication` beállítást, vagy adja át az `authenticationResults` értéket.

Minden bejegyzés egyetlen IP-cím, tartomány vagy e-mail-cím, és pontos egyezést keres: egy tartománybejegyzés az altartományait és az azokon lévő címeket is lefedi, de címtartományok (`192.0.2.0/24`), helyettesítő karakterek (`*.example.com`) és minták (`@example.com`) nincsenek. Az IPv6-címek bármilyen alakban egyeznek (`2001:0db8::0001` azonos `2001:db8::1` címmel, az RFC 5952 szerinti alakkal), egy IPv6-ba leképezett IPv4-cím (`::ffff:192.0.2.1`) az IPv4-címmel egyezik, egy IPv6-ra fordított vagy a NAT64-előtag alá helyezett IPv4-címet pedig úgy kell írni, hogy az IPv4-cím pontozott alakban szerepeljen benne (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), a bejegyzésekben és az ügyfélcímekben egyaránt.


## Metódusok

| Metódus                              | Visszatérési érték                                                             |
| ------------------------------------ | ------------------------------------------------------------------------------ |
| `scan(source, options)`              | Az eredmény. A `source` Buffer, karakterlánc, Uint8Array vagy olvasható stream |
| `scanFile(path, options)`            | Egy levélfájl eredménye                                                        |
| `learn(source, 'spam' \| 'ham')`     | Egy levelet tanít az osztályozónak                                             |
| `unlearn(source, 'spam' \| 'ham')`   | Visszavonja a `learn` hatását                                                  |
| `saveModel(path, options)`           | Fájlba írja az osztályozót (`options`: `minCount`, `maxFeatures`, `metadata`)  |
| `getClassifier()`                    | A használt `Classifier` vagy `null`                                            |
| `getClassification(features)`        | Az osztályozó ítélete a `getFeatures` által adott jellemzőkre                  |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` egy levélből |
| `getTokens(text, locale)`            | Egy szöveg szavai                                                              |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                     |
| `parse(source)`                      | `{raw, mail}`, ahol a `mail` a mailparsertől származik (lásd lent)             |

A `scan`, a `parse`, a `learn`, az `unlearn` és a `getTokensAndMailFromSource` mind ugyanúgy olvassa a levelet: a MIME-elemző korlátain (több mint 1000 rész, 1 MB-nál nagyobb részfejléc) túli levelet addig olvassa, ameddig az elemző engedi. A címmezőket (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To és List-\*) a levélben, annak részeiben és a csatolt levelekben mezőnként legfeljebb 16 KB-ig, 2000 vesszőig és pontosvesszőig és 16 beágyazott csoportig, levelenként pedig összesen 64 KB-ig olvassa, mindig egy teljes cím végéig, így nem olvas be olyan címet, amelyet a mező nem ad meg; a levágott mező `truncated` jelölést kap (`mail.to.truncated`), a levágott From mező pedig nem ad jóváírást a feladó hitelesítéséért. Az a szöveg, amelynek első sora nem fejlécmező (`Name: value`, vagy a `From` sor, amellyel az mbox-fájlokban minden levél kezdődik), egy fejléc nélküli levél törzseként olvasódik, így a `mail.text` ez a szöveg lesz. Más hibákat kivételként dob.

A `getFeatures` eredményében a `text` a levelezőprogram által megjelenített szöveg, amelyből a szavakat olvassa, a `hidden` pedig az, hogy a HTML hány karakternyi szöveget rejt el. A mailparser itt nem készít szöveget a HTML-ből: a `mail.text` csak az egyszerű szöveges részeket tartalmazza, és egy csak HTML-ből álló levélnél üres; a HTML által megjelenített szöveg a `getFeatures(mail).text`.

A `scanner.metrics` a `totalScans`, az `averageTime` és a `lastScanTime` értékeket tartalmazza.


## Az eredmény

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

A `phishing`, `attachments`, `executables`, `macros`, `viruses` és `arbitrary` mezőkben lévő találatok `type` és `message` mezővel rendelkező objektumok. A `String(finding)` az üzenetet adja. Egy csatolt üzenet (`message/rfc822`, `.eml`) mellékletei annak nevét kapják: `fw.eml/invoice.exe`. Az ilyen mellékletben a ClamAV által talált vírust csak annál jelenti, nem újra az azt hordozó csatolt üzenetnél is. A `virusScanErrors` felsorolja azokat a mellékleteket, amelyeket a ClamAV nem tudott átvizsgálni, `{filename, error}` alakban: egy ilyen üzenet vírust tartalmazhat, ezért inkább tartsa vissza, mint hogy kézbesítse. A milter és a tartalomszűrő elhalasztja, hacsak az `onError` (`--on-error`) értéke nem `accept`, és minden szerver `X-Spam-Virus-Scan: failed` fejléccel jelöli az ilyen levelet, ha továbbengedi. A `virusScanSkipped` azokat a mellékleteket sorolja fel, amelyek nagyobbak, mint amit a clamd elfogad (a `StreamMaxLength` értéke), `{filename, reason}` alakban: ezeket a clamd minden próbálkozáskor elutasítja, így nem számítanak hibának, ahogy a clamav-milter is kihagyja a `MaxFileSize` értékénél nagyobb fájlt. A clamd többi korlátja (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), amelyet egy archívumbomba elér, hibának számít.

Minden `dnsbl` elem tartalmazza a lista `answers` értékét (127.0.0.0/8 tartománybeli címek, amelyek jelentését minden lista dokumentálja). A listák által az elutasított vagy megválaszolhatatlan lekérdezésekre adott válaszok nem listázások, sem az ügyfél címére, sem a hivatkozások domainjeire (`uribl` találatok a `phishing` mezőben): a Spamhausnál 127.255.255.x (például 127.255.255.254 egy nyilvános feloldón keresztüli lekérdezésre, és 127.255.255.255 túl sok lekérdezésre), a Spamhaus DBL-nél 127.0.1.255, bármely listánál 127.0.0.255, a SURBL-nél és az URIBL-nél pedig 127.0.0.1, amelyet az általuk letiltott feloldóknak válaszolnak.


## Exportok

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

### Osztályozó

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Beállítás                              | Alapértelmezés | Jelentés                                                                                                                                                 |
| -------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinson s és x paramétere: milyen erősen húzza a ritka jellemzőket 0,5 felé                                                                             |
| `minDistance`                          | `0.1`          | Az ennél közelebb 0,5-höz eső jellemzőket figyelmen kívül hagyja                                                                                         |
| `maxClues`                             | `150`          | Levelenként összevont legerősebb jellemzők                                                                                                               |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Az `unsure` tartomány határai                                                                                                                            |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Egy nyelven szükséges ham levelek a teljes magabiztossághoz, és ötödannyi spam levél; kevesebb, ha az összes ham vagy spam `languageShare` aránya kisebb |
| `languagePrior`                        | `true`         | A szavak súlyozása a saját nyelvük számlálóihoz képest                                                                                                   |

A `merge(other)`, a `toJSON(options)`, a `Classifier.fromJSON(json)`, a `size` és az `entries()` is elérhető. A `Classifier.fromJSON` ellenőrzi a modellt, és sérült adatoknál `Corrupt classifier model` kezdetű `TypeError` hibát dob. A JSON-ban nincs `Infinity`, így a 7.0.3-as verzió által `Infinity` értékkel mentett beállítás `null` értékként olvasható vissza: `Infinity` értéknek számít a `maxClues`, a `minDistance` és a `minLanguageExamples` esetén, `-Infinity` értéknek a `hamCutoff` (soha nem ham) és `Infinity` értéknek a `spamCutoff` (soha nem spam) esetén, a többinél pedig az alapértéknek. A `toJSON` a 0-n és 1-en túli küszöböt -1-ként vagy 2-ként menti, ami ugyanúgy működik. A `loadModel` újra beolvassa a fájlt, ha megváltozik, a `saveModel` pedig egy új ideiglenes fájlon keresztül ír, amelyet lemezre ürít, mielőtt az lecseréli a modellt, amely megtartja a jogosultságait.

### Tanítás

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

Az `evaluate(classifier, examples)` `{label, features}` elemeket fogad, vagy a `readExamples(sources)` eredményét, amely ugyanazokat a forrásokat olvassa, mint a `train`, és visszaadja a darabszámokat, a precizitást, a felidézést, az F1-et, a pontosságot, valamint a téves pozitív, a téves negatív és a bizonytalan arányokat.

### Szerverek

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

A milter `onError` beállítása adja meg a válaszát, ha egy vizsgálat sikertelen, vagy a ClamAV nem tudott átvizsgálni egy mellékletet: `'tempfail'` (alapértelmezés) vagy `'accept'`, amely `X-Spam-Virus-Scan: failed` jelöléssel továbbengedi a levelet, a feladó által hozzáadott `X-Spam-*` fejlécek nélkül.

### ARF-jelentések

A `spamscanner/arf` visszaélési visszajelzési jelentéseket (RFC 5965) olvas és ír, abban a formátumban, amelyet a postafiók-szolgáltatók a spampanaszok jelentésére használnak:

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

A `parse()` Buffert, Uint8Arrayt vagy karakterláncot fogad. Az `ArfParser.tryParse()` kivétel dobása helyett `null` értéket ad vissza azoknál a leveleknél, amelyek nem jelentések, az `isArfMessage(mail)` pedig egy feldolgozott levelet ellenőriz. Az `originalHeaders` értéke `null`, ha a jelentés nem tartalmazza az eredeti levelet. A `create()` karakterláncot ad vissza, vagy `Buffer` objektumot, ha az `originalMessage` is az, így a bájtjai karakterkészlettől függetlenül megmaradnak.
