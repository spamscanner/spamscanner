<!-- source: b3cc9f949acd -->

# API-referencia

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Érdemes egyetlen szkennert létrehozni és újrahasználni: a modellt egyszer tölti be, a DNS- és nyelvimodell-válaszokat pedig gyorsítótárazza.


## Beállítások

Minden beállítás átadható a konstruktornak. A legtöbb egyetlen levélre a `scan()` számára is átadható, ekkor a konstruktor beállításai fölé kerülnek.

| Beállítás               | Alapértelmezés                   | Jelentés                                                                                                                         |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Az a pontszám, amelytől egy levél spam                                                                                           |
| `rejectThreshold`       | `15`                             | Az a pontszám, amelytől az `action` értéke `reject`                                                                              |
| `scores`                | `{}`                             | Pontok tesztenként: beállításkulcsok vagy tesztnevek ([tesztek és pontszámok](scoring.md))                                       |
| `classifier`            | beépített modell                 | Egy `Classifier`, egy modellobjektum, egy modellfájl elérési útja vagy `false`                                                   |
| `classifierOptions`     | `{}`                             | A beépített modell beállításai (lásd: [Osztályozó](#classifier))                                                                 |
| `allowedLanguages`      | `[]`                             | ISO 639-1 kódok; a többi nyelv `LANGUAGE_NOT_ALLOWED` találatot kap                                                              |
| `phishing.cloudflare`   | `true`                           | A Cloudflare szűrő DNS-feloldóinak megkérdezése a hivatkozások gépneveiről                                                       |
| `phishing.adult`        | `true`                           | A felnőtt oldalakat blokkoló családi DNS-feloldó megkérdezése is                                                                 |
| `phishing.maxHosts`     | `25`                             | Levelenként lekérdezett hivatkozás-gépnevek száma                                                                                |
| `phishing.homograph`    | `{}`                             | `brands` (a beépített lista cseréje), `extraBrands`, `allowlist` (soha meg nem jelölt domainek), `strictMode`                    |
| `dnsbl`                 | `{ip: [], domain: []}`           | DNS-tiltólista-zónák a kliens IP-címéhez és a hivatkozások domainjeihez                                                          |
| `dns`                   | `{servers: null, timeout: 3000}` | Névszerverek a DNS-ellenőrzésekhez (alapértelmezés: a rendszeré)                                                                 |
| `attachments`           | `true`                           | A mellékletek vizsgálata                                                                                                         |
| `macros`                | `true`                           | Makrók, aktív PDF-ek és RTF-objektumok megjelölése                                                                               |
| `arbitrary`             | `true`                           | A [szabályok](scoring.md#rules) futtatása                                                                                        |
| `authentication`        | `false`                          | `true` vagy `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                                         |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                                |
| `allowlist`, `denylist` |                                  | IP-címek, domainek vagy címek; a `reputation` rövidítése                                                                         |
| `clamav`                | `false`                          | `true` (alapértelmezett socket), `{socket}` vagy `{host, port}`                                                                  |
| `llm`                   | `null`                           | [Nyelvimodell-beállítások](llm.md#any-server-port-and-authentication), `mode`, `minScore` és `maxScore` értékkel                 |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: olyan modell, amelynek `classify([text])` válasza a `@tensorflow-models/toxicity` válaszához hasonló |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: olyan modell, amelynek `classify(imageBuffer)` válasza az `nsfwjs` válaszához hasonló                |
| `maxLength`             | `100000`                         | A beolvasott levéltörzs karaktereinek száma                                                                                      |
| `timeout`               | `10000`                          | Az egyes hálózati ellenőrzésekre engedélyezett idő ezredmásodpercben                                                             |
| `session`               | `{}`                             | Alapértelmezett SMTP-munkamenet-adatok                                                                                           |

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
| `getFeatures(mail)`                  | `{features, words, language, script, links}` egy feldolgozott levélhez         |
| `getTokens(text, locale)`            | Egy szöveg szavai                                                              |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                     |
| `parse(source)`                      | `{raw, mail}`, ahol a `mail` a mailparsertől származik                         |

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

A `phishing`, `attachments`, `executables`, `macros`, `viruses` és `arbitrary` mezőkben lévő találatok `type` és `message` mezővel rendelkező objektumok. A `String(finding)` az üzenetet adja.


## Exportok

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

### Osztályozó

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Beállítás                              | Alapértelmezés | Jelentés                                                                     |
| -------------------------------------- | -------------- | ---------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinson s és x paramétere: milyen erősen húzza a ritka jellemzőket 0,5 felé |
| `minDistance`                          | `0.1`          | Az ennél közelebb 0,5-höz eső jellemzőket figyelmen kívül hagyja             |
| `maxClues`                             | `150`          | Levelenként összevont legerősebb jellemzők                                   |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Az `unsure` tartomány határai                                                |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Egy nyelven mindkét osztályból szükséges levelek a teljes magabiztossághoz   |
| `languagePrior`                        | `true`         | A szavak súlyozása a saját nyelvük számlálóihoz képest                       |

A `merge(other)`, a `toJSON(options)`, a `Classifier.fromJSON(json)`, a `size` és az `entries()` is elérhető.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARF-jelentések

A `spamscanner/arf` visszaélési visszajelzési jelentéseket (RFC 5965) olvas és ír, abban a formátumban, amelyet a postafiók-szolgáltatók a spampanaszok jelentésére használnak:

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

Az `ArfParser.tryParse()` kivétel dobása helyett `null` értéket ad vissza azoknál a leveleknél, amelyek nem jelentések, az `isArfMessage(mail)` pedig egy feldolgozott levelet ellenőriz.
