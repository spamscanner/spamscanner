<!-- source: b3cc9f949acd -->

# תיעוד API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

כדאי ליצור סורק אחד ולהשתמש בו שוב: הוא טוען את המודל פעם אחת ושומר במטמון תשובות DNS ותשובות של מודל השפה.


## אפשרויות

אפשר להעביר כל אפשרות לבנאי. את רובן אפשר להעביר גם ל-`scan()` עבור הודעה אחת, ואז הן ממוזגות מעל האפשרויות של הבנאי.

| אפשרות                  | ברירת מחדל                       | משמעות                                                                                                    |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | הניקוד שבו הודעה היא ספאם                                                                                 |
| `rejectThreshold`       | `15`                             | הניקוד שבו `action` הוא `reject`                                                                          |
| `scores`                | `{}`                             | נקודות לכל בדיקה: מפתחות הגדרה או שמות בדיקות ([בדיקות וניקוד](scoring.md))                               |
| `classifier`            | המודל המצורף                     | ‏`Classifier`, אובייקט מודל, נתיב לקובץ מודל, או `false`                                                  |
| `classifierOptions`     | `{}`                             | אפשרויות למודל המצורף (ראו [Classifier](#classifier))                                                     |
| `allowedLanguages`      | `[]`                             | קודי ISO 639-1; שפות אחרות מקבלות `LANGUAGE_NOT_ALLOWED`                                                  |
| `phishing.cloudflare`   | `true`                           | לשאול את שרתי ה-DNS המסננים של Cloudflare על המארחים שבקישורים                                            |
| `phishing.adult`        | `true`                           | לשאול גם את שרת ה-DNS המשפחתי, שחוסם אתרים למבוגרים                                                       |
| `phishing.maxHosts`     | `25`                             | מספר המארחים מקישורים שנבדקים בכל הודעה                                                                   |
| `phishing.homograph`    | `{}`                             | `brands` (מחליף את הרשימה המובנית), `extraBrands`, `allowlist` (דומיינים שלעולם לא מסומנים), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | אזורי רשימות שחורות ב-DNS עבור ה-IP של הלקוח ועבור דומיינים מקישורים                                      |
| `dns`                   | `{servers: null, timeout: 3000}` | שרתי שמות לבדיקות DNS (ברירת מחדל: של המערכת)                                                             |
| `attachments`           | `true`                           | לבדוק קבצים מצורפים                                                                                       |
| `macros`                | `true`                           | לסמן פקודות מאקרו, קובצי PDF פעילים ואובייקטי RTF                                                         |
| `arbitrary`             | `true`                           | להריץ את [הכללים](scoring.md#rules)                                                                       |
| `authentication`        | `false`                          | `true`, או `{dnsServers, timeout, mta, weights}`: SPF,‏ DKIM,‏ DMARC,‏ ARC                                |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                         |
| `allowlist`, `denylist` |                                  | כתובות IP, דומיינים או כתובות; קיצור של `reputation`                                                      |
| `clamav`                | `false`                          | `true` (ה-socket ברירת המחדל), `{socket}` או `{host, port}`                                               |
| `llm`                   | `null`                           | [הגדרות מודל השפה](llm.md#any-server-port-and-authentication), עם `mode`, `minScore`, `maxScore`          |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: מודל שה-`classify([text])` שלו עונה כמו `@tensorflow-models/toxicity`         |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: מודל שה-`classify(imageBuffer)` שלו עונה כמו `nsfwjs`                         |
| `maxLength`             | `100000`                         | מספר התווים מגוף ההודעה שנקראים                                                                           |
| `timeout`               | `10000`                          | אלפיות השנייה שמוקצות לכל בדיקת רשת                                                                       |
| `session`               | `{}`                             | פרטי ברירת מחדל של שיחת ה-SMTP                                                                            |

`scan()` מקבלת גם `session`:

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


## מתודות

| מתודה                                | מחזירה                                                                   |
| ------------------------------------ | ------------------------------------------------------------------------ |
| `scan(source, options)`              | את התוצאה. `source` הוא Buffer, מחרוזת, Uint8Array או זרם קריא           |
| `scanFile(path, options)`            | את התוצאה עבור קובץ הודעה                                                |
| `learn(source, 'spam' \| 'ham')`     | מלמדת את המסווג הודעה אחת                                                |
| `unlearn(source, 'spam' \| 'ham')`   | מבטלת `learn`                                                            |
| `saveModel(path, options)`           | כותבת את המסווג לקובץ (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | את ה-`Classifier` שבשימוש, או `null`                                     |
| `getClassification(features)`        | את פסק הדין של המסווג עבור מאפיינים מ-`getFeatures`                      |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` עבור הודעה מפוענחת          |
| `getTokens(text, locale)`            | את המילים של טקסט                                                        |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                               |
| `parse(source)`                      | `{raw, mail}`, כש-`mail` מגיע מ-mailparser                               |

`scanner.metrics` מכיל את `totalScans`, ‏`averageTime` ו-`lastScanTime`.


## התוצאה

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

ממצאים ב-`phishing`, ‏`attachments`, ‏`executables`, ‏`macros`, ‏`viruses` ו-`arbitrary` הם אובייקטים עם `type` ו-`message`. ‏`String(finding)` הוא ההודעה.


## ייצואים

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

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| אפשרות                                 | ברירת מחדל     | משמעות                                                          |
| -------------------------------------- | -------------- | --------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | ה-s וה-x של Robinson: כמה חזק מאפיינים נדירים נמשכים לכיוון 0.5 |
| `minDistance`                          | `0.1`          | מאפיינים שקרובים ל-0.5 יותר מזה מתעלמים מהם                     |
| `maxClues`                             | `150`          | מספר המאפיינים החזקים ביותר שמשולבים בכל הודעה                  |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | גבולות הטווח `unsure`                                           |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | מספר ההודעות מכל סוג שנדרשות בשפה כדי להגיע לביטחון מלא         |
| `languagePrior`                        | `true`         | לשקול מילים מול הספירות של השפה שלהן                            |

גם `merge(other)`, ‏`toJSON(options)`, ‏`Classifier.fromJSON(json)`, ‏`size` ו-`entries()` זמינים.

### אימון

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` מקבלת פריטי `{label, features}`, או את `readExamples(sources)`, שקוראת את אותם מקורות כמו `train`, ומחזירה ספירות, דיוק, רגישות, F1, נכונות ושיעורי חיוביות שגויות, שליליות שגויות ו„לא בטוח”.

### שרתים

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### דוחות ARF

`spamscanner/arf` קורא וכותב דוחות משוב על שימוש לרעה (RFC 5965), הפורמט שספקי תיבות דואר משתמשים בו כדי לדווח על תלונות ספאם:

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

`ArfParser.tryParse()` מחזירה `null` במקום לזרוק שגיאה עבור הודעות שאינן דוחות, ו-`isArfMessage(mail)` בודקת הודעה מפוענחת.
