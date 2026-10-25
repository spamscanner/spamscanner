<!-- source: 4c8f9a16e4e6 -->

# תיעוד API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

כדאי ליצור סורק אחד ולהשתמש בו שוב: הוא טוען את המודל פעם אחת ושומר במטמון תשובות DNS ותשובות של מודל השפה.

הצהרות טיפוסים כלולות. הן דורשות TypeScript 4.7 ומעלה עם `import`, ו-5.3 ומעלה עם `require`.


## אפשרויות

אפשר להעביר כל אפשרות לבנאי. את רובן אפשר להעביר גם ל-`scan()` עבור הודעה אחת, ואז הן ממוזגות מעל האפשרויות של הבנאי. אפשרויות שמועברות כ-`undefined` שומרות על ברירת המחדל שלהן. את `classifier`, `classifierOptions`, `dns`, `phishing.homograph` ו-`strictIDNDetection` קורא הבנאי בלבד; קובץ או אובייקט מודל שניתנו ב-`classifier` נקראים שם, כך שמודל חסר או פגום זורק שגיאה מיד.

| אפשרות                  | ברירת מחדל                       | משמעות                                                                                                                                                                                                                   |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `threshold`             | `5`                              | הניקוד שבו הודעה היא ספאם                                                                                                                                                                                                |
| `rejectThreshold`       | `15`                             | הניקוד שבו `action` הוא `reject`                                                                                                                                                                                         |
| `scores`                | `{}`                             | נקודות לכל בדיקה: מפתחות הגדרה או שמות בדיקות ([בדיקות וניקוד](scoring.md))                                                                                                                                              |
| `classifier`            | המודל המצורף                     | ‏`Classifier`, אובייקט מודל, נתיב לקובץ מודל, או `false`                                                                                                                                                                 |
| `classifierOptions`     | `{}`                             | אפשרויות למודל המצורף (ראו [Classifier](#classifier))                                                                                                                                                                    |
| `allowedLanguages`      | `[]`                             | קודי ISO 639-1 (`no` נקרא כ-`nb`,‏ `fil` כ-`tl`, והקודים הישנים `iw`,‏ `in`,‏ `ji` כ-`he`,‏ `id`,‏ `yi`); שפות אחרות מקבלות `LANGUAGE_NOT_ALLOWED`                                                                       |
| `phishing.cloudflare`   | `true`                           | לשאול את שרתי ה-DNS המסננים של Cloudflare על המארחים שבקישורים                                                                                                                                                           |
| `phishing.adult`        | `true`                           | לשאול גם את שרת ה-DNS המשפחתי, שחוסם אתרים למבוגרים                                                                                                                                                                      |
| `phishing.maxHosts`     | `25`                             | מספר המארחים מקישורים שנבדקים בכל הודעה                                                                                                                                                                                  |
| `phishing.attachments`  | `false`                          | כשבודקים מארחים מקישורים, לקרוא גם את הקישורים של ההודעה כולה ושל מה שהיא נושאת, למשך חמש שניות לכל היותר: הודעות מצורפות, קובצי HTML, SVG ו-XML, קובצי טקסט, הזמנות וכרטיסי איש קשר, ומסמכים ב-iframes ובכתובות `data:` |
| `phishing.hostsInText`  | `false`                          | לבדוק גם שמות מארחים שנכתבו בלי קישור או נתיב (`evil.example`), שתוכנות דואר הופכות לקישורים, אחרי הקישורים, ככל שיש מקום                                                                                                |
| `phishing.timeout`      | `timeout`                        | אלפיות השנייה שבדיקות הקישורים רשאיות להימשך בסך הכול                                                                                                                                                                    |
| `phishing.maxLength`    | `1000000`                        | תווי הטקסט שנקראים לאיתור קישורים (פי שניים ב-HTML); טקסט ארוך יותר מגדיר את `results.linksTruncated`; `Infinity`, או כל דבר שאינו מספר חיובי, פירושו ברירת המחדל                                                        |
| `phishing.homograph`    | `{}`                             | `brands` (מחליף את הרשימה המובנית), `extraBrands`, `allowlist` (דומיינים שלעולם לא מסומנים), `strictMode`                                                                                                                |
| `dnsbl`                 | `{ip: [], domain: []}`           | אזורי רשימות שחורות ב-DNS עבור ה-IP של הלקוח ועבור דומיינים מקישורים                                                                                                                                                     |
| `dns`                   | `{servers: null, timeout: 3000}` | שרתי שמות לבדיקות DNS (ברירת מחדל: של המערכת)                                                                                                                                                                            |
| `attachments`           | `true`                           | לבדוק קבצים מצורפים                                                                                                                                                                                                      |
| `macros`                | `true`                           | לסמן פקודות מאקרו, קובצי PDF פעילים ואובייקטי RTF                                                                                                                                                                        |
| `arbitrary`             | `true`                           | להריץ את [הכללים](scoring.md#rules)                                                                                                                                                                                      |
| `authentication`        | `false`                          | `true`, או `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF,‏ DKIM,‏ DMARC,‏ ARC ([ניקוד](scoring.md#authentication))                                                                        |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; התשובות נשמרות לפי שירות וכותרות, ו-`cacheSize` חל על הסורק כולו                                                                    |
| `allowlist`, `denylist` |                                  | כתובות IP, דומיינים או כתובות; קיצור של `reputation` → [רשימת היתר ורשימת חסימה](#allowlist-and-denylist)                                                                                                                |
| `clamav`                | `false`                          | `true` (ה-socket ברירת המחדל), `{socket}` או `{host, port}`, עם `timeout`: אלפיות שנייה לכל הקבצים המצורפים של הודעה (`60000`)                                                                                           |
| `llm`                   | `null`                           | [הגדרות מודל השפה](llm.md#any-server-port-and-authentication), עם `mode`, `minScore`, `maxScore`                                                                                                                         |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: מודל שה-`classify([text])` שלו עונה כמו `@tensorflow-models/toxicity`                                                                                                                        |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: מודל שה-`classify(imageBuffer)` שלו עונה כמו `nsfwjs`                                                                                                                                        |
| `maxLength`             | `100000`                         | מספר התווים מגוף ההודעה שנקראים                                                                                                                                                                                          |
| `timeout`               | `10000`                          | אלפיות השנייה שמוקצות לכל בדיקת רשת; האימות ומודל התמונות מקבלים את הזמן הזה בסך הכול (ל-ClamAV יש `clamav.timeout` משלו)                                                                                                |
| `session`               | `{}`                             | פרטי ברירת מחדל של שיחת ה-SMTP                                                                                                                                                                                           |

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

שרת שכבר בדק SPF,‏ DKIM,‏ DMARC ו-ARC (בעזרת [mailauth](https://github.com/postalsys/mailauth)) יכול להעביר את התוצאות שלו כ-`authenticationResults`, והן מקבלות ניקוד במקום להיבדק שוב:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### רשימת היתר ורשימת חסימה

רשימת החסימה משווה את כתובת ה-IP ושם המארח של הלקוח, את כתובות From, שולח המעטפה ו-Reply-To, ואת הדומיינים שלהן, יהיו אשר יהיו: שם שנמצא תחת דומיין שברשימת החסימה תואם אותו גם אם אינו שם מארח תקין (כמו `a_b!.evil.example`, או שם שיש בו תווית של יותר מ-63 תווים), לפי 127 התוויות ו-253 התווים האחרונים שלו. רשימת ההיתר, וכן רשימת ההיתר ומקורות האמת של שירות מוניטין, משווים רק את מה שהשולח אינו יכול לזייף: כתובת ה-IP ושם המארח המאומת של הלקוח (`remoteAddress`, `resolvedClientHostname`), כתובת From כש-DMARC עובר עבור הדומיין שלה או שחתימת DKIM תקפה מיושרת איתה (והוא שם מארח תקין; ביישור גמיש, כמו ב-DMARC: לדומיין של From ולדומיין החותם או דומיין ה-SPF יש אותו דומיין בר-רישום, ש-mailauth מציין כדומיין ה-DMARC; רשומה שמציינת תת-דומיין, כמו `news.example.com`, נחשבת רק כשאותו דומיין, דומיין שמתחתיו או דומיין שמעליו חתם על ההודעה או עבר SPF, לא תת-דומיין אחר כמו `evil.example.com`, וגם לא סיומת ציבורית; מעבר DMARC עבור הדומיין בר-הרישום ללא פרטי היישור של mailauth נחשב רק עבור רשומה שמציינת את הדומיין בר-הרישום; ביישור קפדני, `adkim=s` או `aspf=s` ברשומת ה-DMARC של הדומיין, בכל רישיות או ריווח, נחשבים רק חתימה או מעבר SPF של דומיין ה-From עצמו, ובלעדיהם DMARC נכשל), ושולח המעטפה כש-SPF עובר עבור הדומיין שלו. חתימת DKIM של תחילת גוף ההודעה בלבד (אורך גוף, `l=`, קצר מהגוף: כל אחד יכול להוסיף טקסט אחריו) אינה נחשבת כלל, וכך גם מעבר DMARC שנשען על חתימה כזו, ושום חתימה אינה נחשבת כש-DMARC נכשל, וגם לא עבור שדה From ארוך מכדי להיקרא במלואו (`mail.from.truncated`). תוצאות שמועברות ב-`authenticationResults` נחשבות רק כשהן מציינות את הדומיין שעבורו עברו, ודומיין שאינו שם מארח (כמו `bank.example/x.attacker.example`, שמפענחי URL קוראים כ-`bank.example`) אינו נחשב עבור אף דומיין, וכך גם מעבר DMARC שנשען על דומיין כזה. דומיינים בינלאומיים תואמים בשתי הצורות: `bücher.example` או `xn--bcher-kva.example`. Reply-To לעולם אינו נחשב. כדי להתיר דומיין, הפעילו את `authentication` או העבירו `authenticationResults`.

כל רשומה היא כתובת IP אחת, דומיין אחד או כתובת דואר אלקטרוני אחת, ומושווית במדויק: רשומת דומיין מכסה גם את תת-הדומיינים שלו ואת הכתובות בהם, אבל אין טווחי כתובות (`192.0.2.0/24`), תווים כלליים (`*.example.com`) או תבניות (`@example.com`). כתובות IPv6 תואמות בכל צורת כתיבה (`2001:0db8::0001` היא `2001:db8::1`, הצורה של RFC 5952), כתובת IPv4 שממופה לתוך IPv6 ‏(`::ffff:192.0.2.1`) תואמת את כתובת ה-IPv4, וכתובת IPv4 שתורגמה ל-IPv6 או שנמצאת תחת קידומת NAT64 נכתבת עם כתובת ה-IPv4 בצורה עשרונית מנוקדת (`::ffff:0:192.0.2.1`,‏ `64:ff9b::192.0.2.1`), הן ברשומות והן בכתובות של לקוחות.


## מתודות

| מתודה                                | מחזירה                                                                     |
| ------------------------------------ | -------------------------------------------------------------------------- |
| `scan(source, options)`              | את התוצאה. `source` הוא Buffer, מחרוזת, Uint8Array או זרם קריא             |
| `scanFile(path, options)`            | את התוצאה עבור קובץ הודעה                                                  |
| `learn(source, 'spam' \| 'ham')`     | מלמדת את המסווג הודעה אחת                                                  |
| `unlearn(source, 'spam' \| 'ham')`   | מבטלת `learn`                                                              |
| `saveModel(path, options)`           | כותבת את המסווג לקובץ (`options`: `minCount`, `maxFeatures`, `metadata`)   |
| `getClassifier()`                    | את ה-`Classifier` שבשימוש, או `null`                                       |
| `getClassification(features)`        | את פסק הדין של המסווג עבור מאפיינים מ-`getFeatures`                        |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` של הודעה |
| `getTokens(text, locale)`            | את המילים של טקסט                                                          |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                 |
| `parse(source)`                      | `{raw, mail, error}`, כש-`mail` מגיע מ-mailparser (ראו בהמשך)              |

`scan`,‏ `parse`,‏ `learn`,‏ `unlearn` ו-`getTokensAndMailFromSource` קוראות כולן הודעה באותו אופן: הודעה שחורגת מהמגבלות של מפענח ה-MIME ‏(יותר מ-1000 חלקים, כותרות של חלק מעל 1 MB) נקראת עד כמה שהמפענח מאפשר. שדות כתובת (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To ו-List-\*), של ההודעה, של חלקיה ושל הודעות מצורפות, נקראים עד 16 KB כל אחד, 2000 פסיקים ונקודה-פסיקים ו-16 קבוצות מקוננות, ועד 64 KB בסך הכול לכל הודעה, תמיד עד סוף כתובת שלמה, כך שלא נקראת שום כתובת שהשדה אינו מספק; שדה שנחתך מסומן `truncated` ‏(`mail.to.truncated`), ושדה From שנחתך אינו מקנה שום זיכוי על האימות של השולח. טקסט שהשורה הראשונה שלו אינה שדה כותרת (`Name: value`, או שורת ה-`From` שפותחת כל הודעה בקובצי mbox) נקרא כגוף של הודעה בלי כותרות, כך ש-`mail.text` הוא הטקסט הזה. שגיאות אחרות נזרקות. `parse` מחזיר ב-`error` את מגבלת המפענח שהודעה חורגת ממנה, כפי ש-`scan` מחזיר אותה ב-`parseError`, ו-null עבור הודעה שנקראה במלואה.

ב-`getFeatures`, ‏`text` הוא הטקסט שתוכנת דואר מציגה, שממנו נקראות המילים, ו-`hidden` הוא מספר התווים של טקסט שה-HTML מסתיר. כאן mailparser אינו מפיק טקסט מ-HTML: ‏`mail.text` מכיל רק את חלקי הטקסט הפשוט, והוא ריק בהודעה שכולה HTML; הטקסט שה-HTML שלה מציג הוא `getFeatures(mail).text`.

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
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    linksTooComplex: false, // a link host never read whole (cut where long text is cut, wrapped deeper than unwrapped, or in more documents than are read)
    linksIncomplete: false, // an attachment left unread for its links, for time
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
  attached: [],          // its attachments and those of its attached messages, named after them: fw.eml/invoice.exe
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

ממצאים ב-`phishing`, ‏`attachments`, ‏`executables`, ‏`macros`, ‏`viruses` ו-`arbitrary` הם אובייקטים עם `type` ו-`message`. ‏`String(finding)` הוא ההודעה. קבצים מצורפים של הודעה מצורפת (`message/rfc822`, `message/global`, `.eml`, `.u8msg`) נקראים על שמה: `fw.eml/invoice.exe`. וירוס ש-ClamAV מוצא בקובץ מצורף כזה מדווח עבורו בלבד, ולא שוב עבור ההודעה המצורפת שמכילה אותו. `virusScanErrors` מפרט את הקבצים המצורפים ש-ClamAV לא הצליח לסרוק, בתור `{filename, error}`: הודעה כזו עלולה להכיל וירוס, לכן עדיף לעכב אותה ולא למסור אותה. ה-milter ומסנן התוכן דוחים אותה למועד מאוחר יותר, אלא אם `onError` ‏(`--on-error`) הוא `accept`, וכל שרת מסמן הודעה כזו שהוא מעביר הלאה ב-`X-Spam-Virus-Scan: failed`. `virusScanSkipped` מפרט את אלה שגדולים ממה ש-clamd מקבל (ה-`StreamMaxLength` שלו), בתור `{filename, reason}`: ‏clamd דוחה אותם בכל ניסיון, ולכן, כפי ש-clamav-milter מדלג על קובץ שחורג מה-`MaxFileSize` שלו, הם אינם כישלונות. המגבלות האחרות שלו (`MaxScanSize`, ‏`MaxFiles`, ‏`MaxRecursion`, ‏`MaxScanTime`), שפצצת ארכיון מגיעה אליהן, הן כישלונות. הודעות מצורפות נפתחות עד שלוש רמות עומק, עם לכל היותר 100 קבצים מצורפים בתוכן ו-25 MB בסך הכול; `unopenedAttachments` מפרט את אלה שלא נפתחו מעבר למגבלות אלה, בצורה `{filename, reason}`, והקבצים המצורפים שלהן לא נבדקו. הוא אינו נספר בציון, כי הודעות שהועברו עשויות להיות מקוננות כך, אבל קורא שזקוק להודעה שנקראה במלואה, למשל כדי לחסום תוכנה שהיא נושאת, יכול לדחות הודעה שיש בה כזו. נפתחות לכל היותר 100 הודעות מצורפות בסך הכול.

כל פריט ב-`dnsbl` נושא את ה-`answers` של הרשימה (כתובות בטווח 127.0.0.0/8, שכל רשימה מתעדת את משמעותן). התשובות שרשימות נותנות לשאילתות שהן מסרבות להן או אינן יכולות לענות עליהן אינן רישומים, לא עבור כתובת הלקוח ולא עבור דומיינים של קישורים (ממצאי `uribl` ב-`phishing`): ‏127.255.255.x ב-Spamhaus (כמו 127.255.255.254 לשאילתה דרך שרת DNS ציבורי, ו-127.255.255.255 ליותר מדי שאילתות), 127.0.1.255 ב-Spamhaus DBL, ‏127.0.0.255 בכל רשימה, ו-127.0.0.1 ב-SURBL וב-URIBL, שעונות כך לשרתי DNS שהן חוסמות.


## ייצואים

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

| אפשרות                                 | ברירת מחדל     | משמעות                                                                                                                               |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `strength`, `unknown`                  | `0.45`, `0.5`  | ה-s וה-x של Robinson: כמה חזק מאפיינים נדירים נמשכים לכיוון 0.5                                                                      |
| `minDistance`                          | `0.1`          | מאפיינים שקרובים ל-0.5 יותר מזה מתעלמים מהם                                                                                          |
| `maxClues`                             | `150`          | מספר המאפיינים החזקים ביותר שמשולבים בכל הודעה                                                                                       |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | גבולות הטווח `unsure`                                                                                                                |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | מספר הודעות ה-ham שנדרשות בשפה כדי להגיע לביטחון מלא, וחמישית מכך הודעות spam; פחות כש-`languageShare` מכלל ה-ham או ה-spam קטן יותר |
| `languagePrior`                        | `true`         | לשקול מילים מול הספירות של השפה שלהן                                                                                                 |

גם `merge(other)`, ‏`toJSON(options)`, ‏`Classifier.fromJSON(json)`, ‏`size` ו-`entries()` זמינים. `Classifier.fromJSON` בודק את המודל וזורק `TypeError` שמתחיל ב-`Corrupt classifier model` כשהנתונים פגומים. ב-JSON אין `Infinity`, ולכן אפשרות שגרסה 7.0.3 שמרה כ-`Infinity` נקראת בחזרה כ-`null`: היא נקראת כ-`Infinity` עבור `maxClues`, ‏`minDistance` ו-`minLanguageExamples`, כ-`-Infinity` עבור `hamCutoff` (לעולם לא ham) וכ-`Infinity` עבור `spamCutoff` (לעולם לא spam), וכערך ברירת המחדל עבור השאר. `toJSON` שומר סף שמעבר ל-0 ול-1 כ-‎-1 או 2, וזה פועל באותו אופן. `loadModel` קורא קובץ מחדש כשהוא משתנה, ו-`saveModel` כותב דרך קובץ זמני חדש, שנכתב לדיסק לפני שהוא מחליף את המודל, וההרשאות של המודל נשמרות.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

‏`onError` של ה-milter הוא התשובה שלו כשסריקה נכשלת או כש-ClamAV לא הצליח לסרוק קובץ מצורף: `'tempfail'` (ברירת המחדל) או `'accept'`, שמעביר את ההודעה הלאה מסומנת ב-`X-Spam-Virus-Scan: failed`, בלי כותרות ה-`X-Spam-*` שהשולח הוסיף.

### דוחות ARF

`spamscanner/arf` קורא וכותב דוחות משוב על שימוש לרעה (RFC 5965), הפורמט שספקי תיבות דואר משתמשים בו כדי לדווח על תלונות ספאם:

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

`parse()` מקבלת Buffer, Uint8Array או מחרוזת. `ArfParser.tryParse()` מחזירה `null` במקום לזרוק שגיאה עבור הודעות שאינן דוחות, ו-`isArfMessage(mail)` בודקת הודעה מפוענחת. `originalHeaders` הוא `null` עבור דוח ללא ההודעה המקורית. `create()` מחזירה מחרוזת, או `Buffer` כאשר `originalMessage` הוא כזה, כך שהבתים שלה נשמרים בכל ערכת תווים.
