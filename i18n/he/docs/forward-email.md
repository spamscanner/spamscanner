<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner נבנה על ידי [Forward Email](https://forwardemail.net), שירות הדואר האלקטרוני בקוד פתוח שמתמקד בפרטיות, עבור שרתי הדואר שלה. Forward Email לא שומרת יומנים של תוכן ההודעות, ולכן שום שירות סינון חיצוני לא התאים: המסנן היה צריך לרוץ על השרתים שלה, ולהסביר כל החלטה בלי שאדם יקרא את הדואר.

הדף הזה מראה איך שרת דואר כמו של Forward Email משתמש בו, ומה השתנה עבור קוד שנכתב ל-Spam Scanner 5 או 6.


## בשרת דואר נכנס

Forward Email מקבלת דואר בעזרת [smtp-server](https://nodemailer.com/extras/smtp-server/). הדפוס, לכל שרת שבנוי עליו:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()` מקבלת את זרם ה-SMTP ישירות. כשתוצאות [mailauth](https://github.com/postalsys/mailauth) כבר זמינות, אפשר לוותר על `authentication` ולהעביר רק את כתובת ה-IP.

תשובה של 421 או 451 גורמת לשרת השולח להכניס את ההודעה לתור ולנסות שוב מאוחר יותר. כללי דחייה חדשים יכולים להתחיל בקוד זמני ולעבור ל-550 אחרי שהתוצאות שלהם נבדקו, בלי לאבד דואר בינתיים.


## שדרוג מגרסה 5 או 6

גרסה 7 היא כתיבה מחדש. הבנאי, `scan()` ושדות התוצאה שקוד של גרסאות 5 ו-6 קורא עדיין עובדים; המסווג, המודל ובדיקות ה-TensorFlow האופציונליות השתנו.

### מה נשאר כמו שהיה

* `new SpamScanner(options)` ו-`await scanner.scan(source)`.
* `require('spamscanner')` מחזיר את המחלקה, ו-`import SpamScanner from 'spamscanner'` עובד.
* `result.isSpam`, ‏`result.message`, ו-`result.results.classification`, ‏`.phishing`, ‏`.executables`, ‏`.arbitrary`, ‏`.viruses`, ‏`.macros` ו-`.idnHomographAttack`.
* כל פריט ב-`results.phishing`, ‏`.executables`, ‏`.arbitrary` ו-`.viruses` מומר לאותו סוג של מחרוזת הודעה כמו קודם (`String(item)`, תבניות מחרוזת, `message.includes('adult-related content')`). עכשיו הם אובייקטים עם `type`, ‏`message` ופרטים.
* `getTokensAndMailFromSource()`, ‏`getClassification()` ו-`getTokens()`.
* האפשרויות האלה ממופות לשמות החדשים שלהן: `clamscan` ל-`clamav`, ‏`enableMacroDetection: false` ל-`macros: false`, ‏`enableArbitraryDetection: false` ל-`arbitrary: false`, ‏`enableAuthentication` עם `authOptions` ל-`authentication` ו-`session`, ‏`enableReputation` עם `reputationOptions.apiUrl` ל-`reputation`, ‏`strictIDNDetection` ל-`phishing.homograph.strictMode`, וגם `allowlist` ו-`denylist`. ‏`logger` ו-`memoize` מתקבלות ומתעלמים מהן.

### מה השתנה

| לפני                                                                | עכשיו                                                                                                                                              |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` קרא את הקובץ                             | מחרוזת היא טקסט של הודעה. יש להשתמש ב-`scanFile(path)` או להעביר Buffer                                                                            |
| מודל Bayes נאיבי של מילים (`classifier.json`), שאי אפשר לטעון עכשיו | מסווג חדש ופורמט מודל חדש; יש לאמן מחדש עם `spamscanner train` ([אימון](training.md))                                                              |
| בדיקות הרעילות וה-NSFW טענו מודלי TensorFlow מהרשת בשימוש הראשון    | מביאים מודל משלכם: `toxicity: {model}` ו-`nsfw: {model}` מקבלים כל אובייקט עם מתודה `classify()`, למשל מ-`@tensorflow-models/toxicity` ומ-`nsfwjs` |
| `results.arbitrary` פירט כל דפוס שהתאים                             | הוא מפרט כללים חזקים מספיק כדי לסמן ספאם בעצמם; כל הכללים נמצאים ב-`result.tests`                                                                  |
| תשובה של כן או לא                                                   | `result.score`, ‏`result.action` (`accept`, ‏`tag` או `reject`) ו-`result.tests`, כל אחד עם נקודות וסיבה                                           |
| `isSpam` נקבע על ידי המסווג או על ידי בדיקה בודדת כלשהי             | `isSpam` הוא ניקוד של 5 ומעלה; אפשר לשנות את הספים ואת הנקודות                                                                                     |
| בדיקות מוניטין מול נקודת קצה של Forward Email                       | שירות מוניטין כללי, כבוי אלא אם מוגדר `reputation.apiUrl`                                                                                          |

### מה חדש

* [מודלי שפה](llm.md) למקרים גבוליים, מקומיים או מתארחים.
* SPF,‏ DKIM,‏ DMARC ו-ARC; רשימות שחורות ב-DNS; שרתי ה-DNS המסננים של Cloudflare.
* בדיקות קבצים מצורפים לפי תוכן: קבצי הרצה מוסווים, ארכיונים, פקודות מאקרו, קובצי PDF פעילים.
* [milter, ‏HTTP API, שרת TCP ושרת spamd](mail-servers.md), ו[שורת פקודה](cli.md).
* אימון, הערכה ולמידה מדיווחים, משורת הפקודה או מה-API.
