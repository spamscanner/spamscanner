<!-- source: 8263c06f1dab -->

# צעדים ראשונים

Spam Scanner דורש Node.js 18 ומעלה, או שום דבר בכלל עם הקובץ הבינארי העצמאי.


## התקנה

ככלי שורת פקודה:

```sh
npm install --global spamscanner
spamscanner version
```

כספרייה בפרויקט Node.js:

```sh
npm install spamscanner
```

כקובץ בינארי עצמאי ל-Linux או ל-macOS, עם Node.js והמודל מובנים בו:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

קבצים בינאריים ל-Linux (x64 ו-arm64), ל-macOS (Intel ו-Apple silicon) ול-Windows מצורפים לכל [גרסה](https://github.com/spamscanner/spamscanner/releases).


## סריקת הודעה

יש לשמור הודעה כקובץ (רוב תוכנות הדואר קוראות לזה „שמירה בשם” או „הצגת המקור”) ולסרוק אותה:

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

קוד היציאה הוא 0 ל-ham, 1 לספאם ו-2 לשגיאה, כך שסקריפטים יכולים להשתמש בו ישירות. `--json` מדפיס את התוצאה המלאה, ו-`--headers` מדפיס את ההודעה עם כותרות `X-Spam-*` שנוספו לה.

הודעות יכולות להגיע גם מהקלט הסטנדרטי:

```sh
cat message.eml | spamscanner scan -
```


## שימוש מתוך Node.js

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

גם CommonJS עובד:

```js
const SpamScanner = require('spamscanner');
```

`scan()` מקבלת את ההודעה הגולמית כ-Buffer, כמחרוזת, כ-Uint8Array או כזרם קריא. מחרוזת היא תמיד טקסט של הודעה: Spam Scanner לעולם לא קורא קובץ רק משום שמחרוזת נראית כמו נתיב. לקבצים יש להשתמש ב-`scanner.scanFile(path)`.


## מידע על שיחת ה-SMTP

כתובת ה-IP של הלקוח, שם המארח המאומת שלו, שם ה-HELO והמעטפה הופכים את התוצאה למדויקת יותר: האימות צריך את כתובת ה-IP, וכלל הזיוף העצמי צריך את הנמענים.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

אותו הדבר משורת הפקודה:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## הפעלת בדיקות נוספות

אף אחת מהבדיקות האלה לא מופעלת כברירת מחדל, כי כל אחת מהן צריכה שירות או החלטה:

| בדיקה                            | אפשרות בספרייה                                   | שורת הפקודה                 |
| -------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC            | `authentication: true`                           | `--auth`                    |
| רשימה שחורה של IP                | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| רשימה שחורה של דומיינים לקישורים | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                           | `clamav: true` או `clamav: {socket}`             | `--clamav [socket]`         |
| מודל שפה                         | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| רשימות היתר וחסימה               | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

כברירת מחדל נשאלים שרתי ה-DNS המסננים של Cloudflare‏ (1.1.1.2 לנוזקות, 1.1.1.3 לתוכן למבוגרים) על המארחים שבקישורים. אפשר לכבות זאת עם `phishing: {cloudflare: false}` או `--no-cloudflare`. [מה יוצא מהמחשב](security.md)

Spamhaus ועוד כמה רשימות שחורות לא עונות לשאילתות שנשלחות דרך שרתי DNS ציבוריים כמו 8.8.8.8 או 1.1.1.1. יש להשתמש בהן עם שרת DNS מקומי עם מטמון, ולבדוק את תנאי השימוש שלהן בהתאם לנפח הדואר.


## הצעדים הבאים

* להציב אותו לפני שרת דואר: [Postfix ו-Sendmail](postfix.md), [שרתים אחרים](mail-servers.md).
* ללמד אותו את הדואר שלכם: [אימון](training.md).
* להוסיף מודל שפה למקרים גבוליים: [מודלי שפה](llm.md).
