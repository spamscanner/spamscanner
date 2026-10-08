<!-- source: ff63d002c5fd -->

<!--
label: מסנן ספאם ל-Node.js
title: ספריית סינון ספאם ל-Node.js עבור דואר אלקטרוני
description: סריקת דואר לאיתור ספאם, פישינג ונוזקות מתוך Node.js: חבילת npm אחת עם מסווג שניתן לאמן, ESM ו-CommonJS, שילוב עם smtp-server ותוצאות מוקלדות.
keywords: מסנן ספאם Node.js, מסנן ספאם npm, זיהוי ספאם JavaScript, ספאם smtp-server, ספריית סינון ספאם לדואר אלקטרוני, מסנן ספאם Nodemailer
-->

# ספריית סינון ספאם ל-Node.js

```sh
npm install spamscanner
```

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner();
const result = await scanner.scan(rawMessage);

if (result.isSpam) {
  console.log(result.score, result.tests.map(test => test.name));
}
```

`scan()` מקבלת Buffer, מחרוזת, Uint8Array או זרם קריא, כך שזרם ה-SMTP מ-smtp-server יכול להיכנס ישירות. CommonJS עובד עם `require('spamscanner')`, והגדרות טיפוסים של TypeScript כלולות.


## עם smtp-server

```js
import {SMTPServer} from 'smtp-server';
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({authentication: true});

const server = new SMTPServer({
  async onData(stream, session, callback) {
    const result = await scanner.scan(stream, {
      session: {
        remoteAddress: session.remoteAddress,
        helo: session.hostNameAppearsAs,
        envelope: session.envelope,
      },
    });

    if (result.action === 'reject') {
      return callback(Object.assign(new Error('Message rejected as spam'), {responseCode: 451}));
    }

    callback();
  },
});
```


## מה התוצאה אומרת

לכל תוצאה יש ניקוד, פעולה (`accept`, ‏`tag` או `reject`) והבדיקות שהופעלו, כל אחת עם נקודות וסיבה. התוצאות המפורטות כוללות את ההסתברות של המסווג ואת הסימנים החזקים ביותר שלו, כל ממצא של פישינג ושל קבצים מצורפים, את תוצאות האימות ואת השפה.


## ללמד אותו

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## עוד

* גם השרתים מיוצאים: `MilterServer`, ‏`createHttpServer`, ‏`createSpamdServer`.
* מודלי שפה: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* נבדק על Node.js 18,‏ 20,‏ 22 ו-24, עם כיסוי בדיקות של 100%.

[תיעוד API](../../docs/api.md)
