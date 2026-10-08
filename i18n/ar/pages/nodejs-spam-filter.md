<!-- source: ff63d002c5fd -->

<!--
label: مرشِّح بريد مزعج لـ Node.js
title: مكتبة Node.js لترشيح البريد المزعج في البريد الإلكتروني
description: افحص البريد بحثًا عن البريد المزعج والتصيّد والبرمجيات الخبيثة من Node.js: حزمة npm واحدة بمصنِّف قابل للتدريب، وESM وCommonJS، وتكامل مع smtp-server.
keywords: فلتر بريد مزعج Node.js, فلتر بريد مزعج npm, كشف البريد المزعج بـ JavaScript, البريد المزعج في smtp-server, مكتبة لكشف البريد المزعج, فلتر بريد مزعج Nodemailer
-->

# مكتبة Node.js لترشيح البريد المزعج

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

تأخذ `scan()` قيمة Buffer أو سلسلة نصية أو Uint8Array أو تدفقًا قابلًا للقراءة، فيمكن تمرير تدفق SMTP من smtp-server مباشرة. يعمل CommonJS مع `require('spamscanner')`، وأنواع TypeScript مضمَّنة.


## مع smtp-server

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


## ماذا تقول النتيجة

لكل نتيجة درجة، وإجراء (`accept` أو `tag` أو `reject`)، والاختبارات التي انطبقت، ولكل منها نقاط وسبب. تتضمن النتائج المفصلة احتمال المصنِّف وأقوى قرائنه، وكل نتيجة لفحوص التصيّد الاحتيالي والمرفقات، ونتائج المصادقة، واللغة.


## علّمه

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## المزيد

* الخوادم مُصدَّرة أيضًا: `MilterServer` و`createHttpServer` و`createSpamdServer`.
* النماذج اللغوية: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* مُختبَر على Node.js 18 و20 و22 و24، بتغطية اختبارات 100%.

[مرجع API](../../docs/api.md)
