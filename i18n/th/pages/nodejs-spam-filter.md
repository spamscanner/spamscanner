<!-- source: ff63d002c5fd -->

<!--
label: ตัวกรองสแปม Node.js
title: ไลบรารีตัวกรองสแปมอีเมลสำหรับ Node.js
description: สแกนอีเมลหาสแปม ฟิชชิง และมัลแวร์จาก Node.js: แพ็กเกจ npm เดียว มีตัวจำแนกที่ฝึกได้ รองรับ ESM และ CommonJS ใช้กับ smtp-server ได้ และมีชนิดข้อมูลของผลลัพธ์
keywords: ตัวกรองสแปม Node.js, ตัวกรองสแปม npm, ตรวจจับสแปม JavaScript, สแปม smtp-server, ไลบรารีกรองอีเมลขยะ, ตัวกรองสแปม Nodemailer
-->

# ไลบรารีตัวกรองสแปมสำหรับ Node.js

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

`scan()` รับ Buffer สตริง Uint8Array หรือ readable stream สตรีม SMTP จาก smtp-server จึงส่งเข้าไปได้โดยตรง CommonJS ใช้ได้ด้วย `require('spamscanner')` และมีชนิดข้อมูลของ TypeScript มาให้


## ใช้กับ smtp-server

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


## ผลลัพธ์บอกอะไร

แต่ละผลลัพธ์มีคะแนน การดำเนินการ (`accept`, `tag` หรือ `reject`) และการทดสอบที่ทำงาน ซึ่งแต่ละรายการมีคะแนนและเหตุผล ผลลัพธ์โดยละเอียดมีความน่าจะเป็นและเบาะแสที่แรงที่สุดของตัวจำแนก สิ่งที่พบทั้งหมดเกี่ยวกับฟิชชิงและไฟล์แนบ ผลการยืนยันตัวตน และภาษา


## สอนโมเดล

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## เพิ่มเติม

* เซิร์ฟเวอร์ถูก export ไว้ด้วย: `MilterServer`, `createHttpServer`, `createSpamdServer`
* โมเดลภาษา: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`
* ทดสอบบน Node.js 18, 20, 22 และ 24 ด้วย test coverage 100%

[เอกสารอ้างอิง API](../../docs/api.md)
