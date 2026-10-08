<!-- source: ff63d002c5fd -->

<!--
label: Bộ lọc spam Node.js
title: Thư viện lọc spam email cho Node.js
description: Quét email tìm spam, phishing và mã độc từ Node.js: một gói npm với bộ phân loại huấn luyện được, ESM và CommonJS, tích hợp smtp-server và kết quả có kiểu.
keywords: bộ lọc spam Node.js, lọc spam npm, phát hiện spam JavaScript, lọc spam smtp-server, thư viện lọc spam email, lọc spam Nodemailer
-->

# Thư viện lọc spam cho Node.js

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

`scan()` nhận một Buffer, một chuỗi, một Uint8Array hoặc một readable stream, nên luồng SMTP từ smtp-server có thể được đưa thẳng vào. CommonJS hoạt động với `require('spamscanner')`, và có sẵn kiểu TypeScript.


## Với smtp-server

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


## Kết quả cho biết gì

Mỗi kết quả có một điểm số, một hành động (`accept`, `tag` hoặc `reject`) và các phép kiểm tra đã kích hoạt, mỗi phép kèm điểm và lý do. Kết quả chi tiết bao gồm xác suất của bộ phân loại và các dấu hiệu mạnh nhất, mọi phát hiện về phishing và tệp đính kèm, kết quả xác thực và ngôn ngữ.


## Dạy nó

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Thêm nữa

* Các máy chủ cũng được export: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Mô hình ngôn ngữ: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Được kiểm thử trên Node.js 18, 20, 22 và 24, với độ bao phủ kiểm thử 100%.

[Tham chiếu API](../../docs/api.md)
