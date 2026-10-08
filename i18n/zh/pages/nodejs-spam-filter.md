<!-- source: ff63d002c5fd -->

<!--
label: Node.js 垃圾邮件过滤
title: 用于电子邮件的 Node.js 垃圾邮件过滤库
description: 在 Node.js 中扫描电子邮件中的垃圾邮件、钓鱼和恶意软件：一个 npm 包，含可训练分类器、ESM 和 CommonJS、smtp-server 集成和带类型的结果。
keywords: Node.js 垃圾邮件过滤, npm 垃圾邮件过滤, JavaScript 垃圾邮件检测, smtp-server 垃圾邮件, 邮件反垃圾库, Nodemailer 垃圾邮件过滤
-->

# Node.js 垃圾邮件过滤库

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

`scan()` 接受 Buffer、字符串、Uint8Array 或可读流，因此来自 smtp-server 的 SMTP 流可以直接传入。CommonJS 可通过 `require('spamscanner')` 使用，并且已包含 TypeScript 类型。


## 配合 smtp-server

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


## 结果包含什么

每个结果都有分数、动作（`accept`、`tag` 或 `reject`）以及触发的测试，每项测试都附有分值和原因。详细结果包括分类器的概率和最强的线索、每一项钓鱼和附件发现、身份验证结果以及语言。


## 让它学习

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## 更多

* 服务器也会导出：`MilterServer`、`createHttpServer`、`createSpamdServer`。
* 语言模型：`new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`。
* 在 Node.js 18、20、22 和 24 上测试，测试覆盖率 100%。

[API 参考](../../docs/api.md)
