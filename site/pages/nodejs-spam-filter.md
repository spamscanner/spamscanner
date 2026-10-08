<!--
label: Node.js spam filter
title: Node.js spam filter library for email
description: Scan email for spam, phishing and malware from Node.js: one npm package with a trainable classifier, ESM and CommonJS, smtp-server integration and typed results.
keywords: Node.js spam filter, npm spam filter, JavaScript spam detection, smtp-server spam, email spam library, Nodemailer spam filter
-->

# Node.js spam filter library

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

`scan()` takes a Buffer, a string, a Uint8Array or a readable stream, so the SMTP stream from smtp-server can go straight in. CommonJS works with `require('spamscanner')`, and TypeScript types are included.


## With smtp-server

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


## What the result says

Each result has a score, an action (`accept`, `tag` or `reject`) and the tests that fired, each with points and a reason. The detailed results include the classifier's probability and strongest clues, every phishing and attachment finding, authentication results and the language.


## Teach it

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## More

* The servers are exported too: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Language models: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Tested on Node.js 18, 20, 22 and 24, with 100% test coverage.

[API reference](../../docs/api.md)
