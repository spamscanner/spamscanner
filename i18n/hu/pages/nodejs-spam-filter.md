<!-- source: ff63d002c5fd -->

<!--
label: Node.js spamszűrő
title: Node.js spamszűrő könyvtár e-mailekhez
description: Levelek vizsgálata spamre, adathalászatra és kártevőkre Node.js-ből: egy npm-csomag tanítható osztályozóval, ESM és CommonJS, smtp-server, típusos eredmények.
keywords: Node.js spamszűrő, npm spamszűrő, JavaScript spamfelismerés, smtp-server spam, e-mail spamszűrő könyvtár, Nodemailer spamszűrő
-->

# Node.js spamszűrő könyvtár

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

A `scan()` Buffert, karakterláncot, Uint8Array-t vagy olvasható streamet fogad, így az smtp-server SMTP-streamje közvetlenül átadható. A CommonJS a `require('spamscanner')` hívással működik, és a TypeScript-típusok is benne vannak.


## smtp-serverrel

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


## Mit mond az eredmény

Minden eredményben van egy pontszám, egy művelet (`accept`, `tag` vagy `reject`) és a teljesült tesztek, mindegyik ponttal és okkal. A részletes eredmények tartalmazzák az osztályozó valószínűségét és legerősebb jeleit, minden adathalászati és mellékletre vonatkozó találatot, a hitelesítési eredményeket és a nyelvet.


## Tanítás

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## További tudnivalók

* A szerverek is exportálva vannak: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Nyelvi modellek: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Node.js 18, 20, 22 és 24 alatt tesztelve, 100%-os tesztlefedettséggel.

[API-referencia](../../docs/api.md)
