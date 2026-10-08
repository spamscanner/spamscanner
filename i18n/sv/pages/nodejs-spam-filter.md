<!-- source: ff63d002c5fd -->

<!--
label: Spamfilter för Node.js
title: Spamfilterbibliotek för e-post i Node.js
description: Skanna e-post efter spam, nätfiske och skadlig kod i Node.js: ett npm-paket med träningsbar klassificerare, ESM och CommonJS, smtp-server och typade resultat.
keywords: Node.js spamfilter, npm spamfilter, JavaScript spamdetektering, smtp-server spam, spambibliotek e-post, Nodemailer spamfilter
-->

# Spamfilterbibliotek för Node.js

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

`scan()` tar emot en Buffer, en sträng, en Uint8Array eller en läsbar ström, så SMTP-strömmen från smtp-server kan skickas rakt in. CommonJS fungerar med `require('spamscanner')`, och TypeScript-typer ingår.


## Med smtp-server

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


## Vad resultatet säger

Varje resultat har en poäng, en åtgärd (`accept`, `tag` eller `reject`) och de tester som slog till, vart och ett med poäng och en orsak. De detaljerade resultaten innehåller klassificerarens sannolikhet och starkaste ledtrådar, alla fynd om nätfiske och bilagor, autentiseringsresultat och språket.


## Lär upp det

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Mer

* Servrarna exporteras också: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Språkmodeller: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Testat på Node.js 18, 20, 22 och 24, med 100 % testtäckning.

[API-referens](../../docs/api.md)
