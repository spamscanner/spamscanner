<!-- source: ff63d002c5fd -->

<!--
label: Spamfilter for Node.js
title: Spamfilterbibliotek for e-post i Node.js
description: Skann e-post for spam, phishing og skadevare fra Node.js: én npm-pakke med en klassifiserer som kan trenes, ESM og CommonJS, smtp-server og typede resultater.
keywords: spamfilter Node.js, npm spamfilter, spamdeteksjon JavaScript, smtp-server spam, bibliotek for e-postspam, Nodemailer spamfilter
-->

# Spamfilterbibliotek for Node.js

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

`scan()` tar imot en Buffer, en streng, en Uint8Array eller en lesbar strøm, så SMTP-strømmen fra smtp-server kan sendes rett inn. CommonJS virker med `require('spamscanner')`, og TypeScript-typer er inkludert.


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


## Hva resultatet sier

Hvert resultat har en poengsum, en handling (`accept`, `tag` eller `reject`) og testene som slo ut, hver med poeng og en begrunnelse. De detaljerte resultatene inkluderer klassifisererens sannsynlighet og sterkeste indisier, alle funn for phishing og vedlegg, autentiseringsresultater og språket.


## Lær det opp

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Mer

* Serverne eksporteres også: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Språkmodeller: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Testet på Node.js 18, 20, 22 og 24, med 100 % testdekning.

[API-referanse](../../docs/api.md)
