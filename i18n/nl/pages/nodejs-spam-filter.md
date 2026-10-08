<!-- source: ff63d002c5fd -->

<!--
label: Node.js-spamfilter
title: Node.js-spamfilterbibliotheek voor e-mail
description: Scan e-mail op spam, phishing en malware vanuit Node.js: één npm-pakket met een te trainen classifier, ESM en CommonJS, smtp-server en getypte resultaten.
keywords: Node.js spamfilter, npm spamfilter, JavaScript spamdetectie, smtp-server spam, e-mail spam bibliotheek, Nodemailer spamfilter
-->

# Node.js-spamfilterbibliotheek

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

`scan()` accepteert een Buffer, een string, een Uint8Array of een readable stream, zodat de SMTP-stream van smtp-server er direct in kan. CommonJS werkt met `require('spamscanner')`, en TypeScript-typen zijn inbegrepen.


## Met smtp-server

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


## Wat het resultaat zegt

Elk resultaat heeft een score, een actie (`accept`, `tag` of `reject`) en de tests die afgingen, elk met punten en een reden. De gedetailleerde resultaten bevatten de kans en de sterkste aanwijzingen van de classifier, elke bevinding over phishing en bijlagen, de authenticatieresultaten en de taal.


## Het bijleren

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Meer

* De servers worden ook geëxporteerd: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Taalmodellen: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Getest op Node.js 18, 20, 22 en 24, met 100% testdekking.

[API-referentie](../../docs/api.md)
