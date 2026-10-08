<!-- source: ff63d002c5fd -->

<!--
label: Node.js-spamfilter
title: Node.js-spamfilterbibliotek til e-mail
description: Scan e-mail for spam, phishing og malware fra Node.js: én npm-pakke med trænbar klassifikator, ESM og CommonJS, smtp-server-integration og typede resultater.
keywords: Node.js spamfilter, npm spamfilter, JavaScript spamdetektion, smtp-server spam, e-mail spambibliotek, Nodemailer spamfilter
-->

# Node.js-spamfilterbibliotek

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

`scan()` tager en Buffer, en streng, et Uint8Array eller en læsbar stream, så SMTP-streamen fra smtp-server kan gå direkte ind. CommonJS virker med `require('spamscanner')`, og TypeScript-typer er inkluderet.


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


## Hvad resultatet siger

Hvert resultat har en score, en handling (`accept`, `tag` eller `reject`) og de test, der slog til, hver med point og en begrundelse. De detaljerede resultater indeholder klassifikatorens sandsynlighed og stærkeste spor, alle fund om phishing og vedhæftede filer, godkendelsesresultater og sproget.


## Lær den op

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Mere

* Serverne eksporteres også: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Sprogmodeller: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Testet på Node.js 18, 20, 22 og 24 med 100 % testdækning.

[API-reference](../../docs/api.md)
