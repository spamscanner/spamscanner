<!-- source: ff63d002c5fd -->

<!--
label: Spamový filtr pro Node.js
title: Knihovna pro filtrování spamu v e-mailech pro Node.js
description: Kontrola e-mailů na spam, phishing a malware z Node.js: balíček npm, trénovatelný klasifikátor, ESM i CommonJS, integrace se smtp-server a typované výsledky.
keywords: spamový filtr Node.js, spamový filtr npm, detekce spamu JavaScript, smtp-server spam, knihovna pro e-mailový spam, spamový filtr Nodemailer
-->

# Knihovna pro filtrování spamu pro Node.js

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

`scan()` přijímá Buffer, řetězec, Uint8Array nebo čitelný stream, takže stream SMTP ze smtp-server může jít rovnou dovnitř. CommonJS funguje s `require('spamscanner')` a typy pro TypeScript jsou součástí.


## Se smtp-server

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


## Co říká výsledek

Každý výsledek má skóre, akci (`accept`, `tag` nebo `reject`) a testy, které se spustily, každý s body a důvodem. Podrobné výsledky obsahují pravděpodobnost a nejsilnější indicie klasifikátoru, každý nález phishingu a příloh, výsledky ověření a jazyk.


## Učení

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Další možnosti

* Exportované jsou i servery: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Jazykové modely: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Otestováno na Node.js 18, 20, 22 a 24 se 100% pokrytím testy.

[Reference API](../../docs/api.md)
