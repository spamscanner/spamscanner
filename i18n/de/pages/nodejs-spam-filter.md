<!-- source: ff63d002c5fd -->

<!--
label: Node.js-Spamfilter
title: Spamfilter-Bibliothek für E-Mails in Node.js
description: E-Mails in Node.js auf Spam, Phishing und Malware prüfen: ein npm-Paket mit trainierbarem Klassifikator, ESM, CommonJS, smtp-server und TypeScript-Typen.
keywords: Node.js Spamfilter, npm Spamfilter, JavaScript Spamerkennung, smtp-server Spam, E-Mail Spam Bibliothek, Nodemailer Spamfilter
-->

# Spamfilter-Bibliothek für Node.js

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

`scan()` nimmt einen Buffer, einen String, ein Uint8Array oder einen lesbaren Stream entgegen, sodass der SMTP-Stream aus smtp-server direkt übergeben werden kann. CommonJS funktioniert mit `require('spamscanner')`, und TypeScript-Typen sind enthalten.


## Mit smtp-server

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


## Was das Ergebnis aussagt

Jedes Ergebnis hat einen Score, eine Aktion (`accept`, `tag` oder `reject`) und die ausgelösten Tests, jeweils mit Punkten und einer Begründung. Die detaillierten Ergebnisse enthalten die Wahrscheinlichkeit und die stärksten Hinweise des Klassifikators, jeden Phishing- und Anhangsbefund, die Authentifizierungsergebnisse und die Sprache.


## Anlernen

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Mehr

* Auch die Server werden exportiert: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Sprachmodelle: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Getestet unter Node.js 18, 20, 22 und 24, mit 100 % Testabdeckung.

[API-Referenz](../../docs/api.md)
