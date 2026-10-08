<!-- source: ff63d002c5fd -->

<!--
label: Filtro antispam per Node.js
title: Libreria Node.js di filtro antispam per la posta elettronica
description: Analizza le email da Node.js per spam, phishing e malware: un pacchetto npm con classificatore addestrabile, ESM e CommonJS, smtp-server e tipi inclusi.
keywords: filtro antispam Node.js, filtro antispam npm, rilevamento spam JavaScript, smtp-server spam, libreria antispam email, filtro antispam Nodemailer
-->

# Libreria Node.js di filtro antispam

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

`scan()` accetta un Buffer, una stringa, un Uint8Array o uno stream leggibile, quindi lo stream SMTP di smtp-server può essere passato direttamente. CommonJS funziona con `require('spamscanner')`, e i tipi TypeScript sono inclusi.


## Con smtp-server

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


## Cosa dice il risultato

Ogni risultato ha un punteggio, un'azione (`accept`, `tag` o `reject`) e i test scattati, ciascuno con punti e motivo. I risultati dettagliati includono la probabilità del classificatore e gli indizi più forti, ogni rilevamento su phishing e allegati, i risultati dell'autenticazione e la lingua.


## Insegnargli

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Altro

* Anche i server sono esportati: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Modelli linguistici: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Testato su Node.js 18, 20, 22 e 24, con copertura dei test al 100%.

[Riferimento API](../../docs/api.md)
