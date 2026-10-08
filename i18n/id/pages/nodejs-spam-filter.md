<!-- source: ff63d002c5fd -->

<!--
label: Filter spam Node.js
title: Pustaka filter spam Node.js untuk email
description: Pindai spam, phishing, dan malware dari Node.js: satu paket npm dengan pengklasifikasi yang dapat dilatih, ESM dan CommonJS, smtp-server, dan hasil bertipe.
keywords: filter spam Node.js, filter spam npm, deteksi spam JavaScript, spam smtp-server, pustaka spam email, filter spam Nodemailer
-->

# Pustaka filter spam Node.js

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

`scan()` menerima Buffer, string, Uint8Array, atau readable stream, sehingga stream SMTP dari smtp-server dapat langsung dimasukkan. CommonJS berfungsi dengan `require('spamscanner')`, dan tipe TypeScript sudah disertakan.


## Dengan smtp-server

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


## Isi hasilnya

Setiap hasil memiliki skor, tindakan (`accept`, `tag`, atau `reject`), dan tes yang terpicu, masing-masing dengan poin dan alasan. Hasil terperinci mencakup probabilitas pengklasifikasi dan petunjuk terkuatnya, setiap temuan phishing dan lampiran, hasil autentikasi, serta bahasanya.


## Ajari

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Lainnya

* Server-servernya juga diekspor: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Model bahasa: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Diuji pada Node.js 18, 20, 22, dan 24, dengan cakupan tes 100%.

[Referensi API](../../docs/api.md)
