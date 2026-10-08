<!-- source: ff63d002c5fd -->

<!--
label: Node.js spam filtresi
title: E-posta için Node.js spam filtresi kitaplığı
description: Node.js'te e-postayı spam, kimlik avı ve kötü amaçlı yazılıma karşı tarayın: tek npm paketi, eğitilebilir sınıflandırıcı, ESM, CommonJS, smtp-server desteği.
keywords: Node.js spam filtresi, npm spam filtresi, JavaScript spam tespiti, smtp-server spam, e-posta spam kitaplığı, Nodemailer spam filtresi
-->

# Node.js spam filtresi kitaplığı

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

`scan()` bir Buffer, bir dize, bir Uint8Array veya okunabilir bir akış alır; böylece smtp-server'dan gelen SMTP akışı doğrudan verilebilir. CommonJS `require('spamscanner')` ile çalışır ve TypeScript türleri pakete dahildir.


## smtp-server ile

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


## Sonuç ne söyler

Her sonuçta bir puan, bir eylem (`accept`, `tag` veya `reject`) ve tetiklenen testler bulunur; her testin puanı ve nedeni vardır. Ayrıntılı sonuçlar sınıflandırıcının olasılığını ve en güçlü ipuçlarını, tüm kimlik avı ve ek bulgularını, kimlik doğrulama sonuçlarını ve dili içerir.


## Öğretin

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Daha fazlası

* Sunucular da dışa aktarılır: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Dil modelleri: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Node.js 18, 20, 22 ve 24 üzerinde %100 test kapsamıyla test edilmiştir.

[API başvurusu](../../docs/api.md)
