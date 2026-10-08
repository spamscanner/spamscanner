<!-- source: ff63d002c5fd -->

<!--
label: Node.js-roskapostisuodatin
title: Node.js-roskapostisuodatinkirjasto sähköpostille
description: Tarkista sähköposti roskapostin, tietojenkalastelun ja haittaohjelmien varalta Node.js:ssä: npm-paketti, koulutettava luokitin, ESM, CommonJS ja smtp-server.
keywords: Node.js roskapostisuodatin, npm roskapostisuodatin, JavaScript roskapostin tunnistus, smtp-server roskaposti, sähköpostin roskapostikirjasto, Nodemailer roskapostisuodatin
-->

# Node.js-roskapostisuodatinkirjasto

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

`scan()` ottaa Bufferin, merkkijonon, Uint8Arrayn tai luettavan virran, joten smtp-serverin SMTP-virran voi antaa sille suoraan. CommonJS toimii kutsulla `require('spamscanner')`, ja TypeScript-tyypit ovat mukana.


## smtp-serverin kanssa

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


## Mitä tulos kertoo

Jokaisessa tuloksessa on pistemäärä, toiminto (`accept`, `tag` tai `reject`) ja lauenneet testit, kukin pisteineen ja syineen. Yksityiskohtaisissa tuloksissa ovat luokittimen todennäköisyys ja vahvimmat vihjeet, jokainen tietojenkalastelu- ja liitelöydös, todennuksen tulokset ja kieli.


## Opeta sitä

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Lisää

* Myös palvelimet ovat exportteina: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Kielimallit: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Testattu Node.js:n versioilla 18, 20, 22 ja 24, 100 %:n testikattavuudella.

[API-viite](../../docs/api.md)
