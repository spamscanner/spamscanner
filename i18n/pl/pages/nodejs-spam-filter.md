<!-- source: ff63d002c5fd -->

<!--
label: Filtr antyspamowy Node.js
title: Biblioteka filtra antyspamowego Node.js dla poczty e-mail
description: Skanuj pocztę pod kątem spamu, phishingu i złośliwego oprogramowania z Node.js: pakiet npm z trenowalnym klasyfikatorem, ESM i CommonJS, smtp-server i typy.
keywords: filtr antyspamowy Node.js, filtr spamu npm, wykrywanie spamu JavaScript, smtp-server spam, biblioteka antyspamowa e-mail, filtr spamu Nodemailer
-->

# Biblioteka filtra antyspamowego Node.js

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

`scan()` przyjmuje Buffer, string, Uint8Array lub strumień do odczytu, więc strumień SMTP z smtp-server można przekazać bezpośrednio. CommonJS działa z `require('spamscanner')`, a typy TypeScript są dołączone.


## Z smtp-server

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


## Co mówi wynik

Każdy wynik ma punktację, akcję (`accept`, `tag` lub `reject`) i testy, które zadziałały, każdy z punktami i powodem. Szczegółowe wyniki obejmują prawdopodobieństwo według klasyfikatora i jego najsilniejsze wskazówki, każde ustalenie dotyczące phishingu i załączników, wyniki uwierzytelnienia oraz język.


## Uczenie

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Więcej

* Serwery też są eksportowane: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Modele językowe: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Przetestowany na Node.js 18, 20, 22 i 24, ze 100% pokryciem testami.

[Dokumentacja API](../../docs/api.md)
