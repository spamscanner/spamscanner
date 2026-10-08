<!-- source: ff63d002c5fd -->

<!--
label: Filtro de spam para Node.js
title: Biblioteca de filtro de spam para correo en Node.js
description: Analiza el correo en busca de spam, phishing y malware desde Node.js: un paquete npm con clasificador entrenable, ESM, CommonJS y smtp-server.
keywords: filtro de spam Node.js, filtro de spam npm, detección de spam JavaScript, spam smtp-server, biblioteca antispam para correo, filtro de spam Nodemailer
-->

# Biblioteca de filtro de spam para Node.js

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

`scan()` recibe un Buffer, una cadena, un Uint8Array o un flujo legible, así que el flujo SMTP de smtp-server puede entrar directamente. CommonJS funciona con `require('spamscanner')`, y se incluyen los tipos de TypeScript.


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


## Qué dice el resultado

Cada resultado tiene una puntuación, una acción (`accept`, `tag` o `reject`) y las pruebas que se activaron, cada una con puntos y un motivo. Los resultados detallados incluyen la probabilidad y los indicios más fuertes del clasificador, cada hallazgo de phishing y de adjuntos, los resultados de autenticación y el idioma.


## Enseñarle

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Más

* Los servidores también se exportan: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Modelos de lenguaje: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Probado en Node.js 18, 20, 22 y 24, con un 100 % de cobertura de pruebas.

[Referencia de la API](../../docs/api.md)
