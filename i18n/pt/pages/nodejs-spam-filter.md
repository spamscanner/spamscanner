<!-- source: ff63d002c5fd -->

<!--
label: Filtro de spam para Node.js
title: Biblioteca de filtro de spam para e-mail em Node.js
description: Analise e-mails em busca de spam, phishing e malware no Node.js: um pacote npm com classificador treinável, ESM e CommonJS, smtp-server e resultados tipados.
keywords: filtro de spam Node.js, filtro de spam npm, detecção de spam JavaScript, spam smtp-server, biblioteca de spam para e-mail, filtro de spam Nodemailer
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

O `scan()` recebe um Buffer, uma string, um Uint8Array ou um stream legível, então o stream SMTP do smtp-server pode entrar diretamente. O CommonJS funciona com `require('spamscanner')`, e os tipos do TypeScript estão incluídos.


## Com o smtp-server

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


## O que o resultado diz

Cada resultado tem uma pontuação, uma ação (`accept`, `tag` ou `reject`) e os testes acionados, cada um com pontos e um motivo. Os resultados detalhados incluem a probabilidade do classificador e as suas pistas mais fortes, cada achado de phishing e de anexos, os resultados de autenticação e o idioma.


## Ensine o modelo

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Mais

* Os servidores também são exportados: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Modelos de linguagem: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Testado no Node.js 18, 20, 22 e 24, com 100% de cobertura de testes.

[Referência da API](../../docs/api.md)
