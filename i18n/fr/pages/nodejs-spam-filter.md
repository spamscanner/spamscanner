<!-- source: ff63d002c5fd -->

<!--
label: Filtre antispam Node.js
title: Bibliothèque antispam Node.js pour le courrier électronique
description: Détectez spam, hameçonnage et malwares dans les e-mails depuis Node.js : un paquet npm, un classifieur entraînable, ESM, CommonJS et smtp-server.
keywords: antispam Node.js, filtre antispam npm, détection de spam JavaScript, spam smtp-server, bibliothèque antispam e-mail, filtre antispam Nodemailer
-->

# Bibliothèque antispam Node.js

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

`scan()` prend un Buffer, une chaîne, un Uint8Array ou un flux lisible : le flux SMTP de smtp-server peut donc y être passé directement. CommonJS fonctionne avec `require('spamscanner')`, et les types TypeScript sont inclus.


## Avec smtp-server

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


## Ce que dit le résultat

Chaque résultat comporte un score, une action (`accept`, `tag` ou `reject`) et les tests déclenchés, chacun avec des points et une raison. Les résultats détaillés incluent la probabilité du classifieur et ses indices les plus forts, chaque résultat concernant l’hameçonnage et les pièces jointes, les résultats d’authentification et la langue.


## L’entraîner

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Pour aller plus loin

* Les serveurs sont aussi exportés : `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Modèles de langage : `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Testé sur Node.js 18, 20, 22 et 24, avec une couverture de tests de 100 %.

[Référence de l’API](../../docs/api.md)
