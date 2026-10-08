<!-- source: ff63d002c5fd -->

<!--
label: Спам-фільтр для Node.js
title: Бібліотека спам-фільтра для електронної пошти на Node.js
description: Перевірка пошти на спам, фішинг і шкідливе ПЗ з Node.js: один пакет npm із навчуваним класифікатором, ESM і CommonJS, smtp-server і типізованими результатами.
keywords: спам-фільтр Node.js, спам-фільтр npm, виявлення спаму JavaScript, smtp-server спам, бібліотека антиспаму, спам-фільтр Nodemailer
-->

# Бібліотека спам-фільтра для Node.js

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

`scan()` приймає Buffer, рядок, Uint8Array або потік для читання, тож потік SMTP із smtp-server можна передати напряму. CommonJS працює з `require('spamscanner')`, а типи TypeScript входять до пакета.


## Із smtp-server

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


## Що містить результат

Кожен результат має бал, дію (`accept`, `tag` або `reject`) і тести, що спрацювали, кожен із балами та причиною. Детальні результати містять імовірність класифікатора та його найсильніші ознаки, кожну знахідку щодо фішингу й вкладень, результати автентифікації та мову.


## Навчання

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Більше

* Сервери теж експортуються: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Мовні моделі: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Протестовано на Node.js 18, 20, 22 і 24, зі 100 % покриттям тестами.

[Довідник API](../../docs/api.md)
