<!-- source: ff63d002c5fd -->

<!--
label: Спам-фильтр для Node.js
title: Библиотека спам-фильтра для почты на Node.js
description: Проверка почты на спам, фишинг и вирусы из Node.js: один пакет npm с обучаемым классификатором, ESM и CommonJS, smtp-server и типизированные результаты.
keywords: спам-фильтр Node.js, спам-фильтр npm, обнаружение спама на JavaScript, спам в smtp-server, библиотека для фильтрации спама, спам-фильтр Nodemailer
-->

# Библиотека спам-фильтра для Node.js

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

`scan()` принимает Buffer, строку, Uint8Array или поток для чтения, поэтому SMTP-поток из smtp-server можно передать напрямую. CommonJS работает через `require('spamscanner')`, типы TypeScript включены.


## Со smtp-server

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


## Что сообщает результат

У каждого результата есть оценка, действие (`accept`, `tag` или `reject`) и сработавшие тесты, каждый с баллами и причиной. Подробные результаты включают вероятность по оценке классификатора и самые сильные признаки, все находки по фишингу и вложениям, результаты аутентификации и язык.


## Обучение

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## Дополнительно

* Серверы тоже экспортируются: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* Языковые модели: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Протестирован на Node.js 18, 20, 22 и 24 со 100 % покрытием тестами.

[Справочник API](../../docs/api.md)
