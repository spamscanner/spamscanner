<!-- source: ff63d002c5fd -->

<!--
label: Node.js 스팸 필터
title: 이메일용 Node.js 스팸 필터 라이브러리
description: Node.js에서 이메일의 스팸, 피싱, 악성코드를 검사합니다. 학습 가능한 분류기, ESM과 CommonJS, smtp-server 연동, 타입이 있는 결과를 npm 패키지 하나로.
keywords: Node.js 스팸 필터, npm 스팸 필터, JavaScript 스팸 탐지, smtp-server 스팸, 이메일 스팸 라이브러리, Nodemailer 스팸 필터
-->

# Node.js 스팸 필터 라이브러리

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

`scan()`은 Buffer, 문자열, Uint8Array 또는 읽기 가능한 스트림을 받으므로, smtp-server의 SMTP 스트림을 그대로 넣을 수 있습니다. CommonJS에서는 `require('spamscanner')`로 사용하며, TypeScript 타입이 포함되어 있습니다.


## smtp-server와 함께

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


## 결과에 담기는 내용

각 결과에는 점수, 동작(`accept`, `tag`, `reject`), 그리고 각각 점수와 이유가 붙은 발동한 테스트가 들어 있습니다. 상세 결과에는 분류기의 확률과 가장 강한 단서, 모든 피싱 검출과 첨부 파일 검출, 인증 결과, 언어가 포함됩니다.


## 학습시키기

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## 그 밖의 기능

* 서버도 내보냅니다: `MilterServer`, `createHttpServer`, `createSpamdServer`.
* 언어 모델: `new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`.
* Node.js 18, 20, 22, 24에서 테스트하며, 테스트 커버리지는 100%입니다.

[API 레퍼런스](../../docs/api.md)
