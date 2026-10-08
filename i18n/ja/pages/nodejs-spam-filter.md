<!-- source: ff63d002c5fd -->

<!--
label: Node.jsスパムフィルター
title: メール向けNode.jsスパムフィルターライブラリ
description: Node.jsからメールのスパム、フィッシング、マルウェアをスキャン。学習可能な分類器、ESMとCommonJS、smtp-server連携、型付きの結果を備えた1つのnpmパッケージ。
keywords: Node.js スパムフィルター, npm スパムフィルター, JavaScript スパム検出, smtp-server スパム, メール スパム ライブラリ, Nodemailer スパムフィルター
-->

# Node.jsスパムフィルターライブラリ

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

`scan()`はBuffer、文字列、Uint8Array、読み取り可能なストリームを受け取るため、smtp-serverのSMTPストリームをそのまま渡せます。CommonJSでは`require('spamscanner')`で使え、TypeScriptの型定義も含まれています。


## smtp-serverと組み合わせる

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


## 結果の内容

各結果には、スコア、アクション（`accept`、`tag`、`reject`）、該当したテストが含まれ、テストごとに点数と理由があります。詳細な結果には、分類器の確率と最も強い手がかり、フィッシングと添付ファイルの検出結果すべて、認証結果、言語が含まれます。


## 学習させる

```js
await scanner.learn(rawMessage, 'spam');
scanner.saveModel('./model.json');

const trained = new SpamScanner({classifier: './model.json'});
```


## その他

* サーバーもエクスポートしています：`MilterServer`、`createHttpServer`、`createSpamdServer`。
* 言語モデル：`new SpamScanner({llm: {provider: 'ollama', model: 'qwen3.5:4b'}})`。
* Node.js 18、20、22、24でテストしており、テストカバレッジは100%です。

[APIリファレンス](../../docs/api.md)
