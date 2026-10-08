<!-- source: 8263c06f1dab -->

# はじめに

Spam ScannerにはNode.js 18以降が必要です。スタンドアロンバイナリを使う場合は何も必要ありません。


## インストール

コマンドラインツールとして：

```sh
npm install --global spamscanner
spamscanner version
```

Node.jsプロジェクトのライブラリとして：

```sh
npm install spamscanner
```

Node.jsとモデルを組み込んだ、LinuxまたはmacOS向けのスタンドアロンバイナリとして：

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Linux（x64とarm64）、macOS（IntelとApple silicon）、Windows向けのバイナリは、各[リリース](https://github.com/spamscanner/spamscanner/releases)に添付されています。


## メッセージをスキャンする

メッセージをファイルとして保存し（多くのメールソフトでは「名前を付けて保存」や「メッセージのソースを表示」と呼ばれます）、スキャンします。

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

終了コードはハムなら0、スパムなら1、エラーなら2なので、スクリプトでそのまま使えます。`--json`は完全な結果を出力し、`--headers`は`X-Spam-*`ヘッダーを追加したメッセージを出力します。

メッセージは標準入力からも渡せます。

```sh
cat message.eml | spamscanner scan -
```


## Node.jsから使う

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJSでも使えます。

```js
const SpamScanner = require('spamscanner');
```

`scan()`は生のメッセージをBuffer、文字列、Uint8Array、読み取り可能なストリームとして受け取ります。文字列は常にメッセージのテキストとして扱います。文字列がパスのように見えても、Spam Scannerがファイルを読むことはありません。ファイルには`scanner.scanFile(path)`を使ってください。


## SMTPセッションの情報を渡す

クライアントのIPアドレス、検証済みのホスト名、HELO名、エンベロープを渡すと、結果の精度が上がります。認証にはIPアドレスが必要で、自己なりすましのルールには受信者が必要です。

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

コマンドラインでは次のようにします。

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## 検査を追加で有効にする

以下はいずれもデフォルトで無効です。それぞれにサービスか判断が必要なためです。

| 検査                 | ライブラリのオプション                                      | コマンドライン                    |
| ------------------ | ------------------------------------------------ | -------------------------- |
| SPF、DKIM、DMARC、ARC | `authentication: true`                           | `--auth`                   |
| IPブロックリスト          | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org` |
| リンク用のドメインブロックリスト   | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org` |
| ClamAV             | `clamav: true`または`clamav: {socket}`              | `--clamav [socket]`        |
| 言語モデル              | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`             |
| 許可リストと拒否リスト        | `allowlist: [...]`、`denylist: [...]`             | `--allowlist`、`--denylist` |

Cloudflareのフィルタリング用リゾルバー（マルウェア向けの1.1.1.2、アダルトコンテンツ向けの1.1.1.3）には、デフォルトでリンクのホストを問い合わせます。無効にするには`phishing: {cloudflare: false}`または`--no-cloudflare`を使います。[マシンの外に出るもの](security.md)

Spamhausなど一部のブロックリストは、8.8.8.8や1.1.1.1のような公開リゾルバー経由の問い合わせには応答しません。ローカルのキャッシュリゾルバーと組み合わせて使い、自分の利用量に対する利用規約を確認してください。


## 次のステップ

* メールサーバーの前に置く：[PostfixとSendmail](postfix.md)、[その他のサーバー](mail-servers.md)。
* 自分のメールを学習させる：[学習](training.md)。
* 際どい判定のために言語モデルを追加する：[言語モデル](llm.md)。
