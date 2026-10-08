<!-- source: dc9016edd59e -->

# Forward Email

Spam Scannerは、オープンソースでプライバシー重視のメールサービスである[Forward Email](https://forwardemail.net)が、自社のメールサーバーのために開発しました。Forward Emailはメッセージ内容のログを残さないため、外部のフィルタリングサービスは使えませんでした。フィルターは自社のサーバーで動作し、人がメールを読まなくても各判定を説明できる必要がありました。

このページでは、Forward Emailのようなメールサーバーでの使い方と、Spam Scanner 5または6向けに書かれたコードから何が変わったかを説明します。


## 受信メールサーバーで

Forward Emailは[smtp-server](https://nodemailer.com/extras/smtp-server/)でメールを受信します。smtp-serverで構築したサーバーであれば、次のパターンを使えます。

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()`はSMTPストリームを直接受け付けます。[mailauth](https://github.com/postalsys/mailauth)の結果がすでに手元にある場合は、`authentication`を省き、IPアドレスだけを渡してください。

421または451で応答すると、送信側のサーバーはメッセージをキューに入れ、後で再試行します。新しい拒否ルールは一時的なコードで始め、結果を確認してから550に切り替えれば、その間にメールを失うことはありません。


## バージョン5または6からのアップグレード

バージョン7は全面的な書き直しです。バージョン5と6のコードが使うコンストラクター、`scan()`、結果のフィールドはそのまま動きます。分類器、モデル、オプションのTensorFlowによる検査は変わりました。

### 変わらないもの

* `new SpamScanner(options)`と`await scanner.scan(source)`。
* `require('spamscanner')`はクラスを返し、`import SpamScanner from 'spamscanner'`も使えます。
* `result.isSpam`、`result.message`、そして`result.results.classification`、`.phishing`、`.executables`、`.arbitrary`、`.viruses`、`.macros`、`.idnHomographAttack`。
* `results.phishing`、`.executables`、`.arbitrary`、`.viruses`の各項目は、以前と同じ種類のメッセージ文字列に変換されます（`String(item)`、テンプレートリテラル、`message.includes('adult-related content')`）。各項目は現在、`type`、`message`、詳細を持つオブジェクトです。
* `getTokensAndMailFromSource()`、`getClassification()`、`getTokens()`。
* 次のオプションは新しい名前に対応付けられます。`clamscan`は`clamav`に、`enableMacroDetection: false`は`macros: false`に、`enableArbitraryDetection: false`は`arbitrary: false`に、`enableAuthentication`と`authOptions`は`authentication`と`session`に、`enableReputation`と`reputationOptions.apiUrl`は`reputation`に、`strictIDNDetection`は`phishing.homograph.strictMode`に対応し、`allowlist`と`denylist`はそのままです。`logger`と`memoize`は受け付けますが無視します。

### 変わったもの

| 以前                                                | 現在                                                                                                                           |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')`はファイルを読んでいた             | 文字列はメッセージのテキストとして扱う。`scanFile(path)`を使うか、Bufferを渡す                                                                           |
| 単語の単純ベイズモデル（`classifier.json`）。現在は読み込めない          | 新しい分類器とモデル形式。`spamscanner train`で再学習する（[学習](training.md)）                                                                    |
| 有害性とNSFWの検査は、初回使用時にネットワークからTensorFlowのモデルを読み込んでいた | 自分でモデルを用意する。`toxicity: {model}`と`nsfw: {model}`は、`classify()`メソッドを持つ任意のオブジェクトを受け取る（例：`@tensorflow-models/toxicity`と`nsfwjs`） |
| `results.arbitrary`は一致したすべてのパターンを列挙していた           | 単独でスパムと判定できるほど強いルールを列挙する。すべてのルールは`result.tests`にある                                                                           |
| はい・いいえの回答                                         | `result.score`、`result.action`（`accept`、`tag`、`reject`）、`result.tests`。各テストに点数と理由が付く                                         |
| `isSpam`は分類器または単一の検査で決まっていた                       | `isSpam`はスコア5以上を意味する。しきい値と点数は変更できる                                                                                           |
| Forward Emailのエンドポイントに対するレピュテーション検査               | 汎用のレピュテーションサービス。`reputation.apiUrl`を設定しない限り無効                                                                                |

### 新機能

* 際どい判定のための、ローカルまたはホスト型の[言語モデル](llm.md)。
* SPF、DKIM、DMARC、ARC、DNSブロックリスト、Cloudflareのフィルタリング用リゾルバー。
* 内容に基づく添付ファイルの検査：偽装した実行ファイル、アーカイブ、マクロ、アクティブなPDF。
* [milter、HTTP API、TCPサーバー、spamdサーバー](mail-servers.md)と[コマンドライン](cli.md)。
* コマンドラインまたはAPIからの学習、評価、報告からの学習。
