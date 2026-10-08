<!-- source: b3cc9f949acd -->

# APIリファレンス

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

スキャナーは1つ作って使い回してください。モデルを一度だけ読み込み、DNSと言語モデルの回答をキャッシュします。


## オプション

すべてのオプションはコンストラクターに渡せます。ほとんどのオプションは、1通のメッセージ用に`scan()`にも渡せます。その場合、コンストラクターのオプションに上書きでマージされます。

| オプション                  | デフォルト                            | 意味                                                                                      |
| ---------------------- | -------------------------------- | --------------------------------------------------------------------------------------- |
| `threshold`            | `5`                              | メッセージをスパムとするスコア                                                                         |
| `rejectThreshold`      | `15`                             | `action`が`reject`になるスコア                                                                 |
| `scores`               | `{}`                             | テストごとの点数。設定キーまたはテスト名で指定（[テストとスコア](scoring.md)）                                          |
| `classifier`           | 同梱モデル                            | `Classifier`、モデルのオブジェクト、モデルファイルのパス、または`false`                                           |
| `classifierOptions`    | `{}`                             | 同梱モデルのオプション（[Classifier](#classifier)を参照）                                               |
| `allowedLanguages`     | `[]`                             | ISO 639-1のコード。それ以外の言語には`LANGUAGE_NOT_ALLOWED`が付く                                        |
| `phishing.cloudflare`  | `true`                           | リンクのホストについてCloudflareのフィルタリング用リゾルバーに問い合わせる                                              |
| `phishing.adult`       | `true`                           | アダルトサイトをブロックするファミリー向けリゾルバーにも問い合わせる                                                      |
| `phishing.maxHosts`    | `25`                             | メッセージごとに照会するリンクのホスト数                                                                    |
| `phishing.homograph`   | `{}`                             | `brands`（組み込みの一覧を置き換える）、`extraBrands`、`allowlist`（決してスパム扱いしないドメイン）、`strictMode`         |
| `dnsbl`                | `{ip: [], domain: []}`           | クライアントのIPとリンクのドメインに使うDNSブロックリストのゾーン                                                     |
| `dns`                  | `{servers: null, timeout: 3000}` | DNS検査に使うネームサーバー（デフォルトはシステムのもの）                                                          |
| `attachments`          | `true`                           | 添付ファイルを検査する                                                                             |
| `macros`               | `true`                           | マクロ、アクティブなPDF、RTFオブジェクトを検出する                                                            |
| `arbitrary`            | `true`                           | [ルール](scoring.md#rules)を実行する                                                            |
| `authentication`       | `false`                          | `true`または`{dnsServers, timeout, mta, weights}`：SPF、DKIM、DMARC、ARC                       |
| `reputation`           | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                       |
| `allowlist`、`denylist` |                                  | IPアドレス、ドメイン、アドレス。`reputation`の省略形                                                       |
| `clamav`               | `false`                          | `true`（デフォルトのソケット）、`{socket}`、`{host, port}`のいずれか                                       |
| `llm`                  | `null`                           | [言語モデルの設定](llm.md#any-server-port-and-authentication)。`mode`、`minScore`、`maxScore`を含む   |
| `toxicity`             | `false`                          | `{model, threshold = 0.7}`：`classify([text])`が`@tensorflow-models/toxicity`と同じ形式で答えるモデル |
| `nsfw`                 | `false`                          | `{model, threshold = 0.6}`：`classify(imageBuffer)`が`nsfwjs`と同じ形式で答えるモデル                 |
| `maxLength`            | `100000`                         | 読み取る本文テキストの文字数                                                                          |
| `timeout`              | `10000`                          | 各ネットワーク検査に許すミリ秒数                                                                        |
| `session`              | `{}`                             | SMTPセッションの詳細のデフォルト値                                                                     |

`scan()`は`session`も受け取ります。

```js
await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',             // the client's IP address
    resolvedClientHostname: 'mx.example.com', // its verified reverse DNS name
    helo: 'mx.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```


## メソッド

| メソッド                                 | 戻り値                                                          |
| ------------------------------------ | ------------------------------------------------------------ |
| `scan(source, options)`              | 結果。`source`はBuffer、文字列、Uint8Array、読み取り可能なストリームのいずれか          |
| `scanFile(path, options)`            | メッセージファイルの結果                                                 |
| `learn(source, 'spam' \| 'ham')`     | 分類器にメッセージを1通学習させる                                            |
| `unlearn(source, 'spam' \| 'ham')`   | `learn`を取り消す                                                 |
| `saveModel(path, options)`           | 分類器をファイルに書き込む（`options`：`minCount`、`maxFeatures`、`metadata`） |
| `getClassifier()`                    | 使用中の`Classifier`、または`null`                                   |
| `getClassification(features)`        | `getFeatures`で得た特徴に対する分類器の判定                                 |
| `getFeatures(mail)`                  | 解析済みメッセージの`{features, words, language, script, links}`       |
| `getTokens(text, locale)`            | テキストの単語                                                      |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                   |
| `parse(source)`                      | `{raw, mail}`。`mail`はmailparserによるもの                         |

`scanner.metrics`には`totalScans`、`averageTime`、`lastScanTime`が入っています。


## 結果

```js
{
  isSpam: true,
  score: 16.25,
  threshold: 5,
  rejectThreshold: 15,
  action: 'reject',                       // 'accept', 'tag' or 'reject'
  message: 'Spam (BAYES_999, PHISHING_LOOKALIKE_DOMAIN, DECEPTIVE_LINK, FROM_NAME_BRAND)',
  tests: [
    {name: 'BAYES_999', score: 6.25, description: 'Classifier spam probability 99.9%'},
    {name: 'PHISHING_LOOKALIKE_DOMAIN', score: 5, description: '"paypa1-secure.top" imitates paypal by swapping characters'},
    // ...
  ],
  results: {
    classification: {probability, category, spam, ham, clues, coverage},
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'],
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser */},
  version: '7.0.0',
  metrics: {totalTime: 42},
}
```

`phishing`、`attachments`、`executables`、`macros`、`viruses`、`arbitrary`の検出結果は、`type`と`message`を持つオブジェクトです。`String(finding)`はそのメッセージになります。


## エクスポート

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| オプション                                 | デフォルト         | 意味                                  |
| ------------------------------------- | ------------- | ----------------------------------- |
| `strength`、`unknown`                  | `0.45`、`0.5`  | Robinsonのsとx。まれな特徴をどの程度強く0.5に引き寄せるか |
| `minDistance`                         | `0.1`         | 0.5との差がこれより小さい特徴は無視する               |
| `maxClues`                            | `150`         | メッセージごとに組み合わせる最も強い特徴の数              |
| `hamCutoff`、`spamCutoff`              | `0.2`、`0.99`  | `unsure`の範囲の境界                      |
| `minLanguageExamples`、`languageShare` | `1000`、`0.02` | ある言語で完全な確信を持つために必要な各クラスのメッセージ数      |
| `languagePrior`                       | `true`        | 単語をその言語自体の件数に対して重み付けする              |

`merge(other)`、`toJSON(options)`、`Classifier.fromJSON(json)`、`size`、`entries()`も使えます。

### 学習

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)`は、`{label, features}`の項目か、`train`と同じソースを読む`readExamples(sources)`の結果を受け取り、件数、適合率、再現率、F1、正解率、そして偽陽性率、偽陰性率、判定不能率を返します。

### サーバー

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARFレポート

`spamscanner/arf`は、メールボックスプロバイダーがスパムの苦情を報告するのに使う形式である、不正利用フィードバックレポート（RFC 5965）を読み書きします。

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()`は、レポートではないメッセージに対して例外を投げる代わりに`null`を返します。`isArfMessage(mail)`は解析済みのメッセージを確認します。
