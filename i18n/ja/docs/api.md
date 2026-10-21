<!-- source: 9134d1cd102c -->

# APIリファレンス

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

スキャナーは1つ作って使い回してください。モデルを一度だけ読み込み、DNSと言語モデルの回答をキャッシュします。

型定義も含まれています。`import`ではTypeScript 4.7以降、`require`では5.3以降が必要です。


## オプション

すべてのオプションはコンストラクターに渡せます。ほとんどのオプションは、1通のメッセージ用に`scan()`にも渡せます。その場合、コンストラクターのオプションに上書きでマージされます。`undefined` として渡したオプションは既定値のままです。`classifier`、`classifierOptions`、`dns`、`phishing.homograph`、`strictIDNDetection` はコンストラクタだけが読みます。`classifier` に指定したモデルファイルやモデルオブジェクトもそこで読み込まれるため、モデルが見つからない、または壊れている場合はすぐに例外が発生します。

| オプション                  | デフォルト                            | 意味                                                                                                                                       |
| ---------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`            | `5`                              | メッセージをスパムとするスコア                                                                                                                          |
| `rejectThreshold`      | `15`                             | `action`が`reject`になるスコア                                                                                                                  |
| `scores`               | `{}`                             | テストごとの点数。設定キーまたはテスト名で指定（[テストとスコア](scoring.md)）                                                                                           |
| `classifier`           | 同梱モデル                            | `Classifier`、モデルのオブジェクト、モデルファイルのパス、または`false`                                                                                            |
| `classifierOptions`    | `{}`                             | 同梱モデルのオプション（[Classifier](#classifier)を参照）                                                                                                |
| `allowedLanguages`     | `[]`                             | ISO 639-1のコード（`no`は`nb`、`fil`は`tl`、旧コードの`iw`、`in`、`ji`は`he`、`id`、`yi`として読む）。それ以外の言語には`LANGUAGE_NOT_ALLOWED`が付く                           |
| `phishing.cloudflare`  | `true`                           | リンクのホストについてCloudflareのフィルタリング用リゾルバーに問い合わせる                                                                                               |
| `phishing.adult`       | `true`                           | アダルトサイトをブロックするファミリー向けリゾルバーにも問い合わせる                                                                                                       |
| `phishing.maxHosts`    | `25`                             | メッセージごとに照会するリンクのホスト数                                                                                                                     |
| `phishing.maxLength`   | `1000000`                        | リンクを探すために読む本文の文字数（HTML はその 2 倍）。これより長いと `results.linksTruncated` が設定されます。`Infinity` や正の数以外の値は既定値を意味します                                   |
| `phishing.homograph`   | `{}`                             | `brands`（組み込みの一覧を置き換える）、`extraBrands`、`allowlist`（決してスパム扱いしないドメイン）、`strictMode`                                                          |
| `dnsbl`                | `{ip: [], domain: []}`           | クライアントのIPとリンクのドメインに使うDNSブロックリストのゾーン                                                                                                      |
| `dns`                  | `{servers: null, timeout: 3000}` | DNS検査に使うネームサーバー（デフォルトはシステムのもの）                                                                                                           |
| `attachments`          | `true`                           | 添付ファイルを検査する                                                                                                                              |
| `macros`               | `true`                           | マクロ、アクティブなPDF、RTFオブジェクトを検出する                                                                                                             |
| `arbitrary`            | `true`                           | [ルール](scoring.md#rules)を実行する                                                                                                             |
| `authentication`       | `false`                          | `true`または`{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`：SPF、DKIM、DMARC、ARC（[スコアリング](scoring.md#authentication)） |
| `reputation`           | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`。応答はサービスとヘッダーごとに保持され、`cacheSize` はスキャナー全体に適用されます      |
| `allowlist`、`denylist` |                                  | IPアドレス、ドメイン、アドレス。`reputation`の省略形 → [許可リストと拒否リスト](#allowlist-and-denylist)                                                               |
| `clamav`               | `false`                          | `true`（デフォルトのソケット）、`{socket}`、`{host, port}`のいずれか。`timeout` はメッセージのすべての添付ファイルにかけるミリ秒数（`60000`）                                           |
| `llm`                  | `null`                           | [言語モデルの設定](llm.md#any-server-port-and-authentication)。`mode`、`minScore`、`maxScore`を含む                                                    |
| `toxicity`             | `false`                          | `{model, threshold = 0.7}`：`classify([text])`が`@tensorflow-models/toxicity`と同じ形式で答えるモデル                                                  |
| `nsfw`                 | `false`                          | `{model, threshold = 0.6}`：`classify(imageBuffer)`が`nsfwjs`と同じ形式で答えるモデル                                                                  |
| `maxLength`            | `100000`                         | 読み取る本文テキストの文字数                                                                                                                           |
| `timeout`              | `10000`                          | 各ネットワーク検査に許すミリ秒数。認証と画像モデルは全体でこの時間内に終わります（ClamAV には独自の `clamav.timeout` があります）                                                            |
| `session`              | `{}`                             | SMTPセッションの詳細のデフォルト値                                                                                                                      |

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

SPF、DKIM、DMARC、ARCをすでに（[mailauth](https://github.com/postalsys/mailauth)で）検査したサーバーは、その結果を`authenticationResults`として渡せます。その場合、結果は再検査されずにスコアに反映されます。

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### 許可リストと拒否リスト

拒否リストは、クライアントの IP アドレスとホスト名、From・エンベロープ送信者・Reply-To のアドレス、およびそれらのドメインと、その形式を問わず照合します。拒否リストのドメインの配下にある名前は、有効なホスト名でなくても（`a_b!.evil.example` や、63 文字を超えるラベルを含む名前など）、末尾の 127 ラベルと 253 文字によってそのドメインに一致します。許可リスト、およびレピュテーションサービスの許可リストと信頼済みソースは、送信者が偽造できないものとだけ照合します。クライアントの IP アドレスと検証済みホスト名（`remoteAddress`、`resolvedClientHostname`）、そのドメインで DMARC が合格するか、合格した DKIM 署名がアラインしている（かつ有効なホスト名である。DMARC と同じく緩やかなアラインメントで、From ドメインと署名ドメインまたは SPF ドメインの登録可能ドメインが同じもの。この登録可能ドメインを mailauth は DMARC ドメインとして示します。`news.example.com` のようにサブドメインを指定したエントリは、そのドメイン、その配下のドメイン、またはその親ドメインがメッセージに署名したか SPF に合格した場合にだけ使われ、`evil.example.com` のような別のサブドメインやパブリックサフィックスでは使われません。mailauth のアラインメント情報がない、登録可能ドメインに対する DMARC の合格は、登録可能ドメインを指定したエントリにだけ使われます。厳格なアラインメント、つまりドメインの DMARC レコードに大文字・小文字や空白を問わず `adkim=s` または `aspf=s` がある場合は、From ドメインそのものの署名または SPF 合格だけが使われ、それがなければ DMARC は失敗します）From アドレス、そしてそのドメインで SPF が合格したエンベロープ送信者です。本文の先頭だけに対する DKIM 署名（本文長 `l=` が本文より短いもの。その後には誰でもテキストを追加できます）は何にも使われず、それに基づく DMARC の合格も同様です。また、DMARC が失敗した場合はどの署名も使われず、長すぎて全体を読めない From フィールド（`mail.from.truncated`）の場合も同様です。`authenticationResults` で渡された結果は、合格したドメインが明記されている場合にだけ使われます。ホスト名ではないドメイン（URL パーサーが `bank.example` と読む `bank.example/x.attacker.example` など）はどれにも使われず、そのようなドメインに基づく DMARC の合格も同様です。国際化ドメインはどちらの形式でも一致します（`bücher.example` または `xn--bcher-kva.example`）。Reply-To は決して使われません。ドメインを許可するには、`authentication` を有効にするか `authenticationResults` を渡してください。

各エントリは 1 つの IP アドレス、ドメイン、またはメールアドレスで、完全一致で照合します。ドメインのエントリはそのサブドメインとそこにあるアドレスも対象にしますが、アドレス範囲（`192.0.2.0/24`）、ワイルドカード（`*.example.com`）、パターン（`@example.com`）はありません。IPv6 アドレスはどの表記でも一致し（`2001:0db8::0001` は RFC 5952 の表記である `2001:db8::1` と同じ）、IPv6 にマップされた IPv4 アドレス（`::ffff:192.0.2.1`）はその IPv4 アドレスと一致します。また、IPv6 に変換された IPv4 アドレスや NAT64 プレフィックス配下の IPv4 アドレスは、エントリでもクライアントアドレスでも、IPv4 アドレスをドット区切りの形式で含めて書きます（`::ffff:0:192.0.2.1`、`64:ff9b::192.0.2.1`）。


## メソッド

| メソッド                                 | 戻り値                                                                     |
| ------------------------------------ | ----------------------------------------------------------------------- |
| `scan(source, options)`              | 結果。`source`はBuffer、文字列、Uint8Array、読み取り可能なストリームのいずれか                     |
| `scanFile(path, options)`            | メッセージファイルの結果                                                            |
| `learn(source, 'spam' \| 'ham')`     | 分類器にメッセージを1通学習させる                                                       |
| `unlearn(source, 'spam' \| 'ham')`   | `learn`を取り消す                                                            |
| `saveModel(path, options)`           | 分類器をファイルに書き込む（`options`：`minCount`、`maxFeatures`、`metadata`）            |
| `getClassifier()`                    | 使用中の`Classifier`、または`null`                                              |
| `getClassification(features)`        | `getFeatures`で得た特徴に対する分類器の判定                                            |
| `getFeatures(mail)`                  | メッセージの`{features, words, language, script, links, hosts, text, hidden}` |
| `getTokens(text, locale)`            | テキストの単語                                                                 |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                              |
| `parse(source)`                      | `{raw, mail, error}`。`mail`はmailparserによるもの（下記参照）                       |

`scan`、`parse`、`learn`、`unlearn`、`getTokensAndMailFromSource` はすべて同じようにメッセージを読みます。MIME パーサーの上限（1000 を超えるパート、1 MB を超えるパートのヘッダー）を超えるメッセージは、パーサーが許す範囲まで読みます。アドレスフィールド（From、To、Cc、Bcc、Sender、Reply-To、Delivered-To、Return-Path、Disposition-Notification-To、List-\*）は、メッセージ、そのパート、添付されたメッセージのいずれでも、それぞれ 16 KB、カンマとセミコロン 2000 個、入れ子のグループ 16 段まで、メッセージごとに合計 64 KB まで読みます。常に完全なアドレスの終わりまで読むため、フィールドにないアドレスを読むことはありません。切り詰めたフィールドには `truncated` の印を付け（`mail.to.truncated`）、切り詰めた From フィールドでは送信者の認証による加点はありません。最初の行がヘッダーフィールド（`Name: value`、または mbox ファイルで各メッセージの先頭にある `From` 行）でないテキストは、ヘッダーのないメッセージの本文として読むため、`mail.text` はそのテキストになります。その他のエラーは例外として投げられます。`parse` は、メッセージが超えたパーサーの上限を `error` で返します。これは `scan` が `parseError` で返すのと同じで、全体を読めたメッセージでは null です。

`getFeatures`では、`text`はメールクライアントが表示するテキストで、単語はここから読み取られます。`hidden`はHTMLが隠しているテキストの文字数です。ここでは mailparser は HTML からテキストを作りません。`mail.text` にはプレーンテキストのパートだけが入り、HTML だけのメッセージでは空になります。HTML が表示するテキストは `getFeatures(mail).text` です。

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
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    virusScanErrors: [], // attachments ClamAV could not scan: {filename, error}
    virusScanSkipped: [], // attachments larger than clamd accepts, not scanned: {filename, reason}
    unopenedAttachments: [], // attached messages not opened, past the limits they are read within: {filename, reason}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value, answers} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'], // the links checked, of the whole message up to phishing.maxLength
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser; mail.text: the plain text parts only */},
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

`phishing`、`attachments`、`executables`、`macros`、`viruses`、`arbitrary`の検出結果は、`type`と`message`を持つオブジェクトです。`String(finding)`はそのメッセージになります。添付されたメッセージ（`message/rfc822`、`message/global`、`.eml`、`.u8msg`）の添付ファイルは、そのメッセージ名を付けて呼ばれます（`fw.eml/invoice.exe`）。そのような添付ファイルで ClamAV が見つけたウイルスは、その添付ファイルについてだけ報告し、それを含む添付されたメッセージについて重ねて報告することはありません。`virusScanErrors` は ClamAV がスキャンできなかった添付ファイルを `{filename, error}` の形で列挙します。そのようなメッセージはウイルスを含むかもしれないので、配送せずに保留してください。milter とコンテンツフィルターは、`onError`（`--on-error`）が `accept` でない限りそのメッセージを延期します。また、どのサーバーも、そのようなメッセージを通過させる場合は `X-Spam-Virus-Scan: failed` を付けます。`virusScanSkipped` は、clamd が受け付けるサイズ（clamd の `StreamMaxLength`）より大きい添付ファイルを `{filename, reason}` の形で列挙します。clamd はこれらを何度試しても拒否するため、clamav-milter が `MaxFileSize` を超えるファイルをスキップするのと同じく、失敗とはみなしません。clamd のその他の上限（`MaxScanSize`、`MaxFiles`、`MaxRecursion`、`MaxScanTime`）は、アーカイブ爆弾が達するものであり、失敗とみなします。添付されたメッセージは、3 階層の深さまで、その中の添付ファイル 100 個まで、合計 25 MB まで開きます。`unopenedAttachments` は、これらの上限を超えて開かなかったものを `{filename, reason}` として列挙し、その添付ファイルは検査していません。転送されたメッセージはこのように入れ子になることがあるため、スコアには加えませんが、メッセージを全体まで読む必要がある呼び出し側は、たとえば含まれるプログラムをブロックするために、これがひとつでもあるメッセージを拒否できます。開く添付メッセージは合計で最大 100 件です。

`dnsbl` の各項目には、そのリストの `answers`（127.0.0.0/8 内のアドレスで、意味は各リストが文書化しています）が含まれます。リストが拒否した、または答えられないクエリに返す回答は、クライアントのアドレスについてもリンクのドメイン（`phishing` 内の `uribl` の検出結果）についても、掲載ではありません。Spamhaus の 127.255.255.x（公開リゾルバー経由のクエリに対する 127.255.255.254、クエリ過多に対する 127.255.255.255 など）、Spamhaus DBL の 127.0.1.255、すべてのリストの 127.0.0.255、そして SURBL と URIBL がブロックしているリゾルバーに返す 127.0.0.1 です。


## エクスポート

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, unwrapLink, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export
// unwrapLink(address): the URL a link goes to, through Safe Links and
// Proofpoint URL Defense, as the scanner reads it (null for no URL)

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| オプション                                 | デフォルト         | 意味                                                                                              |
| ------------------------------------- | ------------- | ----------------------------------------------------------------------------------------------- |
| `strength`、`unknown`                  | `0.45`、`0.5`  | Robinsonのsとx。まれな特徴をどの程度強く0.5に引き寄せるか                                                             |
| `minDistance`                         | `0.1`         | 0.5との差がこれより小さい特徴は無視する                                                                           |
| `maxClues`                            | `150`         | メッセージごとに組み合わせる最も強い特徴の数                                                                          |
| `hamCutoff`、`spamCutoff`              | `0.2`、`0.99`  | `unsure`の範囲の境界                                                                                  |
| `minLanguageExamples`、`languageShare` | `1000`、`0.02` | ある言語で完全な確信を持つために必要なhamメッセージ数と、その5分の1のスパムメッセージ数。すべてのhamまたはスパムに占める割合が`languageShare`未満の場合はより少なくなる |
| `languagePrior`                       | `true`        | 単語をその言語自体の件数に対して重み付けする                                                                          |

`merge(other)`、`toJSON(options)`、`Classifier.fromJSON(json)`、`size`、`entries()`も使えます。`Classifier.fromJSON` はモデルを検査し、壊れたデータには `Corrupt classifier model` で始まる `TypeError` を投げます。JSON には `Infinity` がないため、バージョン 7.0.3 が `Infinity` として保存したオプションは `null` として読み戻されます。これは `maxClues`、`minDistance`、`minLanguageExamples` では `Infinity`、`hamCutoff` では `-Infinity`（ham にしない）、`spamCutoff` では `Infinity`（spam にしない）として読まれ、その他のオプションではデフォルト値として読まれます。`toJSON` は 0 と 1 の範囲を超えるしきい値を -1 または 2 として保存しますが、これは同じように機能します。`loadModel` はファイルが変わると読み直し、`saveModel` は新しい一時ファイルを経由して書き込み、モデルを置き換える前にディスクへフラッシュします。モデルの権限は保たれます。

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

milterの`onError`は、スキャンが失敗したときや、ClamAVが添付ファイルをスキャンできなかったときの応答です。`'tempfail'`（デフォルト）か`'accept'`を指定します。後者はメッセージに `X-Spam-Virus-Scan: failed` を付け、送信者が付けた `X-Spam-*` ヘッダーを除いて渡します。

### ARFレポート

`spamscanner/arf`は、メールボックスプロバイダーがスパムの苦情を報告するのに使う形式である、不正利用フィードバックレポート（RFC 5965）を読み書きします。

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders?.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`parse()`はBuffer、Uint8Array、文字列を受け取ります。`ArfParser.tryParse()`は、レポートではないメッセージに対して例外を投げる代わりに`null`を返します。`isArfMessage(mail)`は解析済みのメッセージを確認します。`originalHeaders`は、元のメッセージを含まないレポートでは`null`になります。`create()`は文字列を返しますが、`originalMessage`が`Buffer`であれば戻り値も同じ型になるため、文字セットにかかわらずそのバイト列が保たれます。
