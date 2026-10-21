<!-- source: 9134d1cd102c -->

# API 参考

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

创建一个扫描器并重复使用：它只加载一次模型，并缓存 DNS 和语言模型的回答。

包内附带类型声明。使用 `import` 时需要 TypeScript 4.7 或更高版本，使用 `require` 时需要 5.3 或更高版本。


## 选项

每个选项都可以传给构造函数。大多数选项也可以针对单封邮件传给 `scan()`，它们会覆盖合并到构造函数的选项之上。以 `undefined` 传入的选项保持默认值。`classifier`、`classifierOptions`、`dns`、`phishing.homograph` 和 `strictIDNDetection` 只由构造函数读取；`classifier` 指定的模型文件或对象也在构造时读取，因此模型缺失或损坏会立即抛出错误。

| 选项                     | 默认值                              | 含义                                                                                                                                   |
| ---------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `threshold`            | `5`                              | 邮件判为垃圾邮件的分数                                                                                                                          |
| `rejectThreshold`      | `15`                             | `action` 为 `reject` 的分数                                                                                                              |
| `scores`               | `{}`                             | 每项测试的分值：设置键或测试名称（[测试与分值](scoring.md)）                                                                                                |
| `classifier`           | 内置模型                             | `Classifier`、模型对象、模型文件路径或 `false`                                                                                                    |
| `classifierOptions`    | `{}`                             | 内置模型的选项（见[分类器](#classifier)）                                                                                                         |
| `allowedLanguages`     | `[]`                             | ISO 639-1 代码（`no` 按 `nb` 读取，`fil` 按 `tl`，旧代码 `iw`、`in`、`ji` 按 `he`、`id`、`yi`）；其他语言会得到 `LANGUAGE_NOT_ALLOWED`                         |
| `phishing.cloudflare`  | `true`                           | 向 Cloudflare 的过滤解析器查询链接主机                                                                                                            |
| `phishing.adult`       | `true`                           | 同时查询拦截成人网站的家庭解析器                                                                                                                     |
| `phishing.maxHosts`    | `25`                             | 每封邮件查询的链接主机数量                                                                                                                        |
| `phishing.maxLength`   | `1000000`                        | 为查找链接而读取的正文字符数（HTML 为其两倍）；更长的正文会设置 `results.linksTruncated`；`Infinity` 或任何非正数的值表示使用默认值                                               |
| `phishing.homograph`   | `{}`                             | `brands`（替换内置列表）、`extraBrands`、`allowlist`（从不标记的域名）、`strictMode`                                                                     |
| `dnsbl`                | `{ip: [], domain: []}`           | 针对客户端 IP 和链接域名的 DNS 黑名单区域                                                                                                            |
| `dns`                  | `{servers: null, timeout: 3000}` | DNS 检查使用的域名服务器（默认：系统的域名服务器）                                                                                                          |
| `attachments`          | `true`                           | 检查附件                                                                                                                                 |
| `macros`               | `true`                           | 标记宏、含活动内容的 PDF 和 RTF 对象                                                                                                              |
| `arbitrary`            | `true`                           | 运行[规则](scoring.md#rules)                                                                                                             |
| `authentication`       | `false`                          | `true`，或 `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`：SPF、DKIM、DMARC、ARC（[评分](scoring.md#authentication)） |
| `reputation`           | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`；应答按服务和请求头分别保存，`cacheSize` 作用于整个扫描器               |
| `allowlist`、`denylist` |                                  | IP 地址、域名或地址；`reputation` 的简写 → [允许列表和拒绝列表](#allowlist-and-denylist)                                                                  |
| `clamav`               | `false`                          | `true`（默认套接字）、`{socket}` 或 `{host, port}`，以及 `timeout`：一封邮件所有附件合计的毫秒数（`60000`）                                                       |
| `llm`                  | `null`                           | [语言模型设置](llm.md#any-server-port-and-authentication)，含 `mode`、`minScore`、`maxScore`                                                   |
| `toxicity`             | `false`                          | `{model, threshold = 0.7}`：一个其 `classify([text])` 的回答形式与 `@tensorflow-models/toxicity` 相同的模型                                         |
| `nsfw`                 | `false`                          | `{model, threshold = 0.6}`：一个其 `classify(imageBuffer)` 的回答形式与 `nsfwjs` 相同的模型                                                         |
| `maxLength`            | `100000`                         | 读取的正文字符数                                                                                                                             |
| `timeout`              | `10000`                          | 每项网络检查允许的毫秒数；身份验证和图像模型总共在此时间内完成（ClamAV 有自己的 `clamav.timeout`）                                                                        |
| `session`              | `{}`                             | 默认的 SMTP 会话信息                                                                                                                        |

`scan()` 还接受 `session`：

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

已经检查过 SPF、DKIM、DMARC 和 ARC（使用 [mailauth](https://github.com/postalsys/mailauth)）的服务器可以把结果作为 `authenticationResults` 传入，这些结果会直接计分，不再重新检查：

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### 允许列表和拒绝列表

拒绝列表会比对客户端的 IP 地址和主机名、From、信封发件人和 Reply-To 地址及其域名，无论它们是什么：拒绝列表中某个域名之下的名称即使不是有效的主机名（如 `a_b!.evil.example`，或某个标签超过 63 个字符的名称），也会按其最后 127 个标签和 253 个字符与该域名匹配。允许列表，以及信誉服务的允许列表和可信来源，只比对发件人无法伪造的内容：客户端的 IP 地址和经过验证的主机名（`remoteAddress`、`resolvedClientHostname`）、其域名通过 DMARC 或有通过且对齐的 DKIM 签名（且其为有效的主机名；宽松对齐，与 DMARC 相同：From 域名与签名域名或 SPF 域名的可注册域名相同，mailauth 将其列为 DMARC 域名；指定子域名的条目，如 `news.example.com`，只有在该域名、其下级域名或其上级域名签署了邮件或通过了 SPF 时才计入，其他子域名（如 `evil.example.com`）或公共后缀都不算；对可注册域名的 DMARC 通过如果没有 mailauth 的对齐详情，只对指定该可注册域名的条目计入；在严格对齐下，即域名的 DMARC 记录中有 `adkim=s` 或 `aspf=s`（不论大小写或空格）时，只有 From 域名本身的签名或 SPF 通过才计入，没有则 DMARC 失败）的 From 地址，以及其域名通过 SPF 的信封发件人。只签署正文开头部分的 DKIM 签名（正文长度 `l=` 短于正文：任何人都能在其后追加文字）对任何内容都不计入，依赖这种签名的 DMARC 通过也不计入；DMARC 失败时，任何签名都不计入；From 字段过长、无法完整读取（`mail.from.truncated`）时也是如此。通过 `authenticationResults` 传入的结果，只有注明了所通过的域名时才计入；不是主机名的域名（如 `bank.example/x.attacker.example`，URL 解析器会把它读作 `bank.example`）对任何域名都不计入，依赖这种域名的 DMARC 通过也不计入。国际化域名两种形式都能匹配：`bücher.example` 或 `xn--bcher-kva.example`。Reply-To 从不计入。要允许某个域名，请开启 `authentication` 或传入 `authenticationResults`。

每个条目是一个 IP 地址、域名或电子邮件地址，按精确匹配：域名条目也涵盖其子域名及这些域名下的地址，但不支持地址范围（`192.0.2.0/24`）、通配符（`*.example.com`）或模式（`@example.com`）。IPv6 地址以任何形式都能匹配（`2001:0db8::0001` 即 `2001:db8::1`，即 RFC 5952 的形式），映射到 IPv6 中的 IPv4 地址（`::ffff:192.0.2.1`）与该 IPv4 地址匹配，转换为 IPv6 或位于 NAT64 前缀下的 IPv4 地址则连同该前缀以点分十进制形式书写（`::ffff:0:192.0.2.1`、`64:ff9b::192.0.2.1`），条目和客户端地址均是如此。


## 方法

| 方法                                   | 返回值                                                                   |
| ------------------------------------ | --------------------------------------------------------------------- |
| `scan(source, options)`              | 结果。`source` 为 Buffer、字符串、Uint8Array 或可读流                              |
| `scanFile(path, options)`            | 邮件文件的结果                                                               |
| `learn(source, 'spam' \| 'ham')`     | 用一封邮件训练分类器                                                            |
| `unlearn(source, 'spam' \| 'ham')`   | 撤销 `learn`                                                            |
| `saveModel(path, options)`           | 把分类器写入文件（`options`：`minCount`、`maxFeatures`、`metadata`）               |
| `getClassifier()`                    | 正在使用的 `Classifier`，或 `null`                                           |
| `getClassification(features)`        | 分类器对 `getFeatures` 所得特征的判定                                            |
| `getFeatures(mail)`                  | 邮件的 `{features, words, language, script, links, hosts, text, hidden}` |
| `getTokens(text, locale)`            | 文本中的词语                                                                |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                            |
| `parse(source)`                      | `{raw, mail, error}`，其中 `mail` 来自 mailparser（见下文）                     |

`scan`、`parse`、`learn`、`unlearn` 和 `getTokensAndMailFromSource` 都以相同方式读取邮件：超出 MIME 解析器限制（超过 1000 个部分，某个部分的头超过 1 MB）的邮件会在解析器允许的范围内读取。邮件本身、其各个部分以及附带邮件中的地址字段（From、To、Cc、Bcc、Sender、Reply-To、Delivered-To、Return-Path、Disposition-Notification-To 和 List-\*），每个最多读取 16 KB、2000 个逗号和分号以及 16 层嵌套的组，每封邮件合计最多 64 KB，且总是读到一个完整地址的末尾，因此不会读出字段中没有给出的地址；被截断的字段会标记为 `truncated`（`mail.to.truncated`），被截断的 From 字段不会因发件人的身份验证而获得任何减分。第一行不是头字段（`Name: value`，或 mbox 文件中每封邮件开头的 `From` 行）的文本，会被当作没有头的邮件的正文读取，因此 `mail.text` 就是这段文本。其他错误会被抛出。`parse` 在 `error` 中给出消息超出的解析器限制，与 `scan` 在 `parseError` 中给出的相同；完整读取的消息为 null。

在 `getFeatures` 中，`text` 是邮件客户端显示的文本，词语即从中读取；`hidden` 是 HTML 隐藏的文本字符数。mailparser 在这里不会把 HTML 转成文本：`mail.text` 只包含纯文本部分，对于只有 HTML 的邮件则为空；其 HTML 显示的文本是 `getFeatures(mail).text`。

`scanner.metrics` 包含 `totalScans`、`averageTime` 和 `lastScanTime`。


## 结果

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

`phishing`、`attachments`、`executables`、`macros`、`viruses` 和 `arbitrary` 中的发现都是带有 `type` 和 `message` 的对象。`String(finding)` 即为该消息。附带邮件（`message/rfc822`、`message/global`、`.eml`、`.u8msg`）中的附件以该邮件命名：`fw.eml/invoice.exe`。ClamAV 在这类附件中发现的病毒只针对该附件报告，不会再针对包含它的附带邮件重复报告。`virusScanErrors` 以 `{filename, error}` 的形式列出 ClamAV 未能扫描的附件：这样的邮件可能含有病毒，应暂扣而不是投递。除非 `onError`（`--on-error`）为 `accept`，否则 milter 和内容过滤器会推迟处理这样的邮件；每种服务器放行这样的邮件时都会加上 `X-Spam-Virus-Scan: failed` 标记。`virusScanSkipped` 以 `{filename, reason}` 的形式列出大于 clamd 所接受大小（其 `StreamMaxLength`）的附件：clamd 每次尝试都会拒绝它们，因此，正如 clamav-milter 会跳过超过其 `MaxFileSize` 的文件，它们不算失败。clamd 的其他限制（`MaxScanSize`、`MaxFiles`、`MaxRecursion`、`MaxScanTime`）是压缩炸弹会触及的，算作失败。附加的消息最多打开三层，其中的附件最多 100 个，总计最多 25 MB；`unopenedAttachments` 以 `{filename, reason}` 的形式列出因超出这些限制而未打开的消息，其附件未经检查。它不计入评分，因为转发的消息可能这样嵌套，但需要完整读取消息的调用方（例如为了拦截其中携带的程序）可以拒绝含有任何此类条目的消息。总共最多打开 100 封附加的消息。

每个 `dnsbl` 项都带有该列表的 `answers`（127.0.0.0/8 中的地址，其含义由各列表在文档中说明）。列表对其拒绝或无法回答的查询给出的回答不算列入，无论是针对客户端地址还是链接域名（`phishing` 中的 `uribl` 发现）：Spamhaus 的 127.255.255.x（例如通过公共解析器查询时的 127.255.255.254，以及查询过多时的 127.255.255.255）、Spamhaus DBL 的 127.0.1.255、任何列表的 127.0.0.255，以及 SURBL 和 URIBL 的 127.0.0.1，它们会向被其屏蔽的解析器给出这一回答。


## 导出

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

| 选项                                    | 默认值           | 含义                                                                                |
| ------------------------------------- | ------------- | --------------------------------------------------------------------------------- |
| `strength`、`unknown`                  | `0.45`、`0.5`  | Robinson 的 s 和 x：罕见特征被拉向 0.5 的强度                                                  |
| `minDistance`                         | `0.1`         | 与 0.5 的距离小于此值的特征会被忽略                                                              |
| `maxClues`                            | `150`         | 每封邮件合并的最强特征数量                                                                     |
| `hamCutoff`、`spamCutoff`              | `0.2`、`0.99`  | `unsure` 区间的边界                                                                    |
| `minLanguageExamples`、`languageShare` | `1000`、`0.02` | 某种语言中需要多少封正常邮件才能达到十足的置信度，垃圾邮件则需要其五分之一；当 `languageShare` 占全部正常邮件或垃圾邮件的比例更小时，所需数量更少 |
| `languagePrior`                       | `true`        | 用词语所属语言的计数来衡量词语                                                                   |

还可以使用 `merge(other)`、`toJSON(options)`、`Classifier.fromJSON(json)`、`size` 和 `entries()`。`Classifier.fromJSON` 会检查模型，遇到损坏的数据时抛出以 `Corrupt classifier model` 开头的 `TypeError`。JSON 没有 `Infinity`，因此 7.0.3 版以 `Infinity` 保存的选项读回时为 `null`：对于 `maxClues`、`minDistance` 和 `minLanguageExamples`，它按 `Infinity` 读取；对于 `hamCutoff` 按 `-Infinity`（永不判为 ham）读取，对于 `spamCutoff` 按 `Infinity`（永不判为 spam）读取；其他选项则按默认值读取。`toJSON` 会把超出 0 到 1 范围的阈值保存为 -1 或 2，效果相同。`loadModel` 会在文件变化时重新读取，`saveModel` 通过一个新的临时文件写入，该文件在替换模型之前会先刷写到磁盘，模型保留其权限。

### 训练

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` 接受 `{label, features}` 项，或者 `readExamples(sources)` 的结果（它读取与 `train` 相同的来源），并返回计数、精确率、召回率、F1、准确率，以及误报率、漏报率和不确定率。

### 服务器

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

milter 的 `onError` 决定扫描失败或 ClamAV 未能扫描某个附件时如何应答：`'tempfail'`（默认）或 `'accept'`；后者会放行邮件并加上 `X-Spam-Virus-Scan: failed` 标记，同时去掉发件人添加的 `X-Spam-*` 头。

### ARF 报告

`spamscanner/arf` 读写滥用反馈报告（RFC 5965），这是邮箱服务商用于报告垃圾邮件投诉的格式：

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

`parse()` 接受 Buffer、Uint8Array 或字符串。`ArfParser.tryParse()` 对不是报告的邮件返回 `null` 而不是抛出错误，`isArfMessage(mail)` 用于检查已解析的邮件。`originalHeaders` 对于不含原始邮件的报告为 `null`。`create()` 返回字符串，若 `originalMessage` 是 `Buffer`，则返回值也是同一类型，从而无论字符集如何都能保留其字节。
