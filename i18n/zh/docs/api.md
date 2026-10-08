<!-- source: b3cc9f949acd -->

# API 参考

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

创建一个扫描器并重复使用：它只加载一次模型，并缓存 DNS 和语言模型的回答。


## 选项

每个选项都可以传给构造函数。大多数选项也可以针对单封邮件传给 `scan()`，它们会覆盖合并到构造函数的选项之上。

| 选项                     | 默认值                              | 含义                                                                                           |
| ---------------------- | -------------------------------- | -------------------------------------------------------------------------------------------- |
| `threshold`            | `5`                              | 邮件判为垃圾邮件的分数                                                                                  |
| `rejectThreshold`      | `15`                             | `action` 为 `reject` 的分数                                                                      |
| `scores`               | `{}`                             | 每项测试的分值：设置键或测试名称（[测试与分值](scoring.md)）                                                        |
| `classifier`           | 内置模型                             | `Classifier`、模型对象、模型文件路径或 `false`                                                            |
| `classifierOptions`    | `{}`                             | 内置模型的选项（见[分类器](#classifier)）                                                                 |
| `allowedLanguages`     | `[]`                             | ISO 639-1 代码；其他语言会得到 `LANGUAGE_NOT_ALLOWED`                                                  |
| `phishing.cloudflare`  | `true`                           | 向 Cloudflare 的过滤解析器查询链接主机                                                                    |
| `phishing.adult`       | `true`                           | 同时查询拦截成人网站的家庭解析器                                                                             |
| `phishing.maxHosts`    | `25`                             | 每封邮件查询的链接主机数量                                                                                |
| `phishing.homograph`   | `{}`                             | `brands`（替换内置列表）、`extraBrands`、`allowlist`（从不标记的域名）、`strictMode`                             |
| `dnsbl`                | `{ip: [], domain: []}`           | 针对客户端 IP 和链接域名的 DNS 黑名单区域                                                                    |
| `dns`                  | `{servers: null, timeout: 3000}` | DNS 检查使用的域名服务器（默认：系统的域名服务器）                                                                  |
| `attachments`          | `true`                           | 检查附件                                                                                         |
| `macros`               | `true`                           | 标记宏、含活动内容的 PDF 和 RTF 对象                                                                      |
| `arbitrary`            | `true`                           | 运行[规则](scoring.md#rules)                                                                     |
| `authentication`       | `false`                          | `true`，或 `{dnsServers, timeout, mta, weights}`：SPF、DKIM、DMARC、ARC                            |
| `reputation`           | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                            |
| `allowlist`、`denylist` |                                  | IP 地址、域名或地址；`reputation` 的简写                                                                 |
| `clamav`               | `false`                          | `true`（默认套接字）、`{socket}` 或 `{host, port}`                                                    |
| `llm`                  | `null`                           | [语言模型设置](llm.md#any-server-port-and-authentication)，含 `mode`、`minScore`、`maxScore`           |
| `toxicity`             | `false`                          | `{model, threshold = 0.7}`：一个其 `classify([text])` 的回答形式与 `@tensorflow-models/toxicity` 相同的模型 |
| `nsfw`                 | `false`                          | `{model, threshold = 0.6}`：一个其 `classify(imageBuffer)` 的回答形式与 `nsfwjs` 相同的模型                 |
| `maxLength`            | `100000`                         | 读取的正文字符数                                                                                     |
| `timeout`              | `10000`                          | 每项网络检查允许的毫秒数                                                                                 |
| `session`              | `{}`                             | 默认的 SMTP 会话信息                                                                                |

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


## 方法

| 方法                                   | 返回值                                                     |
| ------------------------------------ | ------------------------------------------------------- |
| `scan(source, options)`              | 结果。`source` 为 Buffer、字符串、Uint8Array 或可读流                |
| `scanFile(path, options)`            | 邮件文件的结果                                                 |
| `learn(source, 'spam' \| 'ham')`     | 用一封邮件训练分类器                                              |
| `unlearn(source, 'spam' \| 'ham')`   | 撤销 `learn`                                              |
| `saveModel(path, options)`           | 把分类器写入文件（`options`：`minCount`、`maxFeatures`、`metadata`） |
| `getClassifier()`                    | 正在使用的 `Classifier`，或 `null`                             |
| `getClassification(features)`        | 分类器对 `getFeatures` 所得特征的判定                              |
| `getFeatures(mail)`                  | 已解析邮件的 `{features, words, language, script, links}`     |
| `getTokens(text, locale)`            | 文本中的词语                                                  |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                              |
| `parse(source)`                      | `{raw, mail}`，其中 `mail` 来自 mailparser                   |

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

`phishing`、`attachments`、`executables`、`macros`、`viruses` 和 `arbitrary` 中的发现都是带有 `type` 和 `message` 的对象。`String(finding)` 即为该消息。


## 导出

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

| 选项                                    | 默认值           | 含义                               |
| ------------------------------------- | ------------- | -------------------------------- |
| `strength`、`unknown`                  | `0.45`、`0.5`  | Robinson 的 s 和 x：罕见特征被拉向 0.5 的强度 |
| `minDistance`                         | `0.1`         | 与 0.5 的距离小于此值的特征会被忽略             |
| `maxClues`                            | `150`         | 每封邮件合并的最强特征数量                    |
| `hamCutoff`、`spamCutoff`              | `0.2`、`0.99`  | `unsure` 区间的边界                   |
| `minLanguageExamples`、`languageShare` | `1000`、`0.02` | 某种语言中每类需要多少封邮件才能达到十足的置信度         |
| `languagePrior`                       | `true`        | 用词语所属语言的计数来衡量词语                  |

还可以使用 `merge(other)`、`toJSON(options)`、`Classifier.fromJSON(json)`、`size` 和 `entries()`。

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARF 报告

`spamscanner/arf` 读写滥用反馈报告（RFC 5965），这是邮箱服务商用于报告垃圾邮件投诉的格式：

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

`ArfParser.tryParse()` 对不是报告的邮件返回 `null` 而不是抛出错误，`isArfMessage(mail)` 用于检查已解析的邮件。
