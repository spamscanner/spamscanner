<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner 由 [Forward Email](https://forwardemail.net) 为其自己的邮件服务器开发，Forward Email 是一家开源、注重隐私的电子邮件服务。Forward Email 不记录邮件内容，因此任何外部过滤服务都不适用：过滤器必须在它自己的服务器上运行，并且必须在无人阅读邮件的情况下解释每一个判定。

本页介绍 Forward Email 这样的邮件服务器如何使用它，以及为 Spam Scanner 5 或 6 编写的代码有哪些变化。


## 在接收邮件服务器上

Forward Email 使用 [smtp-server](https://nodemailer.com/extras/smtp-server/) 接收邮件。对于任何基于它构建的服务器，模式如下：

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

`scanner.scan()` 直接接受 SMTP 流。如果手头已有 [mailauth](https://github.com/postalsys/mailauth) 的结果，可以跳过 `authentication`，只传入 IP 地址。

421 或 451 回复会让发送方服务器把邮件放入队列并稍后重试。新的拒收规则可以先使用临时性代码，在结果经过检查后再改为 550，期间不会丢失邮件。


## 从版本 5 或 6 升级

版本 7 是重写版本。构造函数、`scan()` 以及版本 5 和 6 的代码读取的结果字段仍然可用；分类器、模型和可选的 TensorFlow 检查有所变化。

### 保持不变

* `new SpamScanner(options)` 和 `await scanner.scan(source)`。
* `require('spamscanner')` 返回该类，`import SpamScanner from 'spamscanner'` 也可用。
* `result.isSpam`、`result.message`，以及 `result.results.classification`、`.phishing`、`.executables`、`.arbitrary`、`.viruses`、`.macros` 和 `.idnHomographAttack`。
* `results.phishing`、`.executables`、`.arbitrary` 和 `.viruses` 中的每一项都会转换为与以前相同类型的消息字符串（`String(item)`、模板字面量、`message.includes('adult-related content')`）。它们现在是带有 `type`、`message` 和详细信息的对象。
* `getTokensAndMailFromSource()`、`getClassification()` 和 `getTokens()`。
* 以下选项对应到新名称：`clamscan` 改为 `clamav`，`enableMacroDetection: false` 改为 `macros: false`，`enableArbitraryDetection: false` 改为 `arbitrary: false`，`enableAuthentication` 加 `authOptions` 改为 `authentication` 和 `session`，`enableReputation` 加 `reputationOptions.apiUrl` 改为 `reputation`，`strictIDNDetection` 改为 `phishing.homograph.strictMode`，以及 `allowlist` 和 `denylist`。`logger` 和 `memoize` 会被接受并忽略。

### 有变化

| 以前                                     | 现在                                                                                                                     |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` 会读取文件       | 字符串即邮件文本。请使用 `scanFile(path)` 或传入 Buffer                                                                               |
| 基于词语的朴素贝叶斯模型（`classifier.json`），现已无法加载 | 新的分类器和模型格式；用 `spamscanner train` 重新训练（[训练](training.md)）                                                               |
| 毒性和 NSFW 检查在首次使用时从网络加载 TensorFlow 模型   | 自带模型：`toxicity: {model}` 和 `nsfw: {model}` 接受任何带有 `classify()` 方法的对象，例如来自 `@tensorflow-models/toxicity` 和 `nsfwjs` 的对象 |
| `results.arbitrary` 列出所有匹配的模式          | 它只列出足以单独判定为垃圾邮件的规则；所有规则都在 `result.tests` 中                                                                             |
| 是或否的回答                                 | `result.score`、`result.action`（`accept`、`tag` 或 `reject`）和 `result.tests`，每项都附有分值和原因                                   |
| `isSpam` 由分类器或任何单项检查决定                 | `isSpam` 表示分数达到 5 或以上；阈值和分值都可以修改                                                                                       |
| 针对 Forward Email 端点的信誉检查               | 通用的信誉服务，除非设置了 `reputation.apiUrl`，否则关闭                                                                                 |

### 新增

* 用于难以判断的邮件的[语言模型](llm.md)，本地或托管均可。
* SPF、DKIM、DMARC 和 ARC；DNS 黑名单；Cloudflare 的过滤解析器。
* 按内容进行的附件检查：伪装的可执行文件、压缩包、宏、含活动内容的 PDF。
* [milter、HTTP API、TCP 服务器和 spamd 服务器](mail-servers.md)，以及[命令行](cli.md)。
* 训练、评估以及从举报中学习，可通过命令行或 API 进行。
