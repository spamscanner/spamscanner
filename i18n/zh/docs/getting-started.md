<!-- source: 8263c06f1dab -->

# 入门

Spam Scanner 需要 Node.js 18 或更高版本；使用独立二进制文件则无需任何依赖。


## 安装

作为命令行工具：

```sh
npm install --global spamscanner
spamscanner version
```

作为 Node.js 项目中的库：

```sh
npm install spamscanner
```

作为适用于 Linux 或 macOS 的独立二进制文件，内置 Node.js 和模型：

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

每个[版本发布](https://github.com/spamscanner/spamscanner/releases)都附有适用于 Linux（x64 和 arm64）、macOS（Intel 和 Apple 芯片）和 Windows 的二进制文件。


## 扫描一封邮件

把邮件保存为文件（大多数邮件程序称之为“另存为”或“显示原始邮件”），然后扫描：

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

退出码对 ham（正常邮件）为 0，对垃圾邮件为 1，出错时为 2，因此脚本可以直接使用。`--json` 输出完整结果，`--headers` 输出添加了 `X-Spam-*` 邮件头的邮件。

邮件也可以来自标准输入：

```sh
cat message.eml | spamscanner scan -
```


## 在 Node.js 中使用

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

CommonJS 同样可用：

```js
const SpamScanner = require('spamscanner');
```

`scan()` 接受 Buffer、字符串、Uint8Array 或可读流形式的原始邮件。字符串始终被视为邮件文本：Spam Scanner 绝不会因为字符串看起来像路径就去读取文件。读取文件请使用 `scanner.scanFile(path)`。


## 提供 SMTP 会话信息

客户端的 IP 地址、经过验证的主机名、HELO 名称和信封会让结果更准确：身份验证需要 IP 地址，冒充自身域名的规则需要收件人。

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

在命令行中也是一样：

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## 开启更多检查

以下检查默认都不开启，因为每一项都需要外部服务或需要你作出决定：

| 检查                 | 库选项                                              | 命令行                        |
| ------------------ | ------------------------------------------------ | -------------------------- |
| SPF、DKIM、DMARC、ARC | `authentication: true`                           | `--auth`                   |
| IP 黑名单             | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org` |
| 链接域名黑名单            | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org` |
| ClamAV             | `clamav: true` 或 `clamav: {socket}`              | `--clamav [socket]`        |
| 语言模型               | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`             |
| 允许列表和拒绝列表          | `allowlist: [...]`、`denylist: [...]`             | `--allowlist`、`--denylist` |

默认会向 Cloudflare 的过滤解析器（1.1.1.2 针对恶意软件，1.1.1.3 针对成人内容）查询链接主机。用 `phishing: {cloudflare: false}` 或 `--no-cloudflare` 关闭。[哪些内容会离开本机](security.md)

Spamhaus 和其他一些黑名单不响应通过 8.8.8.8 或 1.1.1.1 等公共解析器发送的查询。请配合本地缓存解析器使用，并根据你的查询量查看其使用条款。


## 下一步

* 把它部署在邮件服务器前面：[Postfix 和 Sendmail](postfix.md)、[其他服务器](mail-servers.md)。
* 用你自己的邮件训练它：[训练](training.md)。
* 为难以判断的邮件添加语言模型：[语言模型](llm.md)。
