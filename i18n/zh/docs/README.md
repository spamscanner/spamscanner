<!-- source: c56969e779c4 -->

# Spam Scanner 文档

Spam Scanner 是适用于 Node.js 和命令行的垃圾邮件过滤器，源代码托管在 GitHub 上。它读取原始电子邮件，判定其是否为垃圾邮件、钓鱼邮件、诈骗邮件或是否携带恶意软件，适用于任何语言。它可以作为库、命令行工具、Postfix 或 Sendmail 的 milter、Postfix 内容过滤器、兼容 SpamAssassin 的 spamd 服务器、HTTP API 或 TCP 服务器运行。

它由 [Forward Email](https://forwardemail.net) 为其自己的邮件服务器开发。


## 如何判定一封邮件

每项检查都会加分或减分。由总分决定结果：

| 分数       | 动作       | 邮件服务器的处理      |
| -------- | -------- | ------------- |
| 低于 5     | `accept` | 投递邮件          |
| 5 到 14.9 | `tag`    | 投递并标记为垃圾邮件    |
| 15 及以上   | `reject` | 在 SMTP 会话期间拒收 |

两个阈值都可以修改。每个结果都会列出触发的测试及其分值和原因，因此任何判定都能得到解释。

检查项目：

* **经过训练的分类器**读取任何文字书写的邮件词语、链接的形态、发件人和附件。它出厂时已在公开数据集上训练，并能从你自己的邮件中学习。[分类器的工作原理](how-it-works.md#the-classifier)
* **钓鱼检查**识别仿冒域名（`paypa1.com`、含西里尔字母 а 的 `pаypal.com`），文字显示一个地址而目标是另一个地址的链接，以及自称某个品牌的显示名称。[钓鱼](how-it-works.md#phishing)
* **附件检查**发现可执行文件、伪装成文档的可执行文件、双重扩展名、从右到左文件名把戏、ZIP 文件中的可执行文件、Office 宏和 PDF 中的活动内容。ClamAV 可以扫描附件中的病毒。[附件](how-it-works.md#attachments)
* **身份验证**：在已知客户端 IP 地址时检查 SPF、DKIM、DMARC 和 ARC。[身份验证](how-it-works.md#authentication)
* **DNS 黑名单**检查客户端 IP 地址和链接中的域名，Cloudflare 的过滤解析器检查已知的恶意软件和成人网站。[黑名单](how-it-works.md#blocklists)
* **规则**处理无需分类器学习的模式：GTUBE 测试字符串、性勒索主题、PayPal 账单诈骗、冒充自身域名，以及针对 AI 过滤器隐藏的指令。[规则](scoring.md#rules)
* **语言模型**（可选）为难以判断的邮件提供第二意见：通过 Ollama 或任何兼容 OpenAI 的服务器使用本地模型，或使用 Claude、ChatGPT、Gemini 等。[语言模型](llm.md)


## 从哪里开始

* [入门](getting-started.md)：安装并扫描第一封邮件。
* [命令行](cli.md)：所有命令和选项。
* [Postfix 和 Sendmail](postfix.md)：用 milter 或内容过滤器为邮件服务器过滤邮件。
* [其他邮件服务器](mail-servers.md)：Exim、Haraka、Dovecot、procmail，以及任何能调用 HTTP API 的程序。
* [训练](training.md)：用你自己的邮件训练它，并测量结果。
* [语言模型](llm.md)：服务商、推荐的开放模型、隐私和提示注入。
* [语言](languages.md)：它如何读取中文、阿拉伯文、泰文及其他所有文字。
* [Forward Email](forward-email.md)：Forward Email 如何使用它，以及如何从版本 5 或 6 升级。
* [API 参考](api.md)和[测试与分值](scoring.md)。
* [安全与隐私](security.md)：哪些内容会离开本机，以及如何阻止。
