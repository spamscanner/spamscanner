<!-- source: c93fa1a3f9c7 -->

<!--
label: 常见问题
title: 常见问题
description: 关于 Spam Scanner 的解答：准确率如何，支持哪些语言，会通过网络发送什么，语言模型、SpamAssassin 和 Forward Email。
keywords: Spam Scanner 常见问题, 垃圾邮件过滤器问题, 垃圾邮件过滤准确率, 垃圾邮件过滤隐私
-->

# 常见问题


## Spam Scanner 是什么？

适用于 Node.js、命令行和邮件服务器的垃圾邮件过滤器。它读取原始电子邮件，判定其是否为垃圾邮件、钓鱼邮件、诈骗邮件或是否携带恶意软件，并给出分数和作出判定的测试列表。它可以作为库、用于 Postfix 和 Sendmail 的 milter、兼容 SpamAssassin 的 spamd 服务器、Postfix 内容过滤器、HTTP API 或 TCP 服务器运行。


## 它免费吗？

它的[许可证](https://github.com/spamscanner/spamscanner/blob/master/LICENSE)是 Business Source License 1.1，允许除向他人提供垃圾邮件检测服务以外的任何用途，并写明了它转为 Apache License 2.0 的日期。


## 它有多准确？

在其训练数据中留出的英文邮件上，仅内置分类器本身就没有把任何正常邮件误判为垃圾邮件，并识别出了 97% 的垃圾邮件；各语言的完整数据见[训练指南](../../docs/training.md#the-bundled-model)。链接、附件、身份验证、黑名单和语言模型还会在此基础上进一步提升。你自己的邮件才是真正的检验：`spamscanner eval` 可以在任何已标注的邮件上测量任何模型。


## 它支持哪些语言？

全部语言。它按 Unicode 规则分词，包括不使用空格的中文、日文和泰文。如果内置模型很少见到某种语言的邮件，它会保持“不确定”而不是标记该邮件，由语言模型或你自己训练的模型来判定。[语言](../../docs/languages.md)


## 它会把我的邮件发送到别处吗？

不会。默认情况下，它只在 Cloudflare 的过滤 DNS 解析器上查询链接的主机名，除此之外没有任何内容离开本机。身份验证、黑名单、语言模型和信誉服务在配置之前都处于关闭状态，并且邮件发送给托管语言模型之前会移除个人数据。[安全与隐私](../../docs/security.md)


## 我需要语言模型吗？

不需要。它是难以判断时的第二意见。没有语言模型时，这些邮件只按分数判定。


## 我应该使用哪个语言模型？

在 CPU 上通过 Ollama 使用 `qwen3.5:4b`，有 GPU 时使用 `qwen3.5:9b`。两者都采用 Apache 许可证，能读 201 种语言。Anthropic、OpenAI、Google 等提供的托管模型也可以使用。[推荐的模型](../../docs/llm.md#recommended-open-models)


## 它能替代 SpamAssassin 吗？

对大多数部署来说可以：它支持 spamd 的协议，因此 spamc、Exim 和 Haraka 无需改动即可使用，并且它写入相同的 `X-Spam-*` 邮件头。它不运行 SpamAssassin 的规则文件。[SpamAssassin 替代方案](/spamassassin-alternative/)


## 它会拒收正常邮件吗？

拒收默认关闭：milter 只做标记。使用 `--reject` 时，只有得分 15 及以上的邮件才会被拒收，并且返回临时性的 451 错误，因此发件方会重试，判定有误时只需修改设置即可纠正。内容过滤器从不在 SMTP 会话期间拒收。


## 如何用我的邮件训练它？

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`，然后使用 `--model model.json`。mbox 文件、Maildir、存放 `.eml` 文件的文件夹，以及 CSV 或 JSON Lines 数据集都可以。[训练](../../docs/training.md)


## 没有 Node.js 能用吗？

能：适用于 Linux、macOS 和 Windows 的独立二进制文件已包含 Node.js 和模型。`curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`。


## 谁开发了它？

[Forward Email](https://forwardemail.net)，为其自己的邮件服务器而开发。
