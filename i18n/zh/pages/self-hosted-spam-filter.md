<!-- source: 988243aec4f3 -->

<!--
label: 自托管垃圾邮件过滤器
title: 为你自己的邮件服务器部署自托管垃圾邮件过滤器
description: 运行在你自己服务器上的垃圾邮件过滤器。Spam Scanner 将邮件留在本机，模型随包附带，不发送遥测数据，并可接入 Postfix 或 Exim。
keywords: 自托管垃圾邮件过滤器, 本地部署垃圾邮件过滤器, 私有垃圾邮件过滤器, 本地垃圾邮件过滤器, 邮件服务器垃圾邮件过滤器, 无云垃圾邮件过滤器
-->

# 自托管垃圾邮件过滤器

Spam Scanner 运行在你自己的服务器上，邮件也留在那里。分类器模型包含在软件包中，没有遥测，也不检查更新，默认情况下它唯一发出的是对每个链接主机名的 DNS 查询。


## 哪些数据会离开服务器

默认情况下，只有邮件中链接的主机名。它们以普通 DNS 查询的方式在 Cloudflare 的过滤解析器（1.1.1.2 和 1.1.1.3）上查询，邮件内容及其地址的任何部分都不会被发送。`--no-cloudflare` 也可以关闭这一项。

其他所有使用网络的检查在你开启之前都是关闭的：

| 检查                    | 开启方式                 | 发送的内容                      |
| --------------------- | -------------------- | -------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | 查询发件人记录的 DNS 请求            |
| DNS 黑名单               | `--dnsbl`, `--uribl` | 客户端 IP 地址和链接域名，以 DNS 查询的形式 |
| ClamAV                | `--clamav`           | 附件，发送到你自己的 clamd           |
| 语言模型                  | `--llm`              | 邮件摘要，发送到你指定的服务器            |

扫描不会被记录或保存。[安全与隐私](../../docs/security.md)


## 在服务器上安装

```sh
npm install --global spamscanner
```

或者使用内置 Node.js 和模型的独立二进制文件：

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

安装脚本在安装前会用该版本的 `SHA256SUMS` 文件校验二进制文件，每个二进制文件还带有签名的构建来源证明，可用 `gh attestation verify` 验证。二进制文件提供 Linux（x64 和 arm64）、macOS 和 Windows 版本。Linux 版本需要 glibc，因此在 Alpine 上请用 npm 安装。[快速开始](../../docs/getting-started.md)

没有更新检查。要更新，再次运行安装命令即可：两条命令都会安装最新版本。


## 作为服务运行

milter、HTTP、TCP 和 spamd 服务器默认监听 127.0.0.1，除非 `--host` 另行指定。请以无特权用户运行它们，例如在 systemd 下：

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

[完整的单元文件及其设置](../../docs/postfix.md#1-run-the-milter)见 Postfix 指南。这些服务器都不支持 TLS，因此要从另一台机器访问，请使用私有网络、SSH 隧道或带 TLS 的反向代理。


## 接入你的邮件服务器

| 邮件服务器               | 命令                                      | 端口   |
| ------------------- | --------------------------------------- | ---- |
| Postfix 或 Sendmail  | `spamscanner milter`                    | 7831 |
| Postfix，从不拒收邮件      | `spamscanner filter`，内容过滤器              | 无    |
| Exim、Haraka 或 spamc | `spamscanner spamd`                     | 783  |
| 任何支持 HTTP 的程序       | `spamscanner http`                      | 7832 |
| 简单的 TCP 客户端         | `spamscanner server`                    | 7830 |
| 用 Node.js 编写的邮件服务器  | `import SpamScanner from 'spamscanner'` | 无    |

服务器可以为邮件添加 `X-Spam-Flag`、`X-Spam-Score` 和 `X-Spam-Status` 邮件头，库则返回分数和每个触发的测试。指南：[Postfix 垃圾邮件过滤器](/postfix-spam-filter/)、[其他邮件服务器](../../docs/mail-servers.md)和 [HTTP API](../../docs/http-api.md)。


## 在本地运行语言模型

语言模型是可选的，只读取难以判断的邮件：明显的垃圾邮件和明显的 ham 都不会送到它那里。使用 Ollama 时，它在同一台服务器上运行，因此没有邮件会离开服务器：

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` 可在 CPU 上运行。若改用托管服务商，邮件在发送前会去除个人数据。[语言模型](../../docs/llm.md)


## 用你自己的邮件训练

自带的模型由公开数据集训练而成。用你的服务器收到的邮件训练出的模型效果更好，并且会留在该服务器上：

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

模型文件保存的是经过哈希的特征计数，而不是单词或邮件正文。[训练](../../docs/training.md)


## 运行要求

Linux、macOS 或 Windows 上的 Node.js 18 或更高版本；使用独立二进制文件则无需任何依赖。ClamAV 和 Ollama 是可选的，各自作为独立服务运行。
