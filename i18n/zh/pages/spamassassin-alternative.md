<!-- source: 1562b843d858 -->

<!--
label: SpamAssassin 替代方案
title: 支持 spamd 协议的 SpamAssassin 替代方案
description: 用 Spam Scanner 替换 SpamAssassin 的 spamd。spamc、Exim 和 Haraka 照常工作，X-Spam 邮件头名称不变，并支持所有语言。
keywords: SpamAssassin 替代, spamd 替换, spamc, Exim 垃圾邮件过滤, Haraka spamassassin, rspamd 替代, X-Spam-Status
-->

# 支持 spamd 协议的 SpamAssassin 替代方案

Spam Scanner 响应 SpamAssassin 的 spamd 协议，因此为 SpamAssassin 编写的软件无需改动即可使用它：spamc、Exim 的 `spam` 条件、Haraka 的 `spamassassin` 插件等。


## 替换上去

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

它响应 `CHECK`、`SYMBOLS`、`REPORT`、`REPORT_IFSPAM`、`PROCESS`、`HEADERS`、`PING`，以及在使用 `--allow-tell` 时用于学习的 `TELL`。项目的端到端测试会用 SpamAssassin 自己的 spamc 对它进行测试。


## 保持不变的部分

* 邮件头：`X-Spam-Flag`、`X-Spam-Score`、`X-Spam-Level` 和 `X-Spam-Status` 采用 SpamAssassin 的格式，因此现有的 Sieve、procmail 和邮件客户端规则照常工作。
* 阈值为 5 的分数，由带分值的命名测试组成：`BAYES_99`、`RBL_ZEN`、`SPF_FAIL`、`DKIM_PASS` 等。
* 可以按测试名称修改每项测试的分值。


## 不同之处

* **语言**。按 Unicode 规则分词，因此中文、日文和泰文会被读成词语而不是一个长字符串，不可见字符或拉丁字母词语中的西里尔字母等伪装会先被还原。
* **钓鱼**。无需额外规则即可检查仿冒域名、欺骗性链接和显示名称中的品牌名。
* **附件**按字节识别：改名为 `.pdf` 的可执行文件仍然是可执行文件。
* **语言模型**。难以判断的邮件可以通过 Ollama 交给本地模型，也可以交给托管模型。
* **Node.js**。一条 `npm install`，或一个独立二进制文件；无需管理 Perl 模块或规则更新。

Spam Scanner 不运行 SpamAssassin 的规则文件，它的 Bayes 数据库格式也是自有的：用同样的邮件通过 `spamscanner train` 训练即可。


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim、Haraka、Dovecot 和 procmail](../../docs/mail-servers.md)
