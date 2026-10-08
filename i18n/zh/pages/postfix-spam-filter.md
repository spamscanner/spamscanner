<!-- source: f33722183f00 -->

<!--
label: Postfix 垃圾邮件过滤
title: 使用 milter 或内容过滤器的 Postfix 垃圾邮件过滤
description: 用 Spam Scanner 的 milter 或内容过滤器为 Postfix 服务器过滤垃圾邮件：安装配置、systemd 单元、以 4xx 或 5xx 拒收，以及垃圾邮件文件夹。
keywords: Postfix 垃圾邮件过滤, Postfix milter, smtpd_milters, Postfix 内容过滤器, Postfix 反垃圾邮件, Postfix 拒收垃圾邮件
-->

# Postfix 垃圾邮件过滤器

Spam Scanner 大约五分钟就能为 Postfix 服务器配置好过滤。它作为 milter 运行，因此 Postfix 会在 SMTP 会话期间就每封邮件询问它，并可以在接收之前拒收垃圾邮件。


## 安装并运行

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` 检查 SPF、DKIM、DMARC 和 ARC；`--subject-tag` 在主题中标记垃圾邮件。每封邮件都会得到 `X-Spam-Flag`、`X-Spam-Score`、`X-Spam-Status` 和 `X-Spam-Action` 邮件头，发件人放入的任何 `X-Spam-*` 邮件头都会先被移除。


## 连接 Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` 在 milter 停止运行时让邮件不经过滤直接通过；`tempfail` 则要求发件方稍后重试。


## 在 SMTP 会话期间拒收垃圾邮件

```sh
spamscanner milter --port 7831 --auth --reject
```

达到拒收阈值（15 分）的邮件会以 `451 4.7.1 Message rejected as spam` 被拒收。451 是临时性错误：发件方会保留邮件并重试，因此错误的判定只会造成延迟，而不会丢失邮件。确认结果无误后，`--reject-code 550` 会把拒收改为永久性的。


## 不使用 milter

内容过滤器在 Postfix 接收邮件之后运行：Postfix 把邮件通过管道交给 `spamscanner filter`，后者添加邮件头再交回。会话期间从不拒收任何邮件，出现故障时总是推迟投递而不是退信。[内容过滤器配置](../../docs/postfix.md#content-filter)


## 把垃圾邮件放进 Junk

配合 Dovecot，一条 Sieve 规则即可归档已标记的邮件：

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## 在真实的 Postfix 上测试

项目的端到端测试会运行带有 milter 和内容过滤器的 Postfix：正常邮件带着邮件头投递，伪造的 `X-Spam-Flag` 被移除，垃圾邮件被标记，GTUBE 在 SMTP 会话期间以 550 被拒收。

下一步：[完整的 Postfix 和 Sendmail 指南](../../docs/postfix.md)，包含 systemd 单元和 Sendmail 的 `INPUT_MAIL_FILTER`。
