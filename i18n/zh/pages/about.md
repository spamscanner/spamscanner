<!-- source: 599bd320e55a -->

<!--
label: 关于
title: 关于 Spam Scanner、许可证和隐私
description: Spam Scanner 由谁开发，如何报告错误或漏洞，使用什么许可证，以及本网站收集哪些数据：没有 Cookie，也没有统计分析。
keywords: 关于 Spam Scanner, Forward Email, Spam Scanner 许可证, BUSL-1.1, Spam Scanner 联系方式, Spam Scanner 隐私
-->

# 关于 Spam Scanner

Spam Scanner 是注重隐私的邮件服务 [Forward Email](https://forwardemail.net) 为自己的邮件服务器开发的邮件垃圾过滤器。源代码、问题和版本发布在 [GitHub](https://github.com/spamscanner/spamscanner) 上，软件包发布在 [npm](https://www.npmjs.com/package/spamscanner) 上。


## 由谁开发

Forward Email 团队编写并维护 Spam Scanner。Forward Email 不保存邮件内容的日志，因此无法把邮件发送给外部过滤服务：过滤器必须在自己的服务器上运行，并且在无人阅读邮件的情况下说明每个判定的理由。[Forward Email 如何使用它](../../docs/forward-email.md)

Forward Email 同样是开源的，见 [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net)。其创始人是 DuckDuckGo 最早的员工之一。


## 联系方式

* **问题、错误和功能请求：** 在 [GitHub](https://github.com/spamscanner/spamscanner/issues) 上提交问题。
* **安全漏洞：** 请通过 [GitHub 的漏洞报告](https://github.com/spamscanner/spamscanner/security/advisories/new)私下报告，不要发在公开问题中。同一地址也写在 [security.txt](https://spamscanner.net/.well-known/security.txt) 中。
* **其他许可：** 请联系 [Forward Email](https://forwardemail.net)。


## 许可条款

Spam Scanner 的[许可证](https://github.com/spamscanner/spamscanner/blob/master/LICENSE)是 Business Source License 1.1，其 Change License 为 Apache License 2.0。许可证中写明的 Change Date 已经过去，自该日起，许可证授予你 Apache License 2.0 下的权利。


## 隐私

本网站不设置 Cookie，也不从其他网站加载统计分析、跟踪器、广告、字体或脚本。所有文件都来自 spamscanner.net。

* 主题、你选择的语言以及你分享到的 Mastodon 服务器保存在浏览器的本地存储中，不会发送到任何地方。
* 视频只在你播放时才加载。
* 分享链接是普通链接，在你点击之前不会从这些网络加载任何内容。
* 本网站托管在 GitHub Pages 上，GitHub 出于安全目的会记录每位访客的 IP 地址。请参阅 [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) 和 [GitHub 隐私声明](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)。


## 软件会发送什么

Spam Scanner 不发送遥测数据，也不检查更新。默认情况下，它只会在 Cloudflare 的过滤 DNS 解析器上查询邮件中链接的主机名，除此之外没有任何数据离开本机。其他网络检查在你开启之前都是关闭的。[安全与隐私](../../docs/security.md)


## 版本发布

独立二进制文件由 GitHub Actions 从公开仓库构建。每个版本都在 `SHA256SUMS` 文件中列出它们的哈希值，安装脚本会进行校验，每个二进制文件都带有签名的构建来源证明。版本及其说明发布在 [GitHub](https://github.com/spamscanner/spamscanner/releases) 上。
