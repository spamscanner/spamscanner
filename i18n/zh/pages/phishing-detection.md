<!-- source: 0378a5e0f12b -->

<!--
label: 钓鱼邮件检测
title: 电子邮件钓鱼检测：仿冒域名、欺骗性链接和冒充
description: Spam Scanner 如何检测钓鱼邮件：Unicode 仿冒域名，显示一个地址却指向另一个地址的链接，品牌显示名称，Cloudflare 的恶意软件解析器和 DMARC。
keywords: 钓鱼邮件检测, 邮件钓鱼过滤, 同形异义字攻击, IDN 同形攻击, 仿冒域名检测, 欺骗性链接, 品牌冒充邮件
-->

# 电子邮件钓鱼检测

钓鱼的手法是冒充他人。Spam Scanner 检查伪装会露出破绽的地方。


## 仿冒域名

链接中的每个域名都会用 Unicode 易混淆字符表归约为骨架形式，再与近 100 个常被冒充的品牌进行比较：

| 域名                                  | 识别为                    |
| ----------------------------------- | ---------------------- |
| `pаypal.com`（西里尔字母 а）               | 易混淆字符                  |
| `paypa1-secure.top`                 | 调换字符                   |
| `xn--pple-43d.com`                  | `аpple.com` 的 Punycode |
| `paypal.com.account-verify.example` | 品牌出现在他人的域名中            |
| `paypall.com`                       | 相差一个字母                 |

可以添加品牌，也可以把你拥有的域名加入允许列表。


## 欺骗性链接

如果一个 HTML 链接的文字是一个地址而目标是另一个地址，例如文字为 `https://www.paypal.com/signin`，却指向 `http://paypa1-secure.top/login`，则加 3 分。


## 显示名称和冒充

* 显示名称包含某个品牌（“PayPal Security”），但发件地址属于另一个域名。
* 显示名称包含另一个电子邮件地址。
* 声称来自收件人自己域名的邮件，却未通过 SPF、DKIM 和 DMARC。


## 已知的恶意网站

链接主机会在 Cloudflare 的 1.1.1.2 解析器上查询，该解析器会拦截已知的恶意软件和钓鱼网站；还可以选择在 Spamhaus DBL 等域名黑名单上查询。


## 附件

钓鱼也会以 HTML 附件的形式出现，离线绘制一个假的登录页面，或者以改名为 `.pdf` 的可执行文件的形式出现。两者都会根据内容被识别出来。

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

[检查的工作原理](../../docs/how-it-works.md#phishing)
