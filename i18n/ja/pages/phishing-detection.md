<!-- source: 0378a5e0f12b -->

<!--
label: フィッシング検出
title: メールのフィッシング検出：類似ドメイン、欺瞞的なリンク、なりすまし
description: Spam Scannerがフィッシングメールを検出する仕組み。Unicodeの類似ドメイン、表示と異なる宛先のリンク、ブランドの表示名、Cloudflareのマルウェア対策リゾルバー、DMARC。
keywords: フィッシング検出, フィッシングメール 対策, フィッシングメール フィルター, ホモグラフ攻撃, IDN ホモグラフ, 類似ドメイン 検出, 偽装リンク, なりすましメール
-->

# メールのフィッシング検出

フィッシングは、他人になりすますことで成り立ちます。Spam Scannerは、その偽装が表に出る箇所を検査します。


## 類似ドメイン

リンク内の各ドメインはUnicodeの紛らわしい文字の表（confusables）で骨格に変換され、なりすましの多い約100のブランドと比較されます。

| ドメイン                                | 検出理由                 |
| ----------------------------------- | -------------------- |
| `pаypal.com`（キリル文字のа）               | 紛らわしい文字              |
| `paypa1-secure.top`                 | 入れ替えた文字              |
| `xn--pple-43d.com`                  | `аpple.com`のPunycode |
| `paypal.com.account-verify.example` | 他人のドメインに含まれるブランド     |
| `paypall.com`                       | 1文字違い                |

ブランドは追加でき、自分が所有するドメインは許可リストに入れられます。


## 欺瞞的なリンク

テキストと宛先が別のアドレスになっているHTMLリンク、たとえばテキストが`https://www.paypal.com/signin`で宛先が`http://paypa1-secure.top/login`のリンクには3点が加算されます。


## 表示名となりすまし

* 別のドメインのアドレスから送られた、ブランド名を含む表示名（「PayPal Security」など）。
* 別のメールアドレスを含む表示名。
* 受信者自身のドメインから来たと称し、SPF、DKIM、DMARCに失敗するメール。


## 既知の悪質なサイト

リンクのホストは、既知のマルウェアサイトとフィッシングサイトをブロックするCloudflareの1.1.1.2リゾルバーで照会します。オプションでSpamhaus DBLなどのドメインブロックリストでも照会します。


## 添付ファイル

フィッシングは、オフラインで偽のログインページを表示するHTML添付ファイルや、`.pdf`に名前を変えた実行ファイルとしても届きます。どちらも内容から検出します。

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

[検査の仕組み](../../docs/how-it-works.md#phishing)
