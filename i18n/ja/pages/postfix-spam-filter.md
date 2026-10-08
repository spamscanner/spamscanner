<!-- source: f33722183f00 -->

<!--
label: Postfixスパムフィルター
title: milterまたはコンテンツフィルターで使うPostfixスパムフィルター
description: Spam Scannerのmilterまたはコンテンツフィルターで、Postfixサーバーのスパムを判定します。設定、systemdユニット、4xxや5xxでの拒否、迷惑メールフォルダー。
keywords: Postfix スパムフィルター, Postfix 迷惑メール対策, Postfix milter, smtpd_milters, Postfix content_filter, Postfix スパム 拒否
-->

# Postfixスパムフィルター

Spam Scannerなら、Postfixサーバーのスパムフィルタリングを約5分で導入できます。milterとして動作するため、PostfixはSMTPセッション中に各メッセージについて問い合わせ、受け取る前にスパムを拒否できます。


## インストールと実行

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth`はSPF、DKIM、DMARC、ARCを検査し、`--subject-tag`は件名でスパムを示します。どのメッセージにも`X-Spam-Flag`、`X-Spam-Score`、`X-Spam-Status`、`X-Spam-Action`ヘッダーが付き、送信者が入れた`X-Spam-*`ヘッダーは先に削除されます。


## Postfixに接続する

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept`は、milterが停止しているときにメールをフィルタリングせずに通します。`tempfail`にすると、代わりに送信者に再送を求めます。


## SMTPセッション中にスパムを拒否する

```sh
spamscanner milter --port 7831 --auth --reject
```

拒否のしきい値（15点）に達したメッセージは、`451 4.7.1 Message rejected as spam`で拒否されます。451は一時的なエラーです。送信者はメッセージを保持して再送するため、判定を誤っても遅延が生じるだけで、メッセージは失われません。結果が正しいと確認できたら、`--reject-code 550`で拒否を恒久的にできます。


## milterを使わない場合

コンテンツフィルターは、Postfixがメッセージを受け取った後に動作します。Postfixがメッセージを`spamscanner filter`に渡し、ヘッダーを追加して返します。セッション中に拒否することは一切なく、失敗したときは常にバウンスではなく配送の延期になります。[コンテンツフィルターの設定](../../docs/postfix.md#content-filter)


## スパムを迷惑メールフォルダーへ

Dovecotでは、Sieveのルールでタグ付きのメールを振り分けます。

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## 実際のPostfixでテスト済み

プロジェクトのエンドツーエンドテストでは、milterとコンテンツフィルターを使ってPostfixを動かします。ハムはヘッダー付きで配送されて偽造された`X-Spam-Flag`は削除され、スパムはタグ付けされ、GTUBEはSMTPセッション中に550で拒否されます。

次へ：systemdユニットとSendmailの`INPUT_MAIL_FILTER`を含む[PostfixとSendmailの完全なガイド](../../docs/postfix.md)。
