<!-- source: 1562b843d858 -->

<!--
label: SpamAssassinの代替
title: spamdのプロトコルを話すSpamAssassinの代替
description: SpamAssassinのspamdをSpam Scannerに置き換えます。spamc、Exim、Harakaはそのまま動き、X-Spamヘッダーの名前も変わらず、あらゆる言語に対応します。
keywords: SpamAssassin 代替, SpamAssassin 乗り換え, spamd 置き換え, spamc, Exim スパムフィルター, Haraka spamassassin, rspamd 代替, X-Spam-Status
-->

# spamdのプロトコルを話すSpamAssassinの代替

Spam ScannerはSpamAssassinのspamdプロトコルに応答するため、SpamAssassin向けに書かれたソフトウェアはそのまま使えます。spamc、Eximの`spam`条件、Harakaの`spamassassin`プラグインなどです。


## 置き換える

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

`CHECK`、`SYMBOLS`、`REPORT`、`REPORT_IFSPAM`、`PROCESS`、`HEADERS`、`PING`に応答し、`--allow-tell`を指定すれば学習用の`TELL`にも応答します。プロジェクトのエンドツーエンドテストでは、SpamAssassin自身のspamcを使ってテストしています。


## 変わらないもの

* ヘッダー：`X-Spam-Flag`、`X-Spam-Score`、`X-Spam-Level`、`X-Spam-Status`をSpamAssassinの形式で書き込むため、既存のSieve、procmail、メールクライアントのルールはそのまま動きます。
* しきい値5のスコア。名前付きのテストとその点数から成ります：`BAYES_99`、`RBL_ZEN`、`SPF_FAIL`、`DKIM_PASS`など。
* テストごとのスコアは、テスト名で変更できます。


## 違うところ

* **言語**：単語はUnicodeの規則で分割するため、中国語、日本語、タイ語は1本の長い文字列ではなく単語として読まれます。不可視文字やラテン文字の単語に混ざったキリル文字などの偽装は、先に元に戻します。
* **フィッシング**：類似ドメイン、欺瞞的なリンク、表示名に含まれるブランド名を、追加のルールなしで検査します。
* **添付ファイル**はバイト列で識別します。`.pdf`に名前を変えた実行ファイルも、実行ファイルのままです。
* **言語モデル**：際どい判定は、Ollama経由のローカルモデルやホスト型のモデルに回せます。
* **Node.js**：`npm install`を1回実行するか、スタンドアロンバイナリを使うだけです。管理すべきPerlモジュールやルールの更新はありません。

Spam ScannerはSpamAssassinのルールファイルを実行せず、ベイズデータベースの形式も独自のものです。同じメールから`spamscanner train`で学習させてください。


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

[Exim、Haraka、Dovecot、procmail](../../docs/mail-servers.md)
