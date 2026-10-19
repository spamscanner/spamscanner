<!-- source: 988243aec4f3 -->

<!--
label: セルフホスト型スパムフィルター
title: 自分のメールサーバーで動かすセルフホスト型スパムフィルター
description: 自分のサーバーで動くスパムフィルター。Spam Scanner はメールをマシン上に留め、モデルをパッケージに同梱し、テレメトリーを送らず、Postfix や Exim と連携します。
keywords: セルフホスト スパムフィルター, オンプレミス スパムフィルター, プライベート スパムフィルター, ローカル スパムフィルター, メールサーバー スパムフィルター, クラウド不要 スパムフィルター
-->

# セルフホスト型スパムフィルター

Spam Scanner は自分のサーバーで動き、メールをそこから出しません。分類器のモデルはパッケージに含まれ、テレメトリーも更新確認もなく、既定で外部に送るのは各リンクのホスト名についての DNS クエリだけです。


## サーバーの外に出るもの

既定では、メッセージ内のリンクのホスト名だけです。Cloudflare のフィルタリング用リゾルバー（1.1.1.2 と 1.1.1.3）で通常の DNS クエリとして調べ、メッセージやアドレスの一部が送られることはありません。`--no-cloudflare` でこれも止められます。

ネットワークを使うほかのチェックは、有効にするまですべて無効です。

| チェック                  | 有効にする方法              | 送るもの                                 |
| --------------------- | -------------------- | ------------------------------------ |
| SPF, DKIM, DMARC, ARC | `--auth`             | 送信者のレコードを調べる DNS クエリ                 |
| DNS ブロックリスト           | `--dnsbl`, `--uribl` | クライアントの IP アドレスとリンクのドメイン（DNS クエリとして） |
| ClamAV                | `--clamav`           | 添付ファイル（自分の clamd へ）                  |
| 言語モデル                 | `--llm`              | メッセージの要約（指定したサーバーへ）                  |

検査結果は記録も保存もされません。[セキュリティとプライバシー](../../docs/security.md)


## サーバーへのインストール

```sh
npm install --global spamscanner
```

または、Node.js とモデルを内蔵した単体のバイナリ：

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

インストールスクリプトは、インストール前にリリースの `SHA256SUMS` ファイルでバイナリを照合します。各バイナリには署名付きのビルド来歴証明があり、`gh attestation verify` で確認できます。バイナリは Linux（x64 と arm64）、macOS、Windows 向けです。Linux 用バイナリは glibc が必要なため、Alpine では npm でインストールしてください。[はじめに](../../docs/getting-started.md)

更新の確認はありません。更新するには同じインストールコマンドをもう一度実行します。どちらのコマンドも最新のリリースを入れます。


## サービスとして動かす

milter、HTTP、TCP、spamd の各サーバーは、`--host` で指定しない限り 127.0.0.1 で待ち受けます。特権のないユーザーで、たとえば systemd の下で動かしてください。

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

[ユニット全体と設定手順](../../docs/postfix.md#1-run-the-milter)は Postfix ガイドにあります。どのサーバーも TLS を話さないため、別のマシンから接続するにはプライベートネットワーク、SSH トンネル、TLS 付きのリバースプロキシを使ってください。


## メールサーバーとの接続

| メールサーバー              | コマンド                                    | ポート  |
| -------------------- | --------------------------------------- | ---- |
| Postfix または Sendmail | `spamscanner milter`                    | 7831 |
| Postfix（メールを拒否しない）   | `spamscanner filter`（コンテンツフィルター）        | なし   |
| Exim、Haraka、spamc    | `spamscanner spamd`                     | 783  |
| HTTP を話すもの全般         | `spamscanner http`                      | 7832 |
| シンプルな TCP クライアント     | `spamscanner server`                    | 7830 |
| Node.js で書かれたメールサーバー | `import SpamScanner from 'spamscanner'` | なし   |

サーバーはメッセージに `X-Spam-Flag`、`X-Spam-Score`、`X-Spam-Status` ヘッダーを追加でき、ライブラリはスコアと作動したすべてのテストを返します。ガイド：[Postfix スパムフィルター](/postfix-spam-filter/)、[ほかのメールサーバー](../../docs/mail-servers.md)、[HTTP API](../../docs/http-api.md)。


## 言語モデルをローカルで動かす

言語モデルは任意で、判断の難しいメッセージだけを読みます。明らかなスパムや明らかな ham は届きません。Ollama なら同じサーバーで動くため、メッセージがサーバーの外に出ることはありません。

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` は CPU で動きます。ホスト型のプロバイダーを使う場合は、送信前にメッセージから個人情報を取り除きます。[言語モデル](../../docs/llm.md)


## 自分のメールで学習させる

同梱のモデルは公開データセットで学習しています。サーバーが受け取るメールで学習したモデルのほうが精度が高く、そのサーバーに留まります。

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

モデルファイルが保持するのはハッシュ化した特徴の件数で、単語やメッセージ本文ではありません。[学習](../../docs/training.md)


## 動作要件

Linux、macOS、Windows 上の Node.js 18 以降。単体のバイナリなら何も要りません。ClamAV と Ollama は任意で、それぞれ別のサービスとして動きます。
