<!-- source: 361732724f0e -->

<!--
label: よくある質問
title: よくある質問
description: Spam Scannerに関する回答：精度、対応言語、ネットワークに送る情報、言語モデル、SpamAssassin、Forward Emailについて。
keywords: Spam Scanner よくある質問, スパムフィルター 質問, スパムフィルター 精度, 迷惑メールフィルター 精度, スパムフィルター プライバシー
-->

# よくある質問


## Spam Scannerとは何ですか

Node.js、コマンドライン、メールサーバー向けのスパムフィルターです。生のメールメッセージを読み、スパム、フィッシング、詐欺、マルウェア付きのいずれに当たるかを、スコアと判定の決め手になったテストの一覧とともに判定します。ライブラリ、PostfixとSendmail向けのmilter、SpamAssassin互換のspamdサーバー、Postfixのコンテンツフィルター、HTTP API、TCPサーバーとして動作します。


## 無料ですか

[ライセンス](https://github.com/spamscanner/spamscanner/blob/master/LICENSE)であるBusiness Source License 1.1は、スパム検出をサービスとして他者に提供すること以外のあらゆる利用を認めており、Apache License 2.0に切り替わる日付も明記しています。


## 精度はどのくらいですか

学習データから取り分けた英語のメッセージでは、同梱の分類器単体でハムをスパムと誤判定したものはなく、スパムの97%を検出しました。言語ごとの詳しい数値は[学習ガイド](../../docs/training.md#the-bundled-model)にあります。これにリンク、添付ファイル、認証、ブロックリスト、言語モデルが加わります。本当のテストは自分のメールです。`spamscanner eval`を使えば、ラベル付きの任意のメールで任意のモデルを計測できます。


## どの言語に対応していますか

すべての言語です。Unicodeの規則で単語を分割するため、スペースを使わない中国語、日本語、タイ語にも対応します。同梱モデルがあまりメールを学習していない言語では、スパムと判定せずに「判定不能」とし、言語モデルや自分で学習させたモデルが判定します。[言語](../../docs/languages.md)


## メールをどこかに送りますか

いいえ。デフォルトでは、リンクのホスト名をCloudflareのフィルタリング用DNSリゾルバーで照会するだけで、それ以外にマシンの外に出るものはありません。認証、ブロックリスト、言語モデル、レピュテーションサービスは設定するまで無効で、ホスト型の言語モデルにメールを送る前に個人データは削除されます。[セキュリティとプライバシー](../../docs/security.md)


## 言語モデルは必要ですか

いいえ。言語モデルは際どい判定のためのセカンドオピニオンです。言語モデルがなければ、そうしたメッセージはスコアだけで判定されます。


## どの言語モデルを使うべきですか

CPUならOllama経由の`qwen3.5:4b`、GPUがあれば`qwen3.5:9b`です。どちらもApacheライセンスで、201言語を読みます。Spam Scannerはモデルの1ステップから各判定の確率を読み取ります。2コアのCPUでは、文章で答えさせると1通あたり31秒かかったのに対し、この方法では約11秒で、正確さは同じでした。ホスト型サービスなら、決定モデルのCloudflare ClefとTypeSafe Jevが1秒未満で答えます。Anthropic、OpenAI、Googleなども使えます。[測定結果](../../docs/llm.md#measured)と[推奨モデル](../../docs/llm.md#recommended-open-models)


## SpamAssassinの代わりになりますか

ほとんどの構成では、なります。spamdのプロトコルを話すため、spamc、Exim、Harakaはそのまま動き、同じ`X-Spam-*`ヘッダーを書き込みます。SpamAssassinのルールファイルは実行しません。[SpamAssassinの代替](/spamassassin-alternative/)


## 正当なメールを拒否することはありますか

メールの拒否はデフォルトで無効で、milterはタグ付けだけを行います。`--reject`を指定しても、拒否されるのはスコアが15以上のメッセージだけで、一時的な451エラーを返します。そのため送信者は再送し、誤りがあっても設定を変えれば直せます。コンテンツフィルターがSMTPセッション中に拒否することはありません。


## 自分のメールで学習させるには

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`を実行し、続いて`--model model.json`を指定します。mboxファイル、Maildir、`.eml`ファイルのフォルダー、CSVやJSON Linesのデータセットを使えます。[学習](../../docs/training.md)


## Node.jsなしでも動きますか

はい。Linux、macOS、Windows向けのスタンドアロンバイナリにはNode.jsとモデルが含まれています。`curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`。


## 誰が作っていますか

[Forward Email](https://forwardemail.net)が、自社のメールサーバーのために作っています。
