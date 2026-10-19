<!-- source: 599bd320e55a -->

<!--
label: 概要
title: Spam Scanner について、ライセンスとプライバシー
description: Spam Scanner の開発元、バグや脆弱性の報告方法、ライセンス、そしてこのサイトが集めるもの（Cookie もアクセス解析もなし）について。
keywords: Spam Scanner について, Forward Email, Spam Scanner ライセンス, BUSL-1.1, Spam Scanner 連絡先, Spam Scanner プライバシー
-->

# Spam Scanner について

Spam Scanner は、プライバシーを重視するメールサービス [Forward Email](https://forwardemail.net) が自社のメールサーバー向けに作ったメール用スパムフィルターです。ソースコード、Issue、リリースは [GitHub](https://github.com/spamscanner/spamscanner) に、パッケージは [npm](https://www.npmjs.com/package/spamscanner) にあります。


## 開発しているのは

Forward Email のチームが Spam Scanner を開発し、保守しています。Forward Email はメッセージ内容のログを残さないため、外部のフィルタリングサービスにメールを送ることはできませんでした。フィルターは自社のサーバーで動き、人がメールを読まずにすべての判定の理由を示す必要がありました。[Forward Email での使い方](../../docs/forward-email.md)

Forward Email もオープンソースで、[github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net) で公開しています。創業者は DuckDuckGo の初期の社員の一人でした。


## 連絡先

* **質問、バグ、機能の要望：** [GitHub](https://github.com/spamscanner/spamscanner/issues) で Issue を作成してください。
* **セキュリティの脆弱性：** 公開の Issue ではなく、[GitHub の脆弱性報告](https://github.com/spamscanner/spamscanner/security/advisories/new)から非公開で報告してください。同じ宛先は [security.txt](https://spamscanner.net/.well-known/security.txt) にも記載しています。
* **ほかのライセンス：** [Forward Email](https://forwardemail.net) にお問い合わせください。


## ライセンスの条件

Spam Scanner の[ライセンス](https://github.com/spamscanner/spamscanner/blob/master/LICENSE)は Business Source License 1.1 で、Change License は Apache License 2.0 です。ライセンスに記載された Change Date はすでに過ぎており、その日以降、ライセンスは Apache License 2.0 に基づく権利をあなたに与えます。


## プライバシー

このサイトは Cookie を設定せず、ほかのサイトからアクセス解析、トラッカー、広告、フォント、スクリプトを読み込みません。すべてのファイルは spamscanner.net から配信されます。

* テーマ、選んだ言語、共有先の Mastodon サーバーはブラウザーのローカルストレージに保存され、どこにも送られません。
* 動画は再生したときにだけ読み込まれます。
* 共有リンクは通常のリンクなので、リンクを開くまでそれらのネットワークから何も読み込まれません。
* サイトは GitHub Pages でホストされており、GitHub はセキュリティのために訪問者ごとの IP アドレスを記録します。[GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) と [GitHub のプライバシーステートメント](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)をご覧ください。


## ソフトウェアが送るもの

Spam Scanner はテレメトリーを送らず、更新も確認しません。既定では、メッセージ内のリンクのホスト名を Cloudflare のフィルタリング用 DNS リゾルバーで調べるだけで、ほかには何もマシンの外に出ません。ほかのネットワークチェックは、有効にするまで無効です。[セキュリティとプライバシー](../../docs/security.md)


## リリース

単体のバイナリは、公開リポジトリから GitHub Actions がビルドします。各リリースはバイナリのハッシュを `SHA256SUMS` ファイルに記載し、インストールスクリプトがそれを照合します。各バイナリには署名付きのビルド来歴証明があります。リリースとリリースノートは [GitHub](https://github.com/spamscanner/spamscanner/releases) にあります。
