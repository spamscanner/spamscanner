<!-- source: c061da9312ad -->

# コマンドライン

```text
spamscanner <command> [options]
```

| コマンド                                       | 動作                                        |
| ------------------------------------------ | ----------------------------------------- |
| `scan [file\|-]`                           | ファイルまたは標準入力のメッセージをスキャンする                  |
| `filter -f <sender> -- <recipients...>`    | Postfixのコンテンツフィルター。標準入力をスキャンし、ヘッダーを追加して渡す |
| `milter`                                   | PostfixとSendmail向けのmilter、ポート7831         |
| `http`                                     | HTTP API、ポート7832                          |
| `server`                                   | プレーンなTCPサーバー、ポート7830                      |
| `spamd`                                    | SpamAssassin互換のspamdサーバー、ポート783           |
| `train`                                    | mboxファイル、Maildir、フォルダー、データセットからモデルを学習させる  |
| `eval`                                     | ラベル付きのメールでモデルを計測する                        |
| `learn spam\|ham [file\|-] --model <file>` | モデルにメッセージを1通学習させる                         |
| `llm-test`                                 | 3通のサンプルメッセージで言語モデルの設定を確認する                |
| `models`                                   | 推奨のオープンモデルを一覧表示する                         |
| `version`、`help`                           |                                           |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| オプション                      | 意味                                         |
| -------------------------- | ------------------------------------------ |
| `--json`                   | 完全な結果をJSONで出力する                            |
| `--headers`                | `X-Spam-*`ヘッダーを追加したメッセージを出力する              |
| `--subject-tag <tag>`      | スパムの件名の先頭にも付ける                             |
| `--verbose`                | すべてのテストと、分類器の最も強い手がかりを表示する                 |
| `--threshold <n>`          | メールをスパムとするスコア（デフォルトは5）                     |
| `--reject-threshold <n>`   | メールを拒否するスコア（デフォルトは15）                      |
| `--model <file>`           | 同梱モデルの代わりに使うモデルファイル                        |
| `--no-classifier`          | 分類器を使わない                                   |
| `--config <file>`          | [ライブラリのオプション](api.md#options)を記述したJSONファイル |
| `--allow-language <codes>` | 受け入れる言語。例：`en,de,fr`                       |

終了コード：0はハム、1はスパム、2はエラー。

### SMTPセッション

| オプション               | 意味                        |
| ------------------- | ------------------------- |
| `--ip <address>`    | メッセージを送信したクライアントのIPアドレス   |
| `--hostname <name>` | クライアントの検証済みの逆引きDNS名       |
| `--helo <name>`     | クライアントがHELOまたはEHLOで名乗った名前 |
| `--from <address>`  | エンベロープの送信者（MAIL FROM）     |
| `--to <address>`    | エンベロープの受信者。複数の場合は繰り返す     |

### 検査

| オプション                 | 意味                                            |
| --------------------- | --------------------------------------------- |
| `--auth`              | SPF、DKIM、DMARC、ARCを検査する（`--ip`が必要）            |
| `--dnsbl <zone>`      | IPブロックリスト。例：`zen.spamhaus.org`。繰り返し指定可        |
| `--uribl <zone>`      | リンク用のドメインブロックリスト。例：`dbl.spamhaus.org`。繰り返し指定可 |
| `--dns-server <ip>`   | DNS検査に使うネームサーバー。繰り返し指定可                       |
| `--no-cloudflare`     | リンクについてCloudflareのフィルタリング用リゾルバーに問い合わせない       |
| `--clamav [socket]`   | clamdで添付ファイルをスキャンする。デフォルトのソケットか指定したソケットを使う    |
| `--allowlist <value>` | このIPアドレス、ドメイン、アドレスを常に受け入れる。繰り返し指定可            |
| `--denylist <value>`  | このIPアドレス、ドメイン、アドレスを常に拒否する。繰り返し指定可             |

### 言語モデル

| オプション                                                   | 意味                                                                                        |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `--llm <provider>`                                      | `ollama`、`clef-flash`、`jev`、`openai`、`anthropic`など（[一覧](llm.md#providers)）                |
| `--llm-model <name>`                                    | モデル。例：`qwen3.5:4b`、`claude-haiku-4-5`                                                     |
| `--llm-method <method>`                                 | `decision`（1ステップで各判定の確率を出す。使える場合はデフォルト）または`generate`（[方式](llm.md#decision-or-generation)） |
| `--llm-account <id>`                                    | CloudflareのアカウントID。`clef`と`clef-flash`用                                                   |
| `--llm-url <url>`                                       | ベースURL。例：`http://10.0.0.5:11434`                                                          |
| `--llm-host`、`--llm-port`、`--llm-path`、`--llm-protocol` | プロバイダーのURLの一部を変更する                                                                        |
| `--llm-api-key <key>`                                   | APIキー。下記の環境変数も参照                                                                          |
| `--llm-auth <type>`                                     | `bearer`、`x-api-key`、`api-key`、`basic`、`header`、`none`のいずれか                               |
| `--llm-auth-header <name>`                              | キーを入れるヘッダー。`--llm-auth header`と併用                                                         |
| `--llm-username`、`--llm-password`                       | `--llm-auth basic`用                                                                       |
| `--llm-header "Name: value"`                            | 追加のリクエストヘッダー。繰り返し指定可                                                                      |
| `--llm-mode <mode>`                                     | `auto`（際どい判定のみ、デフォルト）または`always`                                                          |
| `--llm-timeout <ms>`                                    | デフォルトは30000                                                                               |
| `--llm-policy <text>`                                   | モデル向けの追加ルール。例：「請求書をメールで送ることはない」                                                           |
| `--llm-redact`、`--no-llm-redact`                        | 先に個人データを削除する。リモートのプロバイダーではデフォルトで有効                                                        |


## filter

[Postfixのコンテンツフィルター](postfix.md#content-filter)です。標準入力からメッセージを読み、`X-Spam-*`ヘッダーを追加して、同じエンベロープでsendmailに渡します。

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| オプション                 | 意味                         |
| --------------------- | -------------------------- |
| `--sendmail <path>`   | デフォルトは`/usr/sbin/sendmail` |
| `--subject-tag <tag>` | スパムの件名の先頭に付ける              |
| `--reject`            | 拒否のしきい値に達したメールを、渡さずにバウンスする |
| `--discard`           | 拒否のしきい値に達したメールを、渡さずに破棄する   |

終了コードは、Postfixが読み取るsendmailの慣例に従います。0は配送済み（または破棄済み）、64は受信者の指定なし、69はスパムとして拒否（Postfixがバウンスする）、75はなんらかの失敗です。75の場合、Postfixはメッセージを保持して後で再試行します。


## milter、http、server、spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

ポート783は、SpamAssassinのクライアントがデフォルトで使うポートです。1024未満のポートにはrootか`CAP_NET_BIND_SERVICE`ケーパビリティが必要です。`--port 7833`のような別のポートを使い、クライアントにそれを指定してください。

| オプション                 | 意味                                                      |
| --------------------- | ------------------------------------------------------- |
| `--port <n>`          | TCPポート                                                  |
| `--host <ip>`         | 待ち受けるアドレス（デフォルトは127.0.0.1）                              |
| `--socket <path>`     | 代わりにUnixソケットで待ち受ける                                      |
| `--reject`            | milter：拒否のしきい値に達したメールを拒否する                              |
| `--reject-code <n>`   | milter：451（後で再試行、デフォルト）または550                           |
| `--quarantine`        | milter：スパムをメールサーバーの隔離領域に保留する                            |
| `--name <hostname>`   | milter：Authentication-Resultsに記載するこのサーバーの名前             |
| `--token <secret>`    | HTTP：`Authorization: Bearer <secret>`を必須にする。`/learn`に必要 |
| `--allow-tell`        | spamd：学習用のTELLリクエスト（`spamc -L spam`）を受け付ける              |
| `--out <file>`        | HTTPとspamd：学習した内容をこのモデルファイルに保存する                        |
| `--subject-tag <tag>` | milterとspamd：スパムの件名の先頭に付ける                              |
| `--verbose`           | milter：すべてのスキャンをログに記録する。TCPサーバー：1行のテキストで応答する            |

上記のスキャンのオプションはサーバーにも適用されます。[milter](postfix.md#milter)、[HTTP API、TCPサーバー、spamd](http-api.md)を参照してください。


## train、eval、learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| オプション                                          | 意味                                            |
| ---------------------------------------------- | --------------------------------------------- |
| `--spam <path>`                                | スパム：mboxファイル、Maildir、`.eml`ファイルのフォルダー。繰り返し指定可 |
| `--ham <path>`                                 | ハム（指定方法は同上）。繰り返し指定可                           |
| `--dataset <file>`                             | テキストとラベルの列を持つCSVまたはJSON Linesのファイル。繰り返し指定可    |
| `--text-column <name>`、`--label-column <name>` | 列名（自動で検出されない場合）                               |
| `--out <file>`                                 | モデルの書き込み先（デフォルトは`spamscanner-model.json`）     |
| `--merge`                                      | 空のモデルではなく、同梱モデル（または`--model`）から始める            |

`learn`はモデルファイルをその場で更新し、初回は同梱モデルからファイルを作ります。[学習](training.md)


## llm-testとmodels

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test`は、英語とイタリア語で、普通のメッセージ1通と詐欺のメッセージ2通をモデルに送り、その判定、それぞれにかかった時間、使った方式、ハードウェアを表示します。3通すべてが正しい場合にだけ0で終了します。


## 設定ファイル

`--config file.json`（または環境変数`SPAMSCANNER_CONFIG`）で[ライブラリのオプション](api.md#options)を読み込みます。コマンドラインのオプションはファイルの内容より優先されます。

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## 環境変数

| 変数                                                                                                                                                                                                                                                                                                         | 意味                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                       | 設定ファイル                |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                        | 同梱モデルの代わりに使うモデルファイル   |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                        | HTTP API用のトークン        |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                  | 任意の言語モデルプロバイダー用のAPIキー |
| `CLOUDFLARE_API_TOKEN`と`CLOUDFLARE_ACCOUNT_ID`、`TYPESAFE_API_KEY`、`OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`GEMINI_API_KEY`、`MISTRAL_API_KEY`、`GROQ_API_KEY`、`OPENROUTER_API_KEY`、`DEEPSEEK_API_KEY`、`XAI_API_KEY`、`TOGETHER_API_KEY`、`FIREWORKS_API_KEY`、`CEREBRAS_API_KEY`、`HF_TOKEN`、`AZURE_OPENAI_API_KEY` | 各プロバイダー固有のキー          |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                  | デバッグログ                |
