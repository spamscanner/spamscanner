<!-- source: ff86d06bdcd0 -->

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
| `--max-size <bytes>`       | 読み込むメッセージの最大サイズ（デフォルトは26214400、25 MiB）     |

終了コード：0はハム、1はスパム、2はエラー。

`scan`と`learn`は、ファイルまたは標準入力から、メッセージを最大`--max-size`バイトまで読みます。サーバーにも同じ上限があります。これより大きいメッセージはエラー（終了コード2）となり、残りは読みません。

標準出力には結果（またはメッセージ）だけを出力します。コマンドの実行中にライブラリが出力するもの、たとえばDKIMの本文長に関するmailauthの注記は、標準エラー出力に送られます。

### SMTPセッション

| オプション               | 意味                        |
| ------------------- | ------------------------- |
| `--ip <address>`    | メッセージを送信したクライアントのIPアドレス   |
| `--hostname <name>` | クライアントの検証済みの逆引きDNS名       |
| `--helo <name>`     | クライアントがHELOまたはEHLOで名乗った名前 |
| `--from <address>`  | エンベロープの送信者（MAIL FROM）     |
| `--to <address>`    | エンベロープの受信者。複数の場合は繰り返す     |

### 検査

| オプション                 | 意味                                                                            |
| --------------------- | ----------------------------------------------------------------------------- |
| `--auth`              | SPF、DKIM、DMARC、ARCを検査する（`--ip`が必要）                                            |
| `--dnsbl <zone>`      | IPブロックリスト。例：`zen.spamhaus.org`。繰り返し指定可                                        |
| `--uribl <zone>`      | リンク用のドメインブロックリスト。例：`dbl.spamhaus.org`。繰り返し指定可                                 |
| `--dns-server <ip>`   | DNS検査に使うネームサーバー。繰り返し指定可                                                       |
| `--no-cloudflare`     | リンクについてCloudflareのフィルタリング用リゾルバーに問い合わせない                                       |
| `--clamav[=socket]`   | clamdで添付ファイルをスキャンする。デフォルトのソケットか指定したソケットを使う                                    |
| `--allowlist <value>` | このクライアント IP アドレスやホスト名、または認証で送信者が確認されたときのこのドメインやアドレス（`--auth`）を常に受け入れる。繰り返し指定可 |
| `--denylist <value>`  | このIPアドレス、ドメイン、アドレスを常に拒否する。繰り返し指定可                                             |

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
| `--llm-mode <mode>`                                     | `auto`（際どい判定のみ、デフォルト）、`always`、または`off`                                                   |
| `--llm-timeout <ms>`                                    | デフォルトは30000                                                                               |
| `--llm-policy <text>`                                   | モデル向けの追加ルール。例：「請求書をメールで送ることはない」                                                           |
| `--llm-redact`、`--no-llm-redact`                        | 先に個人データを削除する。リモートのプロバイダーではデフォルトで有効                                                        |


## filter

[Postfixのコンテンツフィルター](postfix.md#content-filter)です。標準入力からメッセージを読み、`X-Spam-*`ヘッダーを追加して、同じエンベロープでsendmailに渡します。

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| オプション                 | 意味                                                |
| --------------------- | ------------------------------------------------- |
| `--sendmail <path>`   | デフォルトは`/usr/sbin/sendmail`                        |
| `--subject-tag <tag>` | スパムの件名の先頭に付ける                                     |
| `--reject`            | 拒否のしきい値に達したメールを、渡さずにバウンスする                        |
| `--discard`           | 拒否のしきい値に達したメールを、渡さずに破棄する                          |
| `--on-error <answer>` | 完全にはスキャンできなかったメールの扱い。`tempfail`（デフォルト）または`accept` |
| `--max-size <bytes>`  | スキャンするメッセージの最大サイズ（デフォルトは26214400、25 MiB）          |

終了コードは、Postfixが読み取るsendmailの慣例に従います。0は配送済み（または破棄済み）、64は受信者の指定なし、69はスパムとして拒否（Postfixがバウンスする）、75はなんらかの失敗です。75の場合、Postfixはメッセージを保持して後で再試行します。ClamAVがスキャンできなかった添付ファイルを含むメッセージも失敗として扱います。`--on-error accept`を指定すると、そのようなメッセージやスキャンに失敗したメッセージは、`X-Spam-Virus-Scan: failed`を付け、送信者が付けた`X-Spam-*`ヘッダーを除いて渡されます。

`--max-size`より大きいメッセージはスキャンせず、全体をメモリに保持することもありません。延期する（75）か、`--on-error accept`を指定した場合は、読みながらスキャンせずに渡します。上記のとおり印を付け、送信者の`X-Spam-*`ヘッダーは除きます。Postfixの`message_size_limit`（デフォルトは10 MB）により、メールはデフォルトの上限より小さく保たれます。25 MiBを超えて引き上げる場合は、`--max-size`も引き上げてください。


## milter、http、server、spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832    # token in SPAMSCANNER_TOKEN
spamscanner server --port 7830
spamscanner spamd --port 783
```

HTTP API はトークンを環境変数 `SPAMSCANNER_TOKEN` から読み込みます。`--token` も使えますが、同じマシンの他のユーザーは `ps` でコマンドラインオプションを見ることができます。

ポート783は、SpamAssassinのクライアントがデフォルトで使うポートです。1024未満のポートにはrootか`CAP_NET_BIND_SERVICE`ケーパビリティが必要です。`--port 7833`のような別のポートを使い、クライアントにそれを指定してください。

| オプション                   | 意味                                                                                                                    |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `--port <n>`            | TCPポート                                                                                                                |
| `--host <ip>`           | 待ち受けるアドレス（デフォルトは127.0.0.1）                                                                                            |
| `--socket <path>`       | 代わりにUnixソケットで待ち受ける                                                                                                    |
| `--max-size <bytes>`    | 受け入れるメッセージの最大サイズ（デフォルトは26214400、25 MiB）。milterは長い本文の先頭をスキャンし、エンベロープとヘッダーだけで上限を超える場合は、スキャン失敗時と同じように応答します（`--on-error`） |
| `--max-connections <n>` | 同時に開ける接続数（デフォルトは200）。超えた分はすぐに閉じます。HTTP：同時に処理するリクエスト数でもあり、超えた分には`503`を返します                                             |
| `--reject`              | milter：拒否のしきい値に達したメールを拒否する                                                                                            |
| `--reject-code <n>`     | milter：4xxコード（後で再試行、451がデフォルト）、または550などの5xxコード                                                                        |
| `--quarantine`          | milter：スパムをメールサーバーの隔離領域に保留する                                                                                          |
| `--on-error <answer>`   | milter：完全にはスキャンできなかったメールの扱い。`tempfail`（デフォルト）または`accept`                                                              |
| `--name <hostname>`     | milter：Authentication-Resultsに記載するこのサーバーの名前                                                                           |
| `--token <secret>`      | HTTP：`Authorization: Bearer <secret>`を必須にする。`/learn`に必要                                                               |
| `--allow-tell`          | spamd：学習用のTELLリクエスト（`spamc -L spam`）を受け付ける                                                                            |
| `--out <file>`          | HTTPとspamd：学習した内容をこのモデルファイルに保存する                                                                                      |
| `--subject-tag <tag>`   | milterとspamd：スパムの件名の先頭に付ける                                                                                            |
| `--verbose`             | milter：すべてのスキャンをログに記録する。TCPサーバー：1行のテキストで応答する                                                                          |

上記のスキャンのオプションはサーバーにも適用されます。[milter](postfix.md#milter)、[HTTP API、TCPサーバー、spamd](http-api.md)を参照してください。

spamd と TCP のクライアントはメッセージを送ってきたクライアントの IP アドレスを送らず、HTTP クライアントも `?ip=` を付けたときだけ送ります。そのため `--auth` と `--dnsbl` が働くのは、milter と、IP アドレスを渡す HTTP リクエストだけです。これらのオプションを付けて起動すると、サーバーがその旨を表示します。


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

`--model` と `--out` の両方を指定すると、`learn` は `--model` のファイルから始めて、結果を `--out` に書き込みます。


## llm-testとmodels

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test`は、英語とイタリア語で、普通のメッセージ1通と詐欺のメッセージ2通をモデルに送り、その判定、それぞれにかかった時間、使った方式、そしてこのマシン上のモデルであればハードウェアを表示します。3通すべてが正しい場合にだけ0で終了します。


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
