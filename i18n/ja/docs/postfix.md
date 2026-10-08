<!-- source: f1043eb5fc58 -->

# PostfixとSendmail

Spam ScannerをPostfixに接続する方法は2つあります。

* **milterとして**（推奨）：PostfixはSMTPセッション中、メッセージを受け取る前に、各メッセージについて問い合わせます。スパムは4xxまたは5xxの応答で拒否できるため、その処理は自分のサーバーではなく送信側のサーバーが担います。Sendmailも同じプロトコルを使います。
* **コンテンツフィルターとして**：Postfixがメッセージを受け取り、`spamscanner filter`に渡します。フィルターはヘッダーを追加し、sendmailでメッセージを戻します。SMTPセッション中に拒否することは一切ありません。

どちらの方法でも、すべてのメッセージに次のヘッダーを追加します。

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

メッセージにすでにある`X-Spam-*`ヘッダーは先に削除されるため、送信者が自分のメールを問題なしと偽ることはできません。


## milter

### 1. milterを起動する

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

`--reject`を指定すると、拒否のしきい値（15点）に達したメッセージは`451 4.7.1 Message rejected as spam`で拒否されます。451は一時的なエラーです。送信者は後で再送し、誤りがあっても設定を変えれば修正できます。結果が正しいと確認できたら、`--reject-code 550`で恒久的に拒否できます。`--quarantine`を指定すると、スパムは代わりにPostfixの保留キューに入ります。

systemdのサービスにする場合は、`/etc/systemd/system/spamscanner-milter.service`に次のように記述します。

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. Postfixから使うように設定する

`/etc/postfix/main.cf`に次のように記述します。

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters`はSMTP経由で届くメールが対象です。`sendmail`コマンドで投入したメールもスキャンする必要がない限り、`non_smtpd_milters`は空のままにしてください。

### 3. テストする

[swaks](https://www.jetmore.org/john/code/swaks/)でテストメッセージを送れます。GTUBEは、どのスパムフィルターもスパムとして扱うテスト用の文字列です。

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

`--reject`を指定しなければ、メッセージは`X-Spam-Flag: YES`とタグ付きの件名で配送されます。`--reject`を指定すると、swaksに451または550の応答が表示されます。


## コンテンツフィルター

SMTPセッション中にメールを決して拒否してはならない場合や、milterを使えないサーバーで使います。

`/etc/postfix/master.cf`にフィルターのサービスを追加し、SMTPのリスナーで使います。

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfixはほとんど空の環境でフィルターを実行するため、`argv`ではNode.jsとスクリプトをフルパスで指定します（`command -v node`と`npm root --global`で確認できます）。その後、次を実行します。

```sh
sudo postfix reload
```

フィルターは`sendmail -G -i`でメッセージを戻します。この方法で投入されたメールは再び`smtp`リスナーを通らないため、二重にフィルタリングされることはありません。

終了コードでPostfixに結果を伝えます。0は配送済み、69は拒否（`--reject`指定時。Postfixが送信者にバウンスする）、75は一時的な失敗（Postfixがメッセージを保持して再試行する）です。スキャンや配送の失敗はすべて75になるため、設定が壊れていてもメールが失われたりバウンスしたりすることはありません。


## Sendmail

`sendmail.mc`に次のように記述します。

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T`を指定すると、milterを利用できない間、Sendmailは一時的な失敗で応答します。代わりにメールをフィルタリングせずに受け入れるには、これを外してください。`sendmail.cf`を再生成し、Sendmailを再起動します。


## スパムを迷惑メールフォルダーに振り分ける

タグ付けだけでは、スパムは受信トレイに配送されます。Dovecotでは、Sieveのルールでスパムを移動します。

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[その他のメールサーバー](mail-servers.md)ではDovecot、Exim、Haraka、procmailを扱っています。ユーザーが迷惑メールフォルダーに出し入れしたメールから学習する方法は[学習](training.md#learning-from-reports)を参照してください。


## テスト

リポジトリのエンドツーエンドテストでは、実際のPostfixを動かします。ハムはヘッダー付きで配送され、偽造された`X-Spam-Flag`は削除され、スパムはタグ付けされ、GTUBEはSMTPセッション中に550で拒否され、コンテンツフィルターは2つ目のポートでメールにタグを付けます。`scripts/e2e-postfix.sh`がそのPostfixを準備し、`test/e2e/postfix.test.js`がメールを送ります。
