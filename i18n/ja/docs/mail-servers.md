<!-- source: 1151282f29d3 -->

# その他のメールサーバー

Spam Scannerは4つのプロトコルを話すため、ほとんどのメールソフトウェアは専用のプラグインなしで使えます。

| プロトコル  | コマンド                                    | 利用するソフトウェア                                   |
| ------ | --------------------------------------- | -------------------------------------------- |
| milter | `spamscanner milter`                    | Postfix、Sendmail、OpenSMTPD（filter-milterを使用） |
| spamd  | `spamscanner spamd`                     | spamc、Exim、Haraka、その他SpamAssassin向けに書かれたもの   |
| HTTP   | `spamscanner http`                      | スクリプト、Webhook、独自のMTAやサービス                    |
| パイプ    | `spamscanner scan`、`spamscanner filter` | Postfixのパイプ、procmail、maildrop、cronジョブ        |

[PostfixとSendmail](postfix.md)には専用のページがあります。


## SpamAssassinのspamdをそのまま置き換える

`spamscanner spamd`はSpamAssassinのspamdプロトコルに応答します。`CHECK`、`SYMBOLS`、`REPORT`、`REPORT_IFSPAM`、`PROCESS`、`HEADERS`、`PING`、そして`--allow-tell`を指定すれば`TELL`にも応答します。SpamAssassin向けに書かれたソフトウェアはそのまま動きます。`spamd`を止め、同じポートでSpam Scannerを起動してください。

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

spamcでは次のようにします。

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

リポジトリのエンドツーエンドテストでは、SpamAssassin自身のspamcを使ってテストしています。


## Exim

Eximの`spam` ACL条件はspamdと通信します。メインの設定に次のように記述します。

```text
spamd_address = 127.0.0.1 783
```

DATA ACL（Debianのexim4では`acl_check_data`）に次のように記述します。

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer`は一時的な4xxエラーで応答するため、送信者は再送し、誤りがあっても修正できます。結果が正しいと確認できたら、恒久的に拒否するよう`deny`に変更してください。


## Haraka

Harakaの`spamassassin`プラグインはspamdと通信します。`config/plugins`で有効にし、`config/spamassassin.ini`に次のように設定します。

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot：迷惑メールフォルダーと学習

Sieveのルールで、タグ付きのメールを迷惑メールフォルダー（Junk）に振り分けます。

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

IMAPSieveを使えば、メッセージを迷惑メールフォルダーに移動したり、そこから戻したりすることでモデルに学習させられます。トークンとモデルファイルを指定してHTTP APIを起動します。

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

そして、milterまたはspamdサーバーが`--model /var/lib/spamscanner/model.json`（または`SPAMSCANNER_MODEL`）で同じモデルを使うようにします。学習した内容を反映させるため、ときどき再起動してください。`sieve_pipe`が実行するスクリプトでメッセージを送信します。

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

残りの設定はDovecotの[スパム報告ガイド](https://doc.dovecot.org/main/core/config/spam_reporting.html)にあります。スクリプトから学習するスパムフィルターであれば、どれも同じ設定です。


## procmailとmaildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop：

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

`scan --headers`はスパムの場合に1で終了します。上のルールでは、procmailとmaildropは終了コードではなく出力を使います。


## HTTP API

HTTPリクエストを送れるプログラムであれば、どれでもメールをスキャンできます。

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

すべてのエンドポイントは[HTTP API](http-api.md)に記載しています。


## Node.jsのメールサーバー内で

[smtp-server](https://nodemailer.com/extras/smtp-server/)、Harakaのプラグイン、その他のNode.jsサーバーでは、ライブラリを直接呼び出します。

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({authentication: true});

// smtp-server's onData handler
async function onData(stream, session, callback) {
  const result = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (result.action === 'reject') {
    const error = new Error('Message rejected as spam');
    error.responseCode = 451;
    return callback(error);
  }

  // Deliver, with result.isSpam deciding the folder.
  callback();
}
```

smtp-serverの`session.envelope`は、Spam Scannerが読み取る`mailFrom`と`rcptTo`の形をすでに備えています。
