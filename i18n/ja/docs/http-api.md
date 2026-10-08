<!-- source: faf44f093f8b -->

# HTTP API、TCPサーバー、spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

`--host`で指定しない限り、127.0.0.1で待ち受けます。トークンを設定すると、`/health`以外のすべてのリクエストに`Authorization: Bearer <token>`が必要になります。マシンの外に公開する前に、TLSを使うリバースプロキシの背後に置いてください。

| メソッドとパス            | 本文      | 応答                                         |
| ------------------ | ------- | ------------------------------------------ |
| `GET /health`      |         | `{"ok": true, "version": "7.0.0"}`         |
| `POST /scan`       | 生のメッセージ | JSON形式の[スキャン結果](api.md#the-result)         |
| `POST /check`      | 生のメッセージ | `X-Spam-*`ヘッダーを追加したメッセージ（`message/rfc822`） |
| `POST /learn/spam` | 生のメッセージ | `{"ok": true, "learned": "spam"}`。トークンが必要  |
| `POST /learn/ham`  | 生のメッセージ | `{"ok": true, "learned": "ham"}`。トークンが必要   |

クエリパラメーターでSMTPセッションの情報を渡します。

| パラメーター       | 意味                                    |
| ------------ | ------------------------------------- |
| `ip`         | クライアントのIPアドレス                         |
| `hostname`   | クライアントの検証済みの逆引きDNS名                   |
| `helo`       | クライアントのHELOまたはEHLOの名前                 |
| `from`       | エンベロープの送信者                            |
| `to`         | 受信者。繰り返すか、複数をカンマで区切る                  |
| `verbose=1`  | `/scan`：単語の一覧と件名も返す                   |
| `subjectTag` | `/check`：スパムの件名の先頭に付ける。例：`%5BSPAM%5D` |

`/check`は、`X-Spam-Flag`、`X-Spam-Score`、`X-Spam-Action`をレスポンスヘッダーとしても返すため、クライアントはメッセージを解析せずに判断できます。

25 MBを超えるメッセージには`413`を返します。スキャンに失敗した場合は、`{"error": "..."}`とともに`500`を返します。

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

`--out model.json`を指定すると、`/learn`で学習させた内容がリクエストごとにそのファイルに保存されます。指定しない場合、学習内容はサーバーを再起動するまでしか保持されません。

Node.jsからは次のようにします。

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Pythonからは次のようにします。

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## TCPサーバー

```sh
spamscanner server --port 7830
```

生のメッセージを送り、接続の送信側を閉じてから、1行のJSONを読み取ります。

```sh
nc -N 127.0.0.1 7830 < message.eml
```

`--verbose`を指定すると、代わりに1行のテキストで応答します：`SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND`または`HAM -2.5/5.0 BAYES_00`。


## spamd

```sh
spamscanner spamd --port 783
```

spamc、Exim、Harakaなど、SpamAssassinのクライアント向けのSpamAssassin互換サーバーです。[EximとHarakaの設定](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| コマンド            | 応答                                            |
| --------------- | --------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                     |
| `SYMBOLS`       | 判定と、該当したテストの名前                                |
| `REPORT`        | 判定と、テスト、点数、理由の表                               |
| `REPORT_IFSPAM` | `REPORT`と同様。ただしハムの場合はレポートが空                   |
| `PROCESS`       | 判定と、`X-Spam-*`ヘッダー付きのメッセージ                    |
| `HEADERS`       | 判定と、`X-Spam-*`ヘッダー付きのメッセージのヘッダー部分             |
| `PING`          | `PONG`                                        |
| `SKIP`          | なし                                            |
| `TELL`          | `--allow-tell`を指定するとスパムまたはハムを学習し、`--out`に保存する |

圧縮されたリクエスト（`Compress: zlib`）は拒否します。
