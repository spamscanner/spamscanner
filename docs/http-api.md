# HTTP API, TCP server and spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

It listens on 127.0.0.1 unless `--host` says otherwise. With a token, every request except `/health` needs `Authorization: Bearer <token>`. Put it behind a reverse proxy with TLS before exposing it beyond the machine.

| Method and path    | Body            | Answer                                                         |
| ------------------ | --------------- | -------------------------------------------------------------- |
| `GET /health`      |                 | `{"ok": true, "version": "7.0.0"}`                             |
| `POST /scan`       | The raw message | The [scan result](api.md#the-result) as JSON                   |
| `POST /check`      | The raw message | The message with `X-Spam-*` headers added, as `message/rfc822` |
| `POST /learn/spam` | The raw message | `{"ok": true, "learned": "spam"}`; needs a token               |
| `POST /learn/ham`  | The raw message | `{"ok": true, "learned": "ham"}`; needs a token                |

Query parameters describe the SMTP session:

| Parameter    | Meaning                                                        |
| ------------ | -------------------------------------------------------------- |
| `ip`         | The client's IP address                                        |
| `hostname`   | Its verified reverse DNS name                                  |
| `helo`       | Its HELO or EHLO name                                          |
| `from`       | The envelope sender                                            |
| `to`         | A recipient; repeat it or separate several with commas         |
| `verbose=1`  | `/scan`: also return the word list and the subject             |
| `subjectTag` | `/check`: prefix the subject of spam, for example `%5BSPAM%5D` |

`/check` also returns `X-Spam-Flag`, `X-Spam-Score` and `X-Spam-Action` as response headers, so a client can decide without parsing the message.

Messages larger than 25 MB get `413`. A scan that fails gets `500` with `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

With `--out model.json`, what `/learn` teaches is saved to that file after each request. Without it, learning lasts until the server restarts.

From Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

From Python:

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


## TCP server

```sh
spamscanner server --port 7830
```

Send the raw message, close the sending side of the connection, and read one line of JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

With `--verbose`, the answer is a line of text instead: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` or `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

A SpamAssassin-compatible server for spamc, Exim, Haraka and other SpamAssassin clients. [Setting up Exim and Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Command         | Answer                                                             |
| --------------- | ------------------------------------------------------------------ |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                          |
| `SYMBOLS`       | The verdict and the names of the tests that fired                  |
| `REPORT`        | The verdict and a table of tests, points and reasons               |
| `REPORT_IFSPAM` | Like `REPORT`, with an empty report for ham                        |
| `PROCESS`       | The verdict and the message with `X-Spam-*` headers                |
| `HEADERS`       | The verdict and the message's header block with `X-Spam-*` headers |
| `PING`          | `PONG`                                                             |
| `SKIP`          | Nothing                                                            |
| `TELL`          | Learns spam or ham, with `--allow-tell`; saves to `--out`          |

Compressed requests (`Compress: zlib`) are refused.
