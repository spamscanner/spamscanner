<!-- source: faf44f093f8b -->

# HTTP API、TCP 服务器和 spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

它默认监听 127.0.0.1，除非 `--host` 另行指定。设置令牌后，除 `/health` 以外的每个请求都需要 `Authorization: Bearer <token>`。在把它暴露到本机以外之前，请将其置于带 TLS 的反向代理之后。

| 方法和路径              | 请求体  | 响应                                         |
| ------------------ | ---- | ------------------------------------------ |
| `GET /health`      |      | `{"ok": true, "version": "7.0.0"}`         |
| `POST /scan`       | 原始邮件 | JSON 格式的[扫描结果](api.md#the-result)          |
| `POST /check`      | 原始邮件 | 添加了 `X-Spam-*` 邮件头的邮件，格式为 `message/rfc822` |
| `POST /learn/spam` | 原始邮件 | `{"ok": true, "learned": "spam"}`；需要令牌     |
| `POST /learn/ham`  | 原始邮件 | `{"ok": true, "learned": "ham"}`；需要令牌      |

查询参数描述 SMTP 会话：

| 参数           | 含义                                    |
| ------------ | ------------------------------------- |
| `ip`         | 客户端的 IP 地址                            |
| `hostname`   | 其经过验证的反向 DNS 名称                       |
| `helo`       | 其 HELO 或 EHLO 名称                      |
| `from`       | 信封发件人                                 |
| `to`         | 一个收件人；可重复该参数，或用逗号分隔多个收件人              |
| `verbose=1`  | `/scan`：同时返回词语列表和主题                   |
| `subjectTag` | `/check`：为垃圾邮件的主题添加前缀，例如 `%5BSPAM%5D` |

`/check` 还会把 `X-Spam-Flag`、`X-Spam-Score` 和 `X-Spam-Action` 作为响应头返回，因此客户端无需解析邮件即可作出决定。

大于 25 MB 的邮件会得到 `413`。扫描失败会得到 `500` 和 `{"error": "..."}`。

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

使用 `--out model.json` 时，`/learn` 学到的内容会在每次请求后保存到该文件。不使用时，学到的内容只保留到服务器重启。

在 Node.js 中：

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

在 Python 中：

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


## TCP 服务器

```sh
spamscanner server --port 7830
```

发送原始邮件，关闭连接的发送端，然后读取一行 JSON：

```sh
nc -N 127.0.0.1 7830 < message.eml
```

使用 `--verbose` 时，响应改为一行文本：`SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` 或 `HAM -2.5/5.0 BAYES_00`。


## spamd

```sh
spamscanner spamd --port 783
```

兼容 SpamAssassin 的服务器，供 spamc、Exim、Haraka 和其他 SpamAssassin 客户端使用。[配置 Exim 和 Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| 命令              | 响应                                        |
| --------------- | ----------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                 |
| `SYMBOLS`       | 判定结果和触发的测试名称                              |
| `REPORT`        | 判定结果和一张列出测试、分值和原因的表                       |
| `REPORT_IFSPAM` | 与 `REPORT` 相同，但对正常邮件返回空报告                 |
| `PROCESS`       | 判定结果和带有 `X-Spam-*` 邮件头的邮件                 |
| `HEADERS`       | 判定结果和带有 `X-Spam-*` 邮件头的邮件头部分              |
| `PING`          | `PONG`                                    |
| `SKIP`          | 无                                         |
| `TELL`          | 学习垃圾邮件或正常邮件，需要 `--allow-tell`；保存到 `--out` |

压缩请求（`Compress: zlib`）会被拒绝。
