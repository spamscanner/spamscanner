<!-- source: 1151282f29d3 -->

# 其他邮件服务器

Spam Scanner 支持四种协议，因此大多数邮件软件无需专用插件即可使用它：

| 协议     | 命令                                      | 使用者                                          |
| ------ | --------------------------------------- | -------------------------------------------- |
| Milter | `spamscanner milter`                    | Postfix、Sendmail、OpenSMTPD（配合 filter-milter） |
| spamd  | `spamscanner spamd`                     | spamc、Exim、Haraka，以及任何为 SpamAssassin 编写的软件   |
| HTTP   | `spamscanner http`                      | 脚本、webhook、自定义 MTA 和服务                       |
| 管道     | `spamscanner scan`、`spamscanner filter` | Postfix 管道、procmail、maildrop、cron 任务         |

[Postfix 和 Sendmail](postfix.md) 有单独的页面。


## SpamAssassin spamd 的直接替代品

`spamscanner spamd` 响应 SpamAssassin 的 spamd 协议：`CHECK`、`SYMBOLS`、`REPORT`、`REPORT_IFSPAM`、`PROCESS`、`HEADERS`、`PING`，以及在使用 `--allow-tell` 时的 `TELL`。为 SpamAssassin 编写的软件无需改动即可使用；停止 `spamd`，在同一端口启动 Spam Scanner 即可。

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

配合 spamc：

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

仓库的端到端测试会用 SpamAssassin 自己的 spamc 对它进行测试。


## Exim

Exim 的 `spam` ACL 条件与 spamd 通信。在主配置中：

```text
spamd_address = 127.0.0.1 783
```

在 DATA ACL 中（Debian 的 exim4 中为 `acl_check_data`）：

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` 以临时性的 4xx 错误作答，因此发件方会重试，判定有误时可以纠正。确认结果无误后，把它改为 `deny` 即可永久拒收。


## Haraka

Haraka 的 `spamassassin` 插件与 spamd 通信。在 `config/plugins` 中启用它，并在 `config/spamassassin.ini` 中设置：

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot：Junk 文件夹与学习

一条 Sieve 规则把已标记的邮件归入 Junk：

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

借助 IMAPSieve，把邮件移入或移出 Junk 可以训练模型。用令牌和模型文件启动 HTTP API：

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

并用 `--model /var/lib/spamscanner/model.json`（或 `SPAMSCANNER_MODEL`）让 milter 或 spamd 服务器使用同一个模型。不时重启它，以载入学到的内容。由 `sieve_pipe` 运行的脚本负责提交邮件：

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Dovecot 的[垃圾邮件报告指南](https://doc.dovecot.org/main/core/config/spam_reporting.html)介绍了其余的配置，对于任何通过脚本学习的垃圾邮件过滤器都是一样的。


## procmail 和 maildrop

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

`scan --headers` 对垃圾邮件以 1 退出。按上面的规则，procmail 和 maildrop 使用的是输出，而不是退出码。


## HTTP API

任何能发出 HTTP 请求的程序都能扫描邮件：

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API](http-api.md) 列出了所有端点。


## 在 Node.js 邮件服务器内部

配合 [smtp-server](https://nodemailer.com/extras/smtp-server/)、Haraka 插件或任何其他 Node.js 服务器，直接调用库：

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

smtp-server 的 `session.envelope` 已经具有 Spam Scanner 读取的 `mailFrom` 和 `rcptTo` 结构。
