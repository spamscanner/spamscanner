<!-- source: f1043eb5fc58 -->

# Postfix 和 Sendmail

Spam Scanner 有两种方式接入 Postfix：

* **作为 milter**（推荐）。Postfix 在 SMTP 会话期间、接收邮件之前就每封邮件询问它。垃圾邮件可以用 4xx 或 5xx 回复拒收，因此由发送方服务器而不是你的服务器来处理。Sendmail 使用相同的协议。
* **作为内容过滤器**。Postfix 接收邮件后，把它通过管道交给 `spamscanner filter`，后者添加邮件头，再用 sendmail 交回。在 SMTP 会话期间从不拒收任何邮件。

两种方式都会给每封邮件添加以下邮件头：

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

邮件中已有的 `X-Spam-*` 邮件头会先被移除，因此发件人无法把自己的邮件标记为干净。


## Milter

### 1. 运行 milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

使用 `--reject` 时，达到拒收阈值（15 分）的邮件会以 `451 4.7.1 Message rejected as spam` 被拒收。451 是临时性错误：发件方稍后会重试，判定有误时仍可通过修改设置来纠正。确认结果无误后，使用 `--reject-code 550` 改为永久拒收。使用 `--quarantine` 时，垃圾邮件会改为进入 Postfix 的暂留队列（hold queue）。

作为 systemd 服务，写入 `/etc/systemd/system/spamscanner-milter.service`：

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

### 2. 让 Postfix 指向它

在 `/etc/postfix/main.cf` 中：

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

`smtpd_milters` 涵盖通过 SMTP 到达的邮件。除非用 `sendmail` 命令提交的邮件也需要扫描，否则请让 `non_smtpd_milters` 保持为空。

### 3. 测试

[swaks](https://www.jetmore.org/john/code/swaks/) 用于发送测试邮件。GTUBE 是所有垃圾邮件过滤器都视为垃圾邮件的测试字符串：

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

不使用 `--reject` 时，邮件会带着 `X-Spam-Flag: YES` 和已标记的主题投递。使用 `--reject` 时，swaks 会显示 451 或 550 回复。


## 内容过滤器

当邮件绝不能在 SMTP 会话期间被拒收时，或者对于无法使用 milter 的服务器，请使用这种方式。

在 `/etc/postfix/master.cf` 中添加一个过滤服务，并在 SMTP 监听器上使用它：

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix 在几乎为空的环境中运行过滤器，因此 `argv` 要用完整路径指定 Node.js 和脚本（`command -v node` 和 `npm root --global` 会显示这些路径）。然后：

```sh
sudo postfix reload
```

过滤器用 `sendmail -G -i` 把邮件交回。以这种方式提交的邮件不会再次经过 `smtp` 监听器，因此不会被过滤两次。

退出码告诉 Postfix 发生了什么：0 表示已投递，69 表示拒收（使用 `--reject` 时，Postfix 会把邮件退回给发件人），75 表示临时性失败（Postfix 保留邮件并重试）。任何扫描或投递失败都返回 75，因此错误的设置永远不会导致邮件丢失或被退回。


## Sendmail

在 `sendmail.mc` 中：

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` 让 Sendmail 在 milter 不可用时以临时性失败作答；去掉它则改为不经过滤直接接收邮件。重新生成 `sendmail.cf` 并重启 Sendmail。


## 把垃圾邮件归入 Junk 文件夹

仅做标记时，垃圾邮件仍会投递到收件箱。配合 Dovecot，一条 Sieve 规则即可移动它：

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[其他邮件服务器](mail-servers.md)介绍了 Dovecot、Exim、Haraka 和 procmail，[训练](training.md#learning-from-reports)介绍了如何从用户移入和移出 Junk 的邮件中学习。


## 测试情况

仓库的端到端测试会运行真实的 Postfix：正常邮件带着邮件头投递，伪造的 `X-Spam-Flag` 被移除，垃圾邮件被标记，GTUBE 在 SMTP 会话期间以 550 被拒收，内容过滤器在第二个端口上标记邮件。`scripts/e2e-postfix.sh` 负责搭建该 Postfix，`test/e2e/postfix.test.js` 负责发送邮件。
