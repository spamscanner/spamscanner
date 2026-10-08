<!-- source: a59bc5927d86 -->

# 命令行

```text
spamscanner <command> [options]
```

| 命令                                         | 作用                                     |
| ------------------------------------------ | -------------------------------------- |
| `scan [file\|-]`                           | 扫描来自文件或标准输入的邮件                         |
| `filter -f <sender> -- <recipients...>`    | Postfix 内容过滤器：扫描标准输入，添加邮件头，再传递下去       |
| `milter`                                   | 用于 Postfix 和 Sendmail 的 milter，端口 7831 |
| `http`                                     | HTTP API，端口 7832                       |
| `server`                                   | 普通 TCP 服务器，端口 7830                     |
| `spamd`                                    | 兼容 SpamAssassin 的 spamd 服务器，端口 783     |
| `train`                                    | 用 mbox 文件、Maildir、文件夹或数据集训练模型          |
| `eval`                                     | 在已标注的邮件上测量模型                           |
| `learn spam\|ham [file\|-] --model <file>` | 用一封邮件训练模型                              |
| `llm-test`                                 | 用三封示例邮件检查语言模型设置                        |
| `models`                                   | 列出推荐的开放模型                              |
| `version`、`help`                           |                                        |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| 选项                         | 含义                               |
| -------------------------- | -------------------------------- |
| `--json`                   | 以 JSON 格式输出完整结果                  |
| `--headers`                | 输出添加了 `X-Spam-*` 邮件头的邮件          |
| `--subject-tag <tag>`      | 同时为垃圾邮件的主题添加前缀                   |
| `--verbose`                | 显示每一项测试，以及分类器最强的线索               |
| `--threshold <n>`          | 邮件判为垃圾邮件的分数（默认 5）                |
| `--reject-threshold <n>`   | 邮件被拒收的分数（默认 15）                  |
| `--model <file>`           | 用模型文件代替内置模型                      |
| `--no-classifier`          | 不使用分类器                           |
| `--config <file>`          | 包含[库选项](api.md#options)的 JSON 文件 |
| `--allow-language <codes>` | 接受的语言，例如 `en,de,fr`              |

退出码：0 为正常邮件，1 为垃圾邮件，2 为出错。

### SMTP 会话

| 选项                  | 含义                      |
| ------------------- | ----------------------- |
| `--ip <address>`    | 发送该邮件的客户端的 IP 地址        |
| `--hostname <name>` | 客户端经过验证的反向 DNS 名称       |
| `--helo <name>`     | 客户端在 HELO 或 EHLO 中给出的名称 |
| `--from <address>`  | 信封发件人（MAIL FROM）        |
| `--to <address>`    | 信封收件人；多个收件人时重复使用        |

### 检查

| 选项                    | 含义                                  |
| --------------------- | ----------------------------------- |
| `--auth`              | 检查 SPF、DKIM、DMARC 和 ARC（需要 `--ip`）  |
| `--dnsbl <zone>`      | IP 黑名单，例如 `zen.spamhaus.org`；可重复使用  |
| `--uribl <zone>`      | 链接域名黑名单，例如 `dbl.spamhaus.org`；可重复使用 |
| `--dns-server <ip>`   | DNS 检查使用的域名服务器；可重复使用                |
| `--no-cloudflare`     | 不向 Cloudflare 的过滤解析器查询链接            |
| `--clamav [socket]`   | 用 clamd 扫描附件，使用其默认套接字或指定的套接字        |
| `--allowlist <value>` | 始终接收此 IP 地址、域名或地址；可重复使用             |
| `--denylist <value>`  | 始终拒收此 IP 地址、域名或地址；可重复使用             |

### 语言模型

| 选项                                                      | 含义                                                               |
| ------------------------------------------------------- | ---------------------------------------------------------------- |
| `--llm <provider>`                                      | `ollama`、`openai`、`anthropic`、`gemini` 等（[列表](llm.md#providers)） |
| `--llm-model <name>`                                    | 模型，例如 `qwen3.5:4b` 或 `claude-haiku-4-5`                          |
| `--llm-url <url>`                                       | 基础 URL，例如 `http://10.0.0.5:11434`                                |
| `--llm-host`、`--llm-port`、`--llm-path`、`--llm-protocol` | 修改服务商 URL 的某一部分                                                  |
| `--llm-api-key <key>`                                   | API 密钥；另见下文的环境变量                                                 |
| `--llm-auth <type>`                                     | `bearer`、`x-api-key`、`api-key`、`basic`、`header` 或 `none`         |
| `--llm-auth-header <name>`                              | 存放密钥的请求头，配合 `--llm-auth header` 使用                               |
| `--llm-username`、`--llm-password`                       | 用于 `--llm-auth basic`                                            |
| `--llm-header "Name: value"`                            | 额外的请求头；可重复使用                                                     |
| `--llm-mode <mode>`                                     | `auto`（仅限难以判断的邮件，默认）或 `always`                                   |
| `--llm-timeout <ms>`                                    | 默认 30000                                                         |
| `--llm-policy <text>`                                   | 给模型的额外规则，例如“我们从不发送账单”                                            |
| `--llm-redact`、`--no-llm-redact`                        | 先移除个人数据；对远程服务商默认开启                                               |


## filter

[Postfix 内容过滤器](postfix.md#content-filter)。它从标准输入读取邮件，添加 `X-Spam-*` 邮件头，并以相同的信封把邮件交给 sendmail。

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| 选项                    | 含义                      |
| --------------------- | ----------------------- |
| `--sendmail <path>`   | 默认 `/usr/sbin/sendmail` |
| `--subject-tag <tag>` | 为垃圾邮件的主题添加前缀            |
| `--reject`            | 达到拒收阈值的邮件会被退回，而不是传递下去   |
| `--discard`           | 达到拒收阈值的邮件会被丢弃，而不是传递下去   |

退出码遵循 Postfix 能读取的 sendmail 约定：0 表示已投递（或已丢弃），64 表示未提供收件人，69 表示作为垃圾邮件被拒收（Postfix 会退信），75 表示任何失败，此时 Postfix 会保留邮件并稍后重试。


## milter、http、server 和 spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

端口 783 是 SpamAssassin 客户端默认使用的端口。低于 1024 的端口需要 root 权限或 `CAP_NET_BIND_SERVICE` 能力；也可以使用其他端口，例如 `--port 7833`，并告知客户端。

| 选项                    | 含义                                                    |
| --------------------- | ----------------------------------------------------- |
| `--port <n>`          | TCP 端口                                                |
| `--host <ip>`         | 监听的地址（默认 127.0.0.1）                                   |
| `--socket <path>`     | 改为监听 Unix 套接字                                         |
| `--reject`            | Milter：拒收达到拒收阈值的邮件                                    |
| `--reject-code <n>`   | Milter：451，稍后重试（默认），或 550                             |
| `--quarantine`        | Milter：把垃圾邮件扣留在邮件服务器的隔离区中                             |
| `--name <hostname>`   | Milter：本服务器在 Authentication-Results 中的名称              |
| `--token <secret>`    | HTTP：要求 `Authorization: Bearer <secret>`；`/learn` 需要它 |
| `--allow-tell`        | spamd：接受用于学习的 TELL 请求（`spamc -L spam`）                |
| `--out <file>`        | HTTP 和 spamd：把学到的内容保存到此模型文件                           |
| `--subject-tag <tag>` | Milter 和 spamd：为垃圾邮件的主题添加前缀                           |
| `--verbose`           | Milter：记录每次扫描。TCP 服务器：以一行文本作答                         |

上面的扫描选项同样适用于服务器。[milter](postfix.md#milter)，[HTTP API、TCP 服务器和 spamd](http-api.md)。


## train、eval 和 learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| 选项                                             | 含义                                           |
| ---------------------------------------------- | -------------------------------------------- |
| `--spam <path>`                                | 垃圾邮件：mbox 文件、Maildir 或存放 `.eml` 文件的文件夹；可重复使用 |
| `--ham <path>`                                 | 正常邮件，同上；可重复使用                                |
| `--dataset <file>`                             | 带有文本列和标签列的 CSV 或 JSON Lines 文件；可重复使用         |
| `--text-column <name>`、`--label-column <name>` | 列名，在无法自动识别时使用                                |
| `--out <file>`                                 | 模型的写入位置（默认 `spamscanner-model.json`）         |
| `--merge`                                      | 从内置模型（或 `--model`）开始，而不是从空模型开始               |

`learn` 原地更新模型文件，第一次使用时会基于内置模型创建该文件。[训练](training.md)


## llm-test 和 models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` 向模型发送一封普通邮件和两封诈骗邮件，使用英语和意大利语，输出模型的判定，只有三者全部正确时才以 0 退出。


## 配置文件

`--config file.json`（或 `SPAMSCANNER_CONFIG` 环境变量）加载[库选项](api.md#options)。命令行选项会覆盖文件中的设置。

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


## 环境变量

| 变量                                                                                                                                                                                                                                       | 含义                   |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                     | 配置文件                 |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                      | 代替内置模型使用的模型文件        |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                      | HTTP API 的令牌         |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                | 适用于任何语言模型服务商的 API 密钥 |
| `OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`GEMINI_API_KEY`、`MISTRAL_API_KEY`、`GROQ_API_KEY`、`OPENROUTER_API_KEY`、`DEEPSEEK_API_KEY`、`XAI_API_KEY`、`TOGETHER_API_KEY`、`FIREWORKS_API_KEY`、`CEREBRAS_API_KEY`、`HF_TOKEN`、`AZURE_OPENAI_API_KEY` | 各服务商自己的密钥            |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                | 调试日志                 |
