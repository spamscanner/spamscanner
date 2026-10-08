# Command line

```text
spamscanner <command> [options]
```

| Command                                    | What it does                                                         |
| ------------------------------------------ | -------------------------------------------------------------------- |
| `scan [file\|-]`                           | Scan a message from a file or standard input                         |
| `filter -f <sender> -- <recipients...>`    | Postfix content filter: scan standard input, add headers, pass it on |
| `milter`                                   | Milter for Postfix and Sendmail, port 7831                           |
| `http`                                     | HTTP API, port 7832                                                  |
| `server`                                   | Plain TCP server, port 7830                                          |
| `spamd`                                    | SpamAssassin-compatible spamd server, port 783                       |
| `train`                                    | Train a model from mbox files, Maildirs, folders or datasets         |
| `eval`                                     | Measure a model on labelled mail                                     |
| `learn spam\|ham [file\|-] --model <file>` | Teach a model one message                                            |
| `llm-test`                                 | Check language model settings with three sample messages             |
| `models`                                   | List recommended open models                                         |
| `version`, `help`                          |                                                                      |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Option                     | Meaning                                               |
| -------------------------- | ----------------------------------------------------- |
| `--json`                   | Print the full result as JSON                         |
| `--headers`                | Print the message with `X-Spam-*` headers added       |
| `--subject-tag <tag>`      | Also prefix the subject of spam                       |
| `--verbose`                | Show every test, and the classifier's strongest clues |
| `--threshold <n>`          | Score at which mail is spam (default 5)               |
| `--reject-threshold <n>`   | Score at which mail is rejected (default 15)          |
| `--model <file>`           | A model file instead of the bundled one               |
| `--no-classifier`          | Do not use the classifier                             |
| `--config <file>`          | A JSON file with [library options](api.md#options)    |
| `--allow-language <codes>` | Accepted languages, for example `en,de,fr`            |

Exit codes: 0 ham, 1 spam, 2 error.

### SMTP session

| Option              | Meaning                                        |
| ------------------- | ---------------------------------------------- |
| `--ip <address>`    | IP address of the client that sent the message |
| `--hostname <name>` | The client's verified reverse DNS name         |
| `--helo <name>`     | The name it gave in HELO or EHLO               |
| `--from <address>`  | Envelope sender (MAIL FROM)                    |
| `--to <address>`    | Envelope recipient; repeat for several         |

### Checks

| Option                | Meaning                                                                |
| --------------------- | ---------------------------------------------------------------------- |
| `--auth`              | Check SPF, DKIM, DMARC and ARC (needs `--ip`)                          |
| `--dnsbl <zone>`      | IP blocklist, for example `zen.spamhaus.org`; repeatable               |
| `--uribl <zone>`      | Domain blocklist for links, for example `dbl.spamhaus.org`; repeatable |
| `--dns-server <ip>`   | Name server for DNS checks; repeatable                                 |
| `--no-cloudflare`     | Do not ask Cloudflare's filtering resolvers about links                |
| `--clamav [socket]`   | Scan attachments with clamd, at its default socket or the one given    |
| `--allowlist <value>` | Always accept this IP address, domain or address; repeatable           |
| `--denylist <value>`  | Always reject this IP address, domain or address; repeatable           |

### Language model

| Option                                                     | Meaning                                                                                                                                        |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` and others ([list](llm.md#providers))                                                     |
| `--llm-model <name>`                                       | Model, for example `qwen3.5:4b` or `claude-haiku-4-5`                                                                                          |
| `--llm-method <method>`                                    | `decision` (a probability for each verdict, in one step; the default where available) or `generate` ([methods](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | Cloudflare account ID, for `clef` and `clef-flash`                                                                                             |
| `--llm-url <url>`                                          | Base URL, for example `http://10.0.0.5:11434`                                                                                                  |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Change one part of the provider's URL                                                                                                          |
| `--llm-api-key <key>`                                      | API key; see also the environment variables below                                                                                              |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` or `none`                                                                                  |
| `--llm-auth-header <name>`                                 | Header for the key, with `--llm-auth header`                                                                                                   |
| `--llm-username`, `--llm-password`                         | For `--llm-auth basic`                                                                                                                         |
| `--llm-header "Name: value"`                               | Extra request header; repeatable                                                                                                               |
| `--llm-mode <mode>`                                        | `auto` (close calls only, the default) or `always`                                                                                             |
| `--llm-timeout <ms>`                                       | Default 30000                                                                                                                                  |
| `--llm-policy <text>`                                      | Extra rules for the model, for example "We never send invoices"                                                                                |
| `--llm-redact`, `--no-llm-redact`                          | Remove personal data first; on by default for remote providers                                                                                 |


## filter

A [Postfix content filter](postfix.md#content-filter). It reads a message from standard input, adds `X-Spam-*` headers and passes it to sendmail with the same envelope.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Option                | Meaning                                                      |
| --------------------- | ------------------------------------------------------------ |
| `--sendmail <path>`   | Default `/usr/sbin/sendmail`                                 |
| `--subject-tag <tag>` | Prefix the subject of spam                                   |
| `--reject`            | Bounce mail at the reject threshold instead of passing it on |
| `--discard`           | Drop mail at the reject threshold instead of passing it on   |

Exit codes follow sendmail's conventions, which Postfix reads: 0 delivered (or discarded), 64 no recipients given, 69 rejected as spam (Postfix bounces it), 75 any failure, so Postfix keeps the message and tries again later.


## milter, http, server and spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Port 783 is the port SpamAssassin clients use by default. Ports below 1024 need root or the `CAP_NET_BIND_SERVICE` capability; use another port, such as `--port 7833`, and tell the client.

| Option                | Meaning                                                             |
| --------------------- | ------------------------------------------------------------------- |
| `--port <n>`          | TCP port                                                            |
| `--host <ip>`         | Address to listen on (default 127.0.0.1)                            |
| `--socket <path>`     | Listen on a Unix socket instead                                     |
| `--reject`            | Milter: refuse mail at the reject threshold                         |
| `--reject-code <n>`   | Milter: 451, try again later (the default), or 550                  |
| `--quarantine`        | Milter: hold spam in the mail server's quarantine                   |
| `--name <hostname>`   | Milter: this server's name in Authentication-Results                |
| `--token <secret>`    | HTTP: require `Authorization: Bearer <secret>`; needed for `/learn` |
| `--allow-tell`        | spamd: accept TELL requests (`spamc -L spam`) to learn              |
| `--out <file>`        | HTTP and spamd: save what is learned to this model file             |
| `--subject-tag <tag>` | Milter and spamd: prefix the subject of spam                        |
| `--verbose`           | Milter: log every scan. TCP server: answer with one text line       |

The scan options above apply to the servers too. [The milter](postfix.md#milter), [the HTTP API, the TCP server and spamd](http-api.md).


## train, eval and learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Option                                          | Meaning                                                               |
| ----------------------------------------------- | --------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: an mbox file, a Maildir or a folder of `.eml` files; repeatable |
| `--ham <path>`                                  | Ham, likewise; repeatable                                             |
| `--dataset <file>`                              | A CSV or JSON Lines file with text and label columns; repeatable      |
| `--text-column <name>`, `--label-column <name>` | Column names, when they are not detected                              |
| `--out <file>`                                  | Where to write the model (default `spamscanner-model.json`)           |
| `--merge`                                       | Start from the bundled model (or `--model`) instead of an empty one   |

`learn` updates the model file in place, creating it from the bundled model the first time. [Training](training.md)


## llm-test and models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` sends one ordinary message and two scams, in English and Italian, to the model, prints its verdicts, the time each took, the method used and the hardware, and exits 0 only if all three are right.


## Configuration file

`--config file.json` (or the `SPAMSCANNER_CONFIG` environment variable) loads [library options](api.md#options). Command-line options override the file.

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


## Environment variables

| Variable                                                                                                                                                                                                                                                                                                                     | Meaning                                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                         | Configuration file                         |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                          | Model file used instead of the bundled one |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                          | Token for the HTTP API                     |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                    | API key for any language model provider    |
| `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Each provider's own key                    |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                    | Debug logging                              |
