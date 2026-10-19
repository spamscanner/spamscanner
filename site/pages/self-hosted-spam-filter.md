<!--
label: Self-hosted spam filter
title: Self-hosted spam filter for your own mail server
description: Run a spam filter on your own server. Spam Scanner keeps mail on the machine, ships its model in the package, sends no telemetry and plugs into Postfix or Exim.
keywords: self-hosted spam filter, on-premises spam filter, private spam filter, local spam filter, spam filter for mail server, spam filter without cloud
-->

# Self-hosted spam filter

Spam Scanner runs on your own server and keeps the mail there. The classifier model ships inside the package, there is no telemetry or update check, and by default the only thing it sends is a DNS lookup for the host name of each link.


## What leaves the server

By default, only the host names of links in a message. They are looked up on Cloudflare's filtering resolvers (1.1.1.2 and 1.1.1.3) as ordinary DNS queries, and no part of the message or its addresses is sent. `--no-cloudflare` turns this off.

Every other check that uses the network is off until you turn it on:

| Check                 | Turn it on with      | What it sends                                            |
| --------------------- | -------------------- | -------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | DNS queries for the sender's records                     |
| DNS blocklists        | `--dnsbl`, `--uribl` | The client's IP address and link domains, as DNS queries |
| ClamAV                | `--clamav`           | Attachments, to your own clamd                           |
| A language model      | `--llm`              | A summary of the message, to the server you name         |

Scans are not logged or stored. [Security and privacy](../../docs/security.md)


## Install on a server

```sh
npm install --global spamscanner
```

Or the standalone binary, with Node.js and the model built in:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

The install script checks the binary against the release's `SHA256SUMS` file before installing it, and each binary has a signed build provenance attestation that `gh attestation verify` checks. Binaries cover Linux (x64 and arm64), macOS and Windows. The Linux binaries need glibc, so on Alpine install with npm. [Getting started](../../docs/getting-started.md)

There is no update check. To update, run the install command again: both commands install the latest release.


## Run it as a service

The milter, HTTP, TCP and spamd servers listen on 127.0.0.1 unless `--host` says otherwise. Run them as an unprivileged user, for example under systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

The [full unit and its setup](../../docs/postfix.md#1-run-the-milter) are in the Postfix guide. None of the servers speak TLS, so to reach one from another machine, use a private network, an SSH tunnel or a reverse proxy with TLS.


## Connect your mail server

| Mail server                      | Command                                 | Port |
| -------------------------------- | --------------------------------------- | ---- |
| Postfix or Sendmail              | `spamscanner milter`                    | 7831 |
| Postfix, never refusing mail     | `spamscanner filter`, a content filter  | none |
| Exim, Haraka or spamc            | `spamscanner spamd`                     | 783  |
| Anything that speaks HTTP        | `spamscanner http`                      | 7832 |
| A plain TCP client               | `spamscanner server`                    | 7830 |
| A mail server written in Node.js | `import SpamScanner from 'spamscanner'` | none |

The servers can add `X-Spam-Flag`, `X-Spam-Score` and `X-Spam-Status` headers to the message, and the library returns the score and every test that fired. Guides: [Postfix spam filter](/postfix-spam-filter/), [other mail servers](../../docs/mail-servers.md) and [the HTTP API](../../docs/http-api.md).


## Keep language models local

A language model is optional and only reads close calls: clear spam and clear ham never reach it. With Ollama it runs on the same server, so no message leaves it:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` runs on a CPU. With a hosted provider instead, personal data is removed from a message before it is sent. [Language models](../../docs/llm.md)


## Train it on your own mail

The bundled model is trained on public datasets. A model trained on the mail your server receives does better, and it stays on that server:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

A model file holds hashed feature counts, not words or message text. [Training](../../docs/training.md)


## Requirements

Node.js 18 or later on Linux, macOS or Windows, or nothing at all with a standalone binary. ClamAV and Ollama are optional and run as their own services.
