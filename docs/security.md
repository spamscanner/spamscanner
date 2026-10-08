# Security and privacy

Spam Scanner reads mail, which is private, from senders, who may be hostile. This page lists what it sends anywhere, and how it treats what it reads.


## What leaves the machine

By default, one thing: the **host names of links** in a message are looked up on Cloudflare's filtering resolvers, 1.1.1.2 and 1.0.0.2 (malware and phishing) and 1.1.1.3 and 1.0.0.3 (also adult content). These are ordinary DNS queries for names such as `example.com`; no part of the message or its addresses is sent. Turn them off with `phishing: {cloudflare: false}` or `--no-cloudflare`, or the adult check alone with `phishing: {adult: false}`.

Everything else is off until configured:

| Check               | Sends                                                                     | To                                                                   |
| ------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `authentication`    | DNS queries for the sender's SPF, DKIM, DMARC and ARC records             | Your resolver, or `dnsServers`                                       |
| `dnsbl`             | The client's IP address, reversed, and link domains, as DNS queries       | The blocklists' name servers, through your resolver or `dns.servers` |
| `llm`               | A summary of the message, with personal data removed for remote providers | The language model server you name ([privacy](llm.md#privacy))       |
| `reputation.apiUrl` | The sender's IP address, domain and address                               | The service you name                                                 |
| `clamav`            | Attachments                                                               | Your clamd, over its socket                                          |

There is no telemetry, no update check and no download at run time. The model ships inside the package.


## What it keeps

Nothing, unless asked. Scans are not logged or stored. `learn()` changes the classifier in memory; it is written to disk only by `saveModel()`, `spamscanner learn`, or the servers' `--out` option. A model file holds hashed feature counts, not words or message text.

Language model answers are cached in memory, keyed by a hash of what was sent, so repeated copies of the same message are asked about once. DNS answers are cached in memory for ten minutes.


## Hostile input

* Attachments are identified by their bytes, never executed or opened by another program. ZIP archives are read from their central directory, with a limit on the number of entries; nested archives are not unpacked.
* Body text is read up to `maxLength` (100,000 characters) and the servers accept messages up to 25 MB.
* Every network check has a timeout (`timeout`, 10 seconds by default). A check that fails or times out is skipped and the scan finishes without it.
* `X-Spam-*` headers already in a message are removed by the milter, the content filter and `--headers`, so senders cannot mark their own mail as clean.
* Microsoft's spam verdict headers are trusted only when the message came directly from Microsoft's servers, and Received headers are never used to decide where a message came from.
* Text that addresses AI filters is scored as spam, and the language model is told that the message is data, not instructions. [Prompt injection](llm.md#prompt-injection)


## Servers

The milter, HTTP, TCP and spamd servers listen on 127.0.0.1 unless `--host` says otherwise. The HTTP API compares its token in constant time and refuses `/learn` without one. None of them speak TLS: to reach them across a network, use a private network, an SSH tunnel or a reverse proxy with TLS.

Run them as an unprivileged user. The [systemd unit in the Postfix guide](postfix.md#1-run-the-milter) adds the usual hardening.


## Reporting a vulnerability

Report security issues privately through [GitHub's vulnerability reporting](https://github.com/spamscanner/spamscanner/security/advisories/new), not in public issues.
