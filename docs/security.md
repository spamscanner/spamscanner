# Security and privacy

Spam Scanner reads mail, which is private, from senders, who may be hostile. This page lists what it sends anywhere, and how it treats what it reads.


## What leaves the machine

By default, one thing: the **host names of links** in a message are looked up on Cloudflare's filtering resolvers, 1.1.1.2 and 1.0.0.2 (malware and phishing) and 1.1.1.3 and 1.0.0.3 (also adult content). These are ordinary DNS queries for names such as `example.com`; no part of the message or its addresses is sent. Turn them off with `phishing: {cloudflare: false}` or `--no-cloudflare`, or the adult check alone with `phishing: {adult: false}`.

Everything else is off until configured:

| Check               | Sends                                                                                                                   | To                                                                   |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `authentication`    | DNS queries for the sender's SPF, DKIM, DMARC and ARC records                                                           | Your resolver, or `dnsServers`                                       |
| `dnsbl`             | The client's IP address, reversed, and link domains, as DNS queries                                                     | The blocklists' name servers, through your resolver or `dns.servers` |
| `llm`               | A summary of the message, with personal data removed for remote providers                                               | The language model server you name ([privacy](llm.md#privacy))       |
| `reputation.apiUrl` | The client's IP address and verified hostname, and the From, envelope sender and Reply-To addresses, with their domains | The service you name                                                 |
| `clamav`            | Attachments                                                                                                             | Your clamd, over its socket                                          |

There is no telemetry, no update check and no download at run time. The model ships inside the package.


## What it keeps

Nothing, unless asked. Scans are not logged or stored. `learn()` changes the classifier in memory; it is written to disk only by `saveModel()`, `spamscanner learn`, or the servers' `--out` option. A model file holds hashed feature counts, not words or message text.

Language model answers are cached in memory, keyed by a hash of what was sent, so repeated copies of the same message are asked about once. DNS answers are cached in memory for ten minutes, and a reputation service's answers for five (`reputation.cacheTtl`; a failed request for one minute).


## Hostile input

* Attachments are identified by their bytes, never executed or opened by another program. ZIP archives are read from their central directory, with limits on the number of entries (2000) and on the bytes of their names (1 MiB; a name over 1 KiB keeps its first and last 512 bytes, and findings show at most 100 characters of one), each entry read once however many directories point at it; nothing is decompressed, so programs inside nested or compressed archives are not seen. Attached messages (`message/rfc822`, or attachments whose file name ends in `.eml`) are opened up to three levels deep, for at most 100 of their attachments and 25 MB of attached messages in all; the message's own attachments are always all inspected. A message beyond the MIME parser's limits (more than 1000 parts, or a part's header over 1 MB) is read as far as the parser allows (its first parts, with an oversized header cut down so its sender still counts) and gets `MIME_TOO_COMPLEX`, which no credit offsets; ClamAV reads it whole. An attached message the parser fails on gets it too, and never fails the scan. Address fields are read up to 16 KB each (2000 addresses, 16 nested groups) and 64 KB in all for each message, cut only at the end of a whole address, as the address parser takes time that grows with the square of the number of addresses; mailauth reads From and Return-Path so bounded too (the other fields as they are, so a signature over them holds), and a header it would take longer than linear time to read (thousands of folded lines, or signatures naming thousands of fields) cut down. A From field cut fails DMARC and allowlists nothing. HTML is read by Spam Scanner's own parser, in linear time, however deeply it is nested.
* Body text is read up to `maxLength` (100,000 characters) and the servers accept messages up to 25 MB. Links are read up to `phishing.maxLength` (1,000,000 characters).
* Every network check has a timeout (`timeout`, 10 seconds by default). A check that fails or times out is skipped and the scan finishes without it. Authentication and the image model (the first 10 images) each finish within it as a whole: authentication sends no DNS query after it, nor more than 300 for one message (room for SPF at the limits of RFC 7208, with DKIM, ARC, DMARC and BIMI), and checks only the first 8 DKIM signatures of a message (mailauth itself reads at most 50 ARC sets). The `Authentication-Results` header the milter adds holds at most 8 KiB of results. ClamAV (four attachments at a time) has its own limit for all of a message's attachments (`clamav.timeout`, 60 seconds), and attachments it could not scan are listed in `results.virusScanErrors`. The language model has its own (`llm.timeout`).
* The allowlist trusts only what a sender cannot forge: the client's address and verified hostname, and sender domains that authentication confirms. [Allowlist and denylist](api.md#allowlist-and-denylist)
* `X-Spam-*` headers already in a message are removed by the milter, the content filter and `--headers`, so senders cannot mark their own mail as clean.
* Microsoft's spam verdict headers are trusted only when the message came directly from Microsoft's servers, and Received headers are never used to decide where a message came from.
* Text that addresses AI filters is scored as spam, and the language model is told that the message is data, not instructions. [Prompt injection](llm.md#prompt-injection)


## Servers

The milter, HTTP, TCP and spamd servers listen on 127.0.0.1 unless `--host` says otherwise. The HTTP API compares its token in constant time and refuses `/learn` without one. None of them speak TLS: to reach them across a network, use a private network, an SSH tunnel or a reverse proxy with TLS.

Run them as an unprivileged user. The [systemd unit in the Postfix guide](postfix.md#1-run-the-milter) adds the usual hardening.


## Reporting a vulnerability

Report security issues privately through [GitHub's vulnerability reporting](https://github.com/spamscanner/spamscanner/security/advisories/new), not in public issues.
