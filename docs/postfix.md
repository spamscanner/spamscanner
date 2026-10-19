# Postfix and Sendmail

Spam Scanner connects to Postfix in two ways:

* **As a milter** (recommended). Postfix asks it about each message during the SMTP session, before accepting it. Spam can be refused with a 4xx or 5xx reply, so the sending server, not yours, deals with it. Sendmail uses the same protocol.
* **As a content filter.** Postfix accepts the message, pipes it to `spamscanner filter`, which adds headers and hands it back with sendmail. Nothing is ever refused during the SMTP session.

Both add these headers to every message:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.3
X-Spam-Action: tag
```

`X-Spam-*` headers already in the message are removed first, so a sender cannot mark its own mail as clean.

A message with an attachment ClamAV could not scan may hold a virus, so both defer it (Postfix or the sender tries again later), as they do when a scan fails. With `--on-error accept` it is passed on with `X-Spam-Virus-Scan: failed` added.


## Milter

### 1. Run the milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

With `--reject`, messages at the reject threshold (15 points) are refused with `451 4.7.1 Message rejected as spam`. A 451 is temporary: the sender tries again later and a mistake can still be corrected by changing a setting. Use `--reject-code 550` for a permanent refusal once the results look right. With `--quarantine`, spam goes to Postfix's hold queue instead. A message the milter could not fully scan gets a 4xx reply; `--on-error accept` lets it through instead.

As a systemd service, in `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Point Postfix at it

In `/etc/postfix/main.cf`:

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

`smtpd_milters` covers mail arriving over SMTP. Leave `non_smtpd_milters` empty unless mail submitted with the `sendmail` command should be scanned too.

### 3. Test it

[swaks](https://www.jetmore.org/john/code/swaks/) sends test messages. GTUBE is a test string every spam filter treats as spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Without `--reject` the message is delivered with `X-Spam-Flag: YES` and a tagged subject. With `--reject`, swaks shows the 451 or 550 reply.


## Content filter

Use this when mail must never be refused during the SMTP session, or for a server that cannot use milters.

In `/etc/postfix/master.cf`, add a filter service and use it on the SMTP listener:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] --from=${sender} -- ${recipient}
```

Postfix runs the filter with an almost empty environment, so `argv` names Node.js and the script by their full paths (`command -v node` and `npm root --global` show them). Then:

```sh
sudo postfix reload
```

The filter passes the message back with `sendmail -G -i`. Mail submitted this way does not pass through the `smtp` listener again, so it is not filtered twice.

Exit codes tell Postfix what happened: 0 delivered, 69 refused (with `--reject`: Postfix bounces it to the sender), 75 temporary failure (Postfix keeps the message and tries again). Any scan or delivery failure is 75, and so is a message with an attachment ClamAV could not scan, so a broken setting never loses or bounces mail. With `--on-error accept`, a message whose scan failed, or that ClamAV could not fully scan, is passed on instead, marked `X-Spam-Virus-Scan: failed` (see [the CLI](cli.md#filter)).


## Sendmail

In `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` makes Sendmail answer with a temporary failure while the milter is unavailable; drop it to accept mail unfiltered instead. Rebuild `sendmail.cf` and restart Sendmail.

The client's hostname can put a message on the allowlist only when it is verified. Postfix sends it only when the client's reverse DNS name resolves back to its address, and `unknown` otherwise. Sendmail sends the reverse DNS name even when it does not resolve back (a name anyone with reverse DNS for their own address can choose), and says so in its `{client_resolve}` macro, which it does not send by default. Add it to the macros sent on connect, before `INPUT_MAIL_FILTER`, so that only a hostname it gives as `OK` counts:

```text
define(`confMILTER_MACROS_CONNECT', `j, _, {daemon_name}, {if_name}, {if_addr}, {client_resolve}')
```


## Sorting spam into a Junk folder

Tagging alone delivers spam to the inbox. With Dovecot, a Sieve rule moves it:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Other mail servers](mail-servers.md) covers Dovecot, Exim, Haraka and procmail, and [training](training.md#learning-from-reports) shows how to learn from mail that users move in and out of Junk.


## Tested

The repository's end-to-end tests run a real Postfix: ham is delivered with headers, a forged `X-Spam-Flag` is removed, spam is tagged, GTUBE is refused with a 550 during the SMTP session, and the content filter tags mail on a second port. `scripts/e2e-postfix.sh` sets up that Postfix and `test/e2e/postfix.test.js` sends the mail.
