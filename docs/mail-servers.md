# Other mail servers

Spam Scanner speaks four protocols, so most mail software can use it without a plugin of its own:

| Protocol | Command                                  | Used by                                                    |
| -------- | ---------------------------------------- | ---------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (with filter-milter)          |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka, and anything written for SpamAssassin |
| HTTP     | `spamscanner http`                       | Scripts, webhooks, custom MTAs and services                |
| Pipe     | `spamscanner scan`, `spamscanner filter` | Postfix pipes, procmail, maildrop, cron jobs               |

[Postfix and Sendmail](postfix.md) have their own page.


## A drop-in for SpamAssassin's spamd

`spamscanner spamd` answers SpamAssassin's spamd protocol: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` and, with `--allow-tell`, `TELL`. Software written for SpamAssassin works unchanged; stop `spamd` and start Spam Scanner on the same port.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

With spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

The repository's end-to-end tests run SpamAssassin's own spamc against it.


## Exim

Exim's `spam` ACL condition talks to spamd. In the main configuration:

```text
spamd_address = 127.0.0.1 783
```

In the DATA ACL (`acl_check_data` in Debian's exim4):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` answers with a temporary 4xx error, so senders retry and a mistake can be corrected. Change it to `deny` for a permanent refusal once results look right.


## Haraka

Haraka's `spamassassin` plugin talks to spamd. Enable it in `config/plugins` and set, in `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Junk folder and learning

A Sieve rule files tagged mail in Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

With IMAPSieve, moving a message into or out of Junk can teach the model. Start the HTTP API with a token and a model file:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

and point the milter or spamd server at the same model with `--model /var/lib/spamscanner/model.json` (or `SPAMSCANNER_MODEL`). Restart it now and then to pick up what was learned. A script run by `sieve_pipe` posts the message:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Dovecot's [spam reporting guide](https://doc.dovecot.org/main/core/config/spam_reporting.html) shows the rest of the setup, which is the same for any spam filter that learns from a script.


## procmail and maildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop:

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

`scan --headers` exits 1 for spam. procmail and maildrop use the output, not the exit code, with the rules above.


## HTTP API

Any program that can make an HTTP request can scan mail:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[The HTTP API](http-api.md) lists every endpoint.


## Inside a Node.js mail server

With [smtp-server](https://nodemailer.com/extras/smtp-server/), Haraka plugins or any other Node.js server, call the library directly:

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

`session.envelope` from smtp-server already has the `mailFrom` and `rcptTo` shape that Spam Scanner reads.
