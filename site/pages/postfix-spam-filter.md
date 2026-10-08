<!--
label: Postfix spam filter
title: Postfix spam filter with a milter or content filter
description: Filter spam on a Postfix server with Spam Scanner's milter or content filter: setup, systemd unit, rejecting with 4xx or 5xx, and a Junk folder.
keywords: Postfix spam filter, Postfix milter, smtpd_milters, Postfix content filter, Postfix anti-spam, reject spam Postfix
-->

# Postfix spam filter

Spam Scanner filters a Postfix server in about five minutes. It runs as a milter, so Postfix asks it about each message during the SMTP session and can refuse spam before accepting it.


## Install and run

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` checks SPF, DKIM, DMARC and ARC; `--subject-tag` marks spam in the subject. Every message gets `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` and `X-Spam-Action` headers, and any `X-Spam-*` header the sender put in is removed first.


## Connect Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` lets mail through unfiltered if the milter is down; `tempfail` asks senders to retry instead.


## Refuse spam during the SMTP session

```sh
spamscanner milter --port 7831 --auth --reject
```

Messages at the reject threshold (15 points) are refused with `451 4.7.1 Message rejected as spam`. A 451 is temporary: the sender keeps the message and retries, so a wrong decision costs a delay, not a lost message. Once the results look right, `--reject-code 550` makes the refusal permanent.


## Without a milter

A content filter runs after Postfix accepts a message: Postfix pipes it to `spamscanner filter`, which adds headers and hands it back. Nothing is ever refused during the session, and a failure always defers delivery rather than bouncing. [Content filter setup](../../docs/postfix.md#content-filter)


## Spam into Junk

With Dovecot, a Sieve rule files tagged mail:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Tested against a real Postfix

The project's end-to-end tests run Postfix with the milter and the content filter: ham is delivered with headers and a forged `X-Spam-Flag` removed, spam is tagged, and GTUBE is refused with a 550 during the SMTP session.

Next: [the full Postfix and Sendmail guide](../../docs/postfix.md), with a systemd unit and Sendmail's `INPUT_MAIL_FILTER`.
