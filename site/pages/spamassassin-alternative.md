<!--
label: SpamAssassin alternative
title: A SpamAssassin alternative that speaks spamd
description: Replace SpamAssassin's spamd with Spam Scanner. spamc, Exim and Haraka keep working, the X-Spam headers keep their names, and every language is supported.
keywords: SpamAssassin alternative, spamd replacement, spamc, Exim spam filter, Haraka spamassassin, rspamd alternative, X-Spam-Status
-->

# A SpamAssassin alternative that speaks spamd

Spam Scanner answers SpamAssassin's spamd protocol, so software written for SpamAssassin uses it unchanged: spamc, Exim's `spam` condition, Haraka's `spamassassin` plugin and others.


## Swap it in

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

It answers `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` and, with `--allow-tell`, `TELL` for learning. The project's end-to-end tests run SpamAssassin's own spamc against it.


## What stays the same

* The headers: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` and `X-Spam-Status` in SpamAssassin's format, so existing Sieve, procmail and mail client rules keep working.
* A score with a threshold of 5, made of named tests with points: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` and so on.
* Per-test scores can be changed by test name.


## What is different

* **Languages.** Words are segmented with the Unicode rules, so Chinese, Japanese and Thai are read as words rather than one long string, and disguises like invisible characters or Cyrillic letters in Latin words are undone first.
* **Phishing.** Lookalike domains, deceptive links and brand names in display names are checked without extra rules.
* **Attachments** are identified by their bytes: an executable renamed to `.pdf` is still an executable.
* **Language models.** Close calls can go to a local model through Ollama or to a hosted one.
* **Node.js.** One `npm install`, or a standalone binary; no Perl modules or rule updates to manage.

Spam Scanner does not run SpamAssassin's rule files, and its Bayes database format is its own: train it from the same mail with `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot and procmail](../../docs/mail-servers.md)
