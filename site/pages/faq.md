<!--
label: FAQ
title: Frequently asked questions
description: Answers about Spam Scanner: how accurate it is, which languages it supports, what it sends over the network, language models, SpamAssassin and Forward Email.
keywords: Spam Scanner FAQ, spam filter questions, spam filter accuracy, spam filter privacy
-->

# Frequently asked questions


## What is Spam Scanner?

A spam filter for Node.js, the command line and mail servers. It reads a raw email message and decides whether it is spam, phishing, a scam or carries malware, with a score and the list of tests that decided it. It runs as a library, a milter for Postfix and Sendmail, a SpamAssassin-compatible spamd server, a Postfix content filter, an HTTP API or a TCP server.


## Is it free?

Its [license](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), the Business Source License 1.1, allows any use except offering spam detection as a service to others, and names the date on which it changes to the Apache License 2.0.


## How accurate is it?

On held-out English messages from its training data, the bundled classifier alone marked no ham as spam and caught 97% of the spam; the full numbers per language are in the [training guide](../../docs/training.md#the-bundled-model). Links, attachments, authentication, blocklists and a language model add to that. Your own mail is the real test: `spamscanner eval` measures any model on any labelled mail.


## Which languages does it support?

All of them. It segments words with the Unicode rules, including Chinese, Japanese and Thai, which have no spaces. Where the bundled model has seen little mail in a language it stays unsure rather than flag it, and a language model or your own training decides. [Languages](../../docs/languages.md)


## Does it send my mail anywhere?

No. By default it looks up the host names of links on Cloudflare's filtering DNS resolvers, and nothing else leaves the machine. Authentication, blocklists, language models and reputation services are off until configured, and personal data is removed before mail goes to a hosted language model. [Security and privacy](../../docs/security.md)


## Do I need a language model?

No. It is a second opinion for close calls. Without one, those messages are decided by their score alone.


## Which language model should I use?

`qwen3.5:4b` through Ollama on a CPU, or `qwen3.5:9b` with a GPU. Both are Apache-licensed and read 201 languages. Hosted models from Anthropic, OpenAI, Google and others work too. [Recommended models](../../docs/llm.md#recommended-open-models)


## Can it replace SpamAssassin?

For most setups, yes: it speaks spamd's protocol, so spamc, Exim and Haraka work unchanged, and it writes the same `X-Spam-*` headers. It does not run SpamAssassin's rule files. [SpamAssassin alternative](/spamassassin-alternative/)


## Will it reject legitimate mail?

Refusing mail is off by default: the milter only tags. With `--reject`, only messages scoring 15 or more are refused, with a temporary 451 error, so senders retry and a mistake can be fixed by changing a setting. The content filter never refuses during the SMTP session.


## How do I train it on my mail?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, then `--model model.json`. Mbox files, Maildirs, folders of `.eml` files and CSV or JSON Lines datasets all work. [Training](../../docs/training.md)


## Does it work without Node.js?

Yes: standalone binaries for Linux, macOS and Windows include Node.js and the model. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Who makes it?

[Forward Email](https://forwardemail.net), for its own mail servers.
