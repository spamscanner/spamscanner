# Spam Scanner documentation

Spam Scanner is a spam filter for Node.js and the command line, with its source code on GitHub. It reads a raw email message and decides whether it is spam, phishing, a scam or carries malware, in any language. It runs as a library, a command-line tool, a Postfix or Sendmail milter, a Postfix content filter, a SpamAssassin-compatible spamd server, an HTTP API or a TCP server.

It is built by [Forward Email](https://forwardemail.net) for its own mail servers.


## How a message is judged

Each check adds or removes points. The total decides the outcome:

| Score        | Action   | What a mail server does            |
| ------------ | -------- | ---------------------------------- |
| Below 5      | `accept` | Delivers the message               |
| 5 to 14.9    | `tag`    | Delivers it marked as spam         |
| 15 and above | `reject` | Refuses it during the SMTP session |

Both thresholds can be changed. Every result lists the tests that fired, with their points and a reason, so a decision can always be explained.

The checks:

* **A trained classifier** reads the words of the message in any script, the shape of its links, its sender and its attachments. It ships trained on public datasets and learns from your own mail. [How the classifier works](how-it-works.md#the-classifier)
* **Phishing checks** catch lookalike domains (`paypa1.com`, `pаypal.com` with a Cyrillic а), links whose text shows one address and whose target is another, and display names that claim a brand. [Phishing](how-it-works.md#phishing)
* **Attachment checks** find executables, executables renamed as documents, double extensions, right-to-left filename tricks, executables inside ZIP files, Office macros and active PDF content. ClamAV can scan attachments for viruses. [Attachments](how-it-works.md#attachments)
* **Authentication**: SPF, DKIM, DMARC and ARC, when the client's IP address is known. [Authentication](how-it-works.md#authentication)
* **DNS blocklists** for the client's IP address and the domains in links, and Cloudflare's filtering resolvers for known malware and adult sites. [Blocklists](how-it-works.md#blocklists)
* **Rules** for patterns no classifier needs to learn: the GTUBE test string, sextortion subjects, PayPal invoice scams, self-spoofing and instructions hidden for AI filters. [Rules](scoring.md#rules)
* **A language model**, optional, gives a second opinion on close calls: a local model through Ollama or any OpenAI-compatible server, or Claude, ChatGPT, Gemini and others. [Language models](llm.md)


## Where to start

* [Getting started](getting-started.md): install it and scan a first message.
* [Command line](cli.md): every command and option.
* [Postfix and Sendmail](postfix.md): filter a mail server with the milter or a content filter.
* [Other mail servers](mail-servers.md): Exim, Haraka, Dovecot, procmail and anything that can call an HTTP API.
* [Training](training.md): teach it your own mail and measure the result.
* [Language models](llm.md): providers, recommended open models, privacy and prompt injection.
* [Languages](languages.md): how it reads Chinese, Arabic, Thai and every other script.
* [Forward Email](forward-email.md): how Forward Email uses it, and upgrading from version 5 or 6.
* [API reference](api.md) and [tests and scores](scoring.md).
* [Security and privacy](security.md): what leaves the machine, and how to stop it.
