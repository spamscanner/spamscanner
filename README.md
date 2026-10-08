<h1 align="center">
  <a href="https://spamscanner.net"><img src="https://raw.githubusercontent.com/spamscanner/spamscanner/master/media/spamscanner.png" alt="Spam Scanner" width="600"></a>
</h1>

<p align="center">
  <a href="https://github.com/spamscanner/spamscanner/actions/workflows/ci.yml"><img src="https://github.com/spamscanner/spamscanner/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.npmjs.com/package/spamscanner"><img src="https://img.shields.io/npm/v/spamscanner.svg" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/spamscanner/spamscanner.svg" alt="License"></a>
</p>

<p align="center">A spam filter for Node.js, the command line and mail servers. It catches spam, phishing, scams and malware in any language, explains every decision, and can ask a language model about close calls.</p>

<p align="center"><a href="https://spamscanner.net">spamscanner.net</a> · <a href="https://spamscanner.net/docs/getting-started/">Getting started</a> · <a href="https://spamscanner.net/docs/">Documentation</a></p>


## Features

* **A classifier that reads every language.** Words are segmented by Unicode rules, so Chinese, Japanese and Thai work like English. Lookalike letters, invisible characters, `v1agra` spellings and styled letters are undone before counting. Links, senders, HTML and attachments count too, not only words.
* **Careful with languages it has not learned.** A language the model saw little ham in gets "unsure" rather than "spam", and the other checks decide.
* **Phishing checks.** Lookalike domains (`pаypal.com` with a Cyrillic а, `paypa1.com`, punycode), links whose text shows another address, brand names in display names, and Cloudflare's malware and adult-content resolvers.
* **Attachment checks.** Executables found by their bytes, also when renamed to `.pdf`; double extensions; right-to-left filename tricks; executables in ZIP files; Office macros; active PDFs; and ClamAV.
* **SPF, DKIM, DMARC and ARC**, DNS blocklists, allow and deny lists.
* **Language models for close calls.** Ollama, LM Studio, llama.cpp, vLLM, Claude, ChatGPT, Gemini, Mistral, Groq, OpenRouter and any OpenAI-compatible server, on any URL, port and authentication, plus the decision models Cloudflare Clef and TypeSafe Jev. By default the model returns a probability for each verdict in one step instead of writing an answer. Personal data is removed before mail goes to a remote provider.
* **Every way to plug in.** A Node.js library, a command line, a Postfix and Sendmail milter, a Postfix content filter, a SpamAssassin-compatible spamd server for spamc, Exim and Haraka, an HTTP API and a TCP server.
* **Explainable.** Each result lists the tests that fired with their points, SpamAssassin-style, and adds `X-Spam-*` headers.
* **Trainable.** Train on your own mbox files, Maildirs or datasets, measure the result, and learn from "report spam" buttons.


## Install

```sh
npm install --global spamscanner     # the command line
npm install spamscanner              # the library
```

Or a standalone binary, with nothing else to install:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

The package needs Node.js 18 or later.


## Use

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner();
const result = await scanner.scan(rawMessage, {
  session: {remoteAddress: '203.0.113.5', envelope: {rcptTo: [{address: 'bob@example.org'}]}},
});

result.isSpam;   // true
result.action;   // 'accept', 'tag' or 'reject'
result.tests;    // [{name: 'DECEPTIVE_LINK', score: 3, description: '...'}, ...]
```

With Postfix:

```sh
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
sudo postconf -e smtpd_milters=inet:127.0.0.1:7831 milter_default_action=accept
sudo postfix reload
```

With a local language model:

```sh
ollama pull qwen3.5:4b
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
```


## Documentation

* [Getting started](https://spamscanner.net/docs/getting-started/)
* [Command line](https://spamscanner.net/docs/cli/)
* [Postfix and Sendmail](https://spamscanner.net/docs/postfix/), [other mail servers](https://spamscanner.net/docs/mail-servers/), [HTTP API and spamd](https://spamscanner.net/docs/http-api/)
* [How it works](https://spamscanner.net/docs/how-it-works/), [tests and scores](https://spamscanner.net/docs/scoring/), [languages](https://spamscanner.net/docs/languages/)
* [Language models](https://spamscanner.net/docs/llm/), with recommended open models from Hugging Face
* [Training](https://spamscanner.net/docs/training/)
* [Forward Email, and upgrading from version 5 or 6](https://spamscanner.net/docs/forward-email/)
* [API reference](https://spamscanner.net/docs/api/)
* [Security and privacy](https://spamscanner.net/docs/security/)

The same pages are in [docs/](docs/) in this repository. The website and documentation are also in 24 other languages; see [i18n/](i18n/README.md).


## Development

```sh
npm install
npm test               # lint, build, and every test, with 100% coverage required
npm run test:e2e       # end-to-end tests against Postfix, ClamAV, spamc and Ollama; see test/e2e/
npm run model:train    # rebuild the bundled model from public datasets
npm run site:build     # build spamscanner.net into _site/
npm run site:serve     # preview it at http://localhost:8080
npm run i18n:check     # check the translations against the English pages
```


## License

[BUSL-1.1](LICENSE) © [Forward Email](https://forwardemail.net)
