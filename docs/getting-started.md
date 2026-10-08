# Getting started

Spam Scanner needs Node.js 18 or later, or nothing at all with the standalone binary.


## Install

As a command-line tool:

```sh
npm install --global spamscanner
spamscanner version
```

As a library in a Node.js project:

```sh
npm install spamscanner
```

As a standalone binary for Linux or macOS, with Node.js and the model built in:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binaries for Linux (x64 and arm64), macOS (Intel and Apple silicon) and Windows are attached to every [release](https://github.com/spamscanner/spamscanner/releases).


## Scan a message

Save a message as a file (most mail programs call this "Save as" or "Show original") and scan it:

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

The exit code is 0 for ham, 1 for spam and 2 for an error, so scripts can use it directly. `--json` prints the full result and `--headers` prints the message with `X-Spam-*` headers added.

Messages can also come from standard input:

```sh
cat message.eml | spamscanner scan -
```


## Use it from Node.js

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJS works too:

```js
const SpamScanner = require('spamscanner');
```

`scan()` takes the raw message as a Buffer, a string, a Uint8Array or a readable stream. A string is always message text: Spam Scanner never reads a file because a string looks like a path. Use `scanner.scanFile(path)` for files.


## Tell it about the SMTP session

The client's IP address, its verified hostname, the HELO name and the envelope make the result more accurate: authentication needs the IP address, and the self-spoofing rule needs the recipients.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

The same from the command line:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Turn on more checks

None of these are on by default, because each needs a service or a decision:

| Check                      | Library option                                   | Command line                |
| -------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC      | `authentication: true`                           | `--auth`                    |
| IP blocklist               | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Domain blocklist for links | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                     | `clamav: true` or `clamav: {socket}`             | `--clamav [socket]`         |
| A language model           | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Allow and deny lists       | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Cloudflare's filtering resolvers (1.1.1.2 for malware, 1.1.1.3 for adult content) are asked about link hosts by default. Turn that off with `phishing: {cloudflare: false}` or `--no-cloudflare`. [What leaves the machine](security.md)

Spamhaus and some other blocklists do not answer queries sent through public resolvers such as 8.8.8.8 or 1.1.1.1. Use them with a local caching resolver, and check their terms of use for your volume.


## Next steps

* Put it in front of a mail server: [Postfix and Sendmail](postfix.md), [other servers](mail-servers.md).
* Teach it your own mail: [training](training.md).
* Add a language model for close calls: [language models](llm.md).
