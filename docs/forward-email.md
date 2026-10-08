# Forward Email

Spam Scanner was built by [Forward Email](https://forwardemail.net), the open-source, privacy-focused email service, for its own mail servers. Forward Email keeps no logs of message content, so no outside filtering service would do: the filter had to run on its own servers, and had to explain each decision without a person reading the mail.

This page shows how a mail server like Forward Email's uses it, and what changed for code written for Spam Scanner 5 or 6.


## On an inbound mail server

Forward Email receives mail with [smtp-server](https://nodemailer.com/extras/smtp-server/). The pattern, for any server built on it:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()` accepts the SMTP stream directly. With [mailauth](https://github.com/postalsys/mailauth) results already at hand, skip `authentication` and pass the IP address only.

A reply of 421 or 451 makes the sending server queue the message and try again later. New rejection rules can start with a temporary code and move to 550 once their results have been checked, without losing mail in between.


## Upgrading from version 5 or 6

Version 7 is a rewrite. The constructor, `scan()` and the result fields that version 5 and 6 code reads still work; the classifier, the model and the optional TensorFlow checks changed.

### Still the same

* `new SpamScanner(options)` and `await scanner.scan(source)`.
* `require('spamscanner')` returns the class, and `import SpamScanner from 'spamscanner'` works.
* `result.isSpam`, `result.message`, and `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` and `.idnHomographAttack`.
* Each item in `results.phishing`, `.executables`, `.arbitrary` and `.viruses` converts to the same kind of message string as before (`String(item)`, template literals, `message.includes('adult-related content')`). They are now objects with `type`, `message` and details.
* `getTokensAndMailFromSource()`, `getClassification()` and `getTokens()`.
* These options map to their new names: `clamscan` to `clamav`, `enableMacroDetection: false` to `macros: false`, `enableArbitraryDetection: false` to `arbitrary: false`, `enableAuthentication` with `authOptions` to `authentication` and `session`, `enableReputation` with `reputationOptions.apiUrl` to `reputation`, `strictIDNDetection` to `phishing.homograph.strictMode`, and `allowlist` and `denylist`. `logger` and `memoize` are accepted and ignored.

### Changed

| Before                                                                          | Now                                                                                                                                                                   |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` read the file                                        | A string is message text. Use `scanFile(path)` or pass a Buffer                                                                                                       |
| A naive Bayes model of words (`classifier.json`), not loadable now              | A new classifier and model format; retrain with `spamscanner train` ([training](training.md))                                                                         |
| Toxicity and NSFW checks loaded TensorFlow models from the network on first use | Bring your own model: `toxicity: {model}` and `nsfw: {model}` take any object with a `classify()` method, for example from `@tensorflow-models/toxicity` and `nsfwjs` |
| `results.arbitrary` listed every pattern that matched                           | It lists rules strong enough to mark spam on their own; all rules are in `result.tests`                                                                               |
| A yes-or-no answer                                                              | `result.score`, `result.action` (`accept`, `tag` or `reject`) and `result.tests`, each with points and a reason                                                       |
| `isSpam` decided by the classifier or any single check                          | `isSpam` is a score of 5 or more; thresholds and points can be changed                                                                                                |
| Reputation checks against a Forward Email endpoint                              | A generic reputation service, off unless `reputation.apiUrl` is set                                                                                                   |

### New

* [Language models](llm.md) for close calls, local or hosted.
* SPF, DKIM, DMARC and ARC; DNS blocklists; Cloudflare's filtering resolvers.
* Attachment checks by content: disguised executables, archives, macros, active PDFs.
* A [milter, HTTP API, TCP server and spamd server](mail-servers.md), and a [command line](cli.md).
* Training, evaluation and learning from reports, from the command line or the API.
