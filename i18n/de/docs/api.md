<!-- source: b3cc9f949acd -->

# API-Referenz

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Erstellen Sie einen Scanner und verwenden Sie ihn wieder: Er lädt das Modell einmal und speichert Antworten von DNS und Sprachmodell zwischen.


## Optionen

Jede Option kann an den Konstruktor übergeben werden. Die meisten lassen sich auch für eine einzelne Nachricht an `scan()` übergeben und überschreiben dann die des Konstruktors.

| Option                  | Standard                         | Bedeutung                                                                                                           |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Score, ab dem eine Nachricht Spam ist                                                                               |
| `rejectThreshold`       | `15`                             | Score, ab dem `action` den Wert `reject` hat                                                                        |
| `scores`                | `{}`                             | Punkte pro Test: Einstellungsschlüssel oder Testnamen ([Tests und Scores](scoring.md))                              |
| `classifier`            | mitgeliefertes Modell            | Ein `Classifier`, ein Modellobjekt, ein Pfad zu einer Modelldatei oder `false`                                      |
| `classifierOptions`     | `{}`                             | Optionen für das mitgelieferte Modell (siehe [Classifier](#classifier))                                             |
| `allowedLanguages`      | `[]`                             | ISO-639-1-Codes; andere Sprachen erhalten `LANGUAGE_NOT_ALLOWED`                                                    |
| `phishing.cloudflare`   | `true`                           | Die filternden Resolver von Cloudflare zu Link-Hosts befragen                                                       |
| `phishing.adult`        | `true`                           | Zusätzlich den Familien-Resolver befragen, der Seiten für Erwachsene blockiert                                      |
| `phishing.maxHosts`     | `25`                             | Pro Nachricht abgefragte Link-Hosts                                                                                 |
| `phishing.homograph`    | `{}`                             | `brands` (ersetzt die eingebaute Liste), `extraBrands`, `allowlist` (nie markierte Domains), `strictMode`           |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zonen von DNS-Blocklisten für die Client-IP und für Link-Domains                                                    |
| `dns`                   | `{servers: null, timeout: 3000}` | Nameserver für DNS-Prüfungen (Standard: die des Systems)                                                            |
| `attachments`           | `true`                           | Anhänge untersuchen                                                                                                 |
| `macros`                | `true`                           | Makros, aktive PDFs und RTF-Objekte markieren                                                                       |
| `arbitrary`             | `true`                           | Die [Regeln](scoring.md#rules) ausführen                                                                            |
| `authentication`        | `false`                          | `true` oder `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                            |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                   |
| `allowlist`, `denylist` |                                  | IP-Adressen, Domains oder Adressen; Kurzform für `reputation`                                                       |
| `clamav`                | `false`                          | `true` (Standard-Socket), `{socket}` oder `{host, port}`                                                            |
| `llm`                   | `null`                           | [Einstellungen für das Sprachmodell](llm.md#any-server-port-and-authentication), mit `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: ein Modell, dessen `classify([text])` wie `@tensorflow-models/toxicity` antwortet       |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: ein Modell, dessen `classify(imageBuffer)` wie `nsfwjs` antwortet                       |
| `maxLength`             | `100000`                         | Gelesene Zeichen des Nachrichtentexts                                                                               |
| `timeout`               | `10000`                          | Erlaubte Millisekunden pro Netzwerkprüfung                                                                          |
| `session`               | `{}`                             | Standardangaben zur SMTP-Sitzung                                                                                    |

`scan()` nimmt außerdem `session` entgegen:

```js
await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',             // the client's IP address
    resolvedClientHostname: 'mx.example.com', // its verified reverse DNS name
    helo: 'mx.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```


## Methoden

| Methode                              | Rückgabe                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Das Ergebnis. `source` ist ein Buffer, String, Uint8Array oder lesbarer Stream              |
| `scanFile(path, options)`            | Das Ergebnis für eine Nachrichtendatei                                                      |
| `learn(source, 'spam' \| 'ham')`     | Bringt dem Klassifikator eine Nachricht bei                                                 |
| `unlearn(source, 'spam' \| 'ham')`   | Macht `learn` rückgängig                                                                    |
| `saveModel(path, options)`           | Schreibt den Klassifikator in eine Datei (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Der verwendete `Classifier` oder `null`                                                     |
| `getClassification(features)`        | Das Urteil des Klassifikators für Merkmale aus `getFeatures`                                |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` für eine geparste Nachricht                    |
| `getTokens(text, locale)`            | Die Wörter eines Texts                                                                      |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                                  |
| `parse(source)`                      | `{raw, mail}`, mit `mail` aus mailparser                                                    |

`scanner.metrics` enthält `totalScans`, `averageTime` und `lastScanTime`.


## Das Ergebnis

```js
{
  isSpam: true,
  score: 16.25,
  threshold: 5,
  rejectThreshold: 15,
  action: 'reject',                       // 'accept', 'tag' or 'reject'
  message: 'Spam (BAYES_999, PHISHING_LOOKALIKE_DOMAIN, DECEPTIVE_LINK, FROM_NAME_BRAND)',
  tests: [
    {name: 'BAYES_999', score: 6.25, description: 'Classifier spam probability 99.9%'},
    {name: 'PHISHING_LOOKALIKE_DOMAIN', score: 5, description: '"paypa1-secure.top" imitates paypal by swapping characters'},
    // ...
  ],
  results: {
    classification: {probability, category, spam, ham, clues, coverage},
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'],
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser */},
  version: '7.0.0',
  metrics: {totalTime: 42},
}
```

Befunde in `phishing`, `attachments`, `executables`, `macros`, `viruses` und `arbitrary` sind Objekte mit einem `type` und einer `message`. `String(finding)` ergibt die Meldung.


## Exporte

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Option                                 | Standard       | Bedeutung                                                                    |
| -------------------------------------- | -------------- | ---------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsons s und x: wie stark seltene Merkmale in Richtung 0,5 gezogen werden |
| `minDistance`                          | `0.1`          | Merkmale, die näher als dieser Wert an 0,5 liegen, werden ignoriert          |
| `maxClues`                             | `150`          | Pro Nachricht kombinierte stärkste Merkmale                                  |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Grenzen des Bereichs `unsure`                                                |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Nachrichten jeder Klasse, die eine Sprache für volle Konfidenz braucht       |
| `languagePrior`                        | `true`         | Wörter an den Zählungen ihrer eigenen Sprache gewichten                      |

Außerdem stehen `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` und `entries()` zur Verfügung.

### Training

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` nimmt `{label, features}`-Einträge entgegen oder `readExamples(sources)`, das dieselben Quellen liest wie `train`, und gibt Zählungen, Präzision, Trefferquote, F1, Genauigkeit sowie die Raten für Fehlalarme, übersehenen Spam und unsichere Fälle zurück.

### Server

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARF-Berichte

`spamscanner/arf` liest und schreibt Abuse-Feedback-Berichte (RFC 5965), das Format, mit dem Postfachanbieter Spam-Beschwerden melden:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()` gibt bei Nachrichten, die keine Berichte sind, `null` zurück, statt einen Fehler zu werfen, und `isArfMessage(mail)` prüft eine geparste Nachricht.
