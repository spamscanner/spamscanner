<!-- source: b3cc9f949acd -->

# Riferimento API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Crea un solo scanner e riutilizzalo: carica il modello una volta e mantiene in cache le risposte DNS e del modello linguistico.


## Opzioni

Ogni opzione si può passare al costruttore. La maggior parte si può passare anche a `scan()` per un singolo messaggio, e in quel caso viene unita a quelle del costruttore, con la precedenza.

| Opzione                 | Predefinito                      | Significato                                                                                                           |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Punteggio a cui un messaggio è spam                                                                                   |
| `rejectThreshold`       | `15`                             | Punteggio a cui `action` è `reject`                                                                                   |
| `scores`                | `{}`                             | Punti per test: chiavi di impostazione o nomi dei test ([test e punteggi](scoring.md))                                |
| `classifier`            | modello incluso                  | Un `Classifier`, un oggetto modello, il percorso di un file di modello o `false`                                      |
| `classifierOptions`     | `{}`                             | Opzioni per il modello incluso (vedi [Classifier](#classifier))                                                       |
| `allowedLanguages`      | `[]`                             | Codici ISO 639-1; le altre lingue ricevono `LANGUAGE_NOT_ALLOWED`                                                     |
| `phishing.cloudflare`   | `true`                           | Interroga i resolver con filtraggio di Cloudflare sugli host dei link                                                 |
| `phishing.adult`        | `true`                           | Interroga anche il resolver per famiglie, che blocca i siti per adulti                                                |
| `phishing.maxHosts`     | `25`                             | Host dei link cercati per messaggio                                                                                   |
| `phishing.homograph`    | `{}`                             | `brands` (sostituisce l'elenco integrato), `extraBrands`, `allowlist` (domini mai segnalati), `strictMode`            |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zone di DNS blocklist per l'IP del client e per i domini dei link                                                     |
| `dns`                   | `{servers: null, timeout: 3000}` | Name server per i controlli DNS (predefiniti: quelli del sistema)                                                     |
| `attachments`           | `true`                           | Esamina gli allegati                                                                                                  |
| `macros`                | `true`                           | Segnala macro, PDF attivi e oggetti RTF                                                                               |
| `arbitrary`             | `true`                           | Esegue le [regole](scoring.md#rules)                                                                                  |
| `authentication`        | `false`                          | `true`, oppure `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                           |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                     |
| `allowlist`, `denylist` |                                  | Indirizzi IP, domini o indirizzi; forma abbreviata di `reputation`                                                    |
| `clamav`                | `false`                          | `true` (socket predefinito), `{socket}` o `{host, port}`                                                              |
| `llm`                   | `null`                           | [Impostazioni del modello linguistico](llm.md#any-server-port-and-authentication), con `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: un modello il cui `classify([text])` risponde come `@tensorflow-models/toxicity`          |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: un modello il cui `classify(imageBuffer)` risponde come `nsfwjs`                          |
| `maxLength`             | `100000`                         | Caratteri del testo del corpo letti                                                                                   |
| `timeout`               | `10000`                          | Millisecondi concessi a ogni controllo di rete                                                                        |
| `session`               | `{}`                             | Dettagli predefiniti della sessione SMTP                                                                              |

`scan()` accetta anche `session`:

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


## Metodi

| Metodo                               | Restituisce                                                                            |
| ------------------------------------ | -------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Il risultato. `source` è un Buffer, una stringa, un Uint8Array o uno stream leggibile  |
| `scanFile(path, options)`            | Il risultato per un file di messaggio                                                  |
| `learn(source, 'spam' \| 'ham')`     | Insegna un messaggio al classificatore                                                 |
| `unlearn(source, 'spam' \| 'ham')`   | Annulla `learn`                                                                        |
| `saveModel(path, options)`           | Scrive il classificatore in un file (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Il `Classifier` in uso, o `null`                                                       |
| `getClassification(features)`        | Il verdetto del classificatore per le feature restituite da `getFeatures`              |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` per un messaggio già interpretato         |
| `getTokens(text, locale)`            | Le parole di un testo                                                                  |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                             |
| `parse(source)`                      | `{raw, mail}`, con `mail` prodotto da mailparser                                       |

`scanner.metrics` contiene `totalScans`, `averageTime` e `lastScanTime`.


## Il risultato

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

I rilevamenti in `phishing`, `attachments`, `executables`, `macros`, `viruses` e `arbitrary` sono oggetti con un `type` e un `message`. `String(finding)` è il messaggio.


## Esportazioni

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

| Opzione                                | Predefinito    | Significato                                                                    |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------ |
| `strength`, `unknown`                  | `0.45`, `0.5`  | I parametri s e x di Robinson: quanto le feature rare vengono spinte verso 0,5 |
| `minDistance`                          | `0.1`          | Le feature più vicine a 0,5 di questo valore vengono ignorate                  |
| `maxClues`                             | `150`          | Feature più forti combinate per messaggio                                      |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Limiti dell'intervallo `unsure`                                                |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Messaggi di ciascuna classe necessari in una lingua per la piena confidenza    |
| `languagePrior`                        | `true`         | Pesa le parole rispetto ai conteggi della loro lingua                          |

Sono disponibili anche `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` e `entries()`.

### Addestramento

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` accetta elementi `{label, features}`, oppure `readExamples(sources)`, che legge le stesse sorgenti di `train`, e restituisce i conteggi, precisione, richiamo, F1, accuratezza e i tassi di falsi positivi, falsi negativi e incerti.

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

### Report ARF

`spamscanner/arf` legge e scrive gli abuse feedback report (RFC 5965), il formato che i provider di caselle di posta usano per segnalare i reclami per spam:

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

`ArfParser.tryParse()` restituisce `null` invece di generare un'eccezione per i messaggi che non sono report, e `isArfMessage(mail)` verifica un messaggio già interpretato.
