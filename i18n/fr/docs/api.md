<!-- source: b3cc9f949acd -->

# Référence de l’API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Créez un seul scanner et réutilisez-le : il charge le modèle une seule fois et met en cache les réponses DNS et celles du modèle de langage.


## Options

Toutes les options peuvent être passées au constructeur. La plupart peuvent aussi être passées à `scan()` pour un seul message ; elles sont alors fusionnées par-dessus celles du constructeur.

| Option                  | Valeur par défaut                | Signification                                                                                                   |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Score à partir duquel un message est du spam                                                                    |
| `rejectThreshold`       | `15`                             | Score à partir duquel `action` vaut `reject`                                                                    |
| `scores`                | `{}`                             | Points par test : clés de réglage ou noms de tests ([tests et scores](scoring.md))                              |
| `classifier`            | modèle fourni                    | Un `Classifier`, un objet modèle, le chemin d’un fichier de modèle, ou `false`                                  |
| `classifierOptions`     | `{}`                             | Options du modèle fourni (voir [Classifieur](#classifier))                                                      |
| `allowedLanguages`      | `[]`                             | Codes ISO 639-1 ; les autres langues obtiennent `LANGUAGE_NOT_ALLOWED`                                          |
| `phishing.cloudflare`   | `true`                           | Interroger les résolveurs filtrants de Cloudflare sur les hôtes des liens                                       |
| `phishing.adult`        | `true`                           | Interroger aussi le résolveur familial, qui bloque les sites pour adultes                                       |
| `phishing.maxHosts`     | `25`                             | Nombre d’hôtes de liens vérifiés par message                                                                    |
| `phishing.homograph`    | `{}`                             | `brands` (remplace la liste intégrée), `extraBrands`, `allowlist` (domaines jamais signalés), `strictMode`      |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zones de listes de blocage DNS pour l’IP du client et pour les domaines des liens                               |
| `dns`                   | `{servers: null, timeout: 3000}` | Serveurs de noms pour les vérifications DNS (par défaut : ceux du système)                                      |
| `attachments`           | `true`                           | Inspecter les pièces jointes                                                                                    |
| `macros`                | `true`                           | Signaler les macros, les PDF actifs et les objets RTF                                                           |
| `arbitrary`             | `true`                           | Appliquer les [règles](scoring.md#rules)                                                                        |
| `authentication`        | `false`                          | `true`, ou `{dnsServers, timeout, mta, weights}` : SPF, DKIM, DMARC, ARC                                        |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                               |
| `allowlist`, `denylist` |                                  | Adresses IP, domaines ou adresses e-mail ; raccourci pour `reputation`                                          |
| `clamav`                | `false`                          | `true` (socket par défaut), `{socket}` ou `{host, port}`                                                        |
| `llm`                   | `null`                           | [Réglages du modèle de langage](llm.md#any-server-port-and-authentication), avec `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}` : un modèle dont `classify([text])` répond comme `@tensorflow-models/toxicity`       |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}` : un modèle dont `classify(imageBuffer)` répond comme `nsfwjs`                       |
| `maxLength`             | `100000`                         | Nombre de caractères du corps lus                                                                               |
| `timeout`               | `10000`                          | Millisecondes accordées à chaque vérification réseau                                                            |
| `session`               | `{}`                             | Détails de session SMTP par défaut                                                                              |

`scan()` accepte aussi `session` :

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


## Méthodes

| Méthode                              | Renvoie                                                                                  |
| ------------------------------------ | ---------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Le résultat. `source` est un Buffer, une chaîne, un Uint8Array ou un flux lisible        |
| `scanFile(path, options)`            | Le résultat pour un fichier de message                                                   |
| `learn(source, 'spam' \| 'ham')`     | Apprend un message au classifieur                                                        |
| `unlearn(source, 'spam' \| 'ham')`   | Annule `learn`                                                                           |
| `saveModel(path, options)`           | Écrit le classifieur dans un fichier (`options` : `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Le `Classifier` utilisé, ou `null`                                                       |
| `getClassification(features)`        | Le verdict du classifieur pour des caractéristiques issues de `getFeatures`              |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` pour un message analysé                     |
| `getTokens(text, locale)`            | Les mots d’un texte                                                                      |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                               |
| `parse(source)`                      | `{raw, mail}`, avec `mail` issu de mailparser                                            |

`scanner.metrics` contient `totalScans`, `averageTime` et `lastScanTime`.


## Le résultat

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

Les résultats dans `phishing`, `attachments`, `executables`, `macros`, `viruses` et `arbitrary` sont des objets avec un `type` et un `message`. `String(finding)` donne le message.


## Exports

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

### Classifieur

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Option                                 | Valeur par défaut | Signification                                                                       |
| -------------------------------------- | ----------------- | ----------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`     | s et x de Robinson : à quel point les caractéristiques rares sont ramenées vers 0,5 |
| `minDistance`                          | `0.1`             | Les caractéristiques plus proches de 0,5 que cette valeur sont ignorées             |
| `maxClues`                             | `150`             | Nombre de caractéristiques les plus fortes combinées par message                    |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`     | Bornes de la plage `unsure`                                                         |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02`    | Messages de chaque classe nécessaires dans une langue pour une confiance totale     |
| `languagePrior`                        | `true`            | Pondérer les mots par rapport aux décomptes de leur propre langue                   |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` et `entries()` sont aussi disponibles.

### Entraînement

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` prend des éléments `{label, features}`, ou `readExamples(sources)`, qui lit les mêmes sources que `train`, et renvoie les décomptes, la précision, le rappel, le F1, l’exactitude ainsi que les taux de faux positifs, de faux négatifs et d’incertains.

### Serveurs

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### Rapports ARF

`spamscanner/arf` lit et écrit des rapports de signalement d’abus (RFC 5965), le format qu’utilisent les fournisseurs de messagerie pour signaler les plaintes pour spam :

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

`ArfParser.tryParse()` renvoie `null` au lieu de lever une exception pour les messages qui ne sont pas des rapports, et `isArfMessage(mail)` vérifie un message analysé.
