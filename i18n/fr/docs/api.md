<!-- source: 9134d1cd102c -->

# Référence de l’API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Créez un seul scanner et réutilisez-le : il charge le modèle une seule fois et met en cache les réponses DNS et celles du modèle de langage.

Les déclarations de types sont incluses. Elles nécessitent TypeScript 4.7 ou ultérieur avec `import`, et 5.3 ou ultérieur avec `require`.


## Options

Toutes les options peuvent être passées au constructeur. La plupart peuvent aussi être passées à `scan()` pour un seul message ; elles sont alors fusionnées par-dessus celles du constructeur. Les options passées à `undefined` gardent leur valeur par défaut. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` et `strictIDNDetection` ne sont lues que par le constructeur ; un fichier ou un objet de modèle donné dans `classifier` y est lu, si bien qu'un modèle absent ou endommagé lève une erreur aussitôt.

| Option                  | Valeur par défaut                | Signification                                                                                                                                                                                                         |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Score à partir duquel un message est du spam                                                                                                                                                                          |
| `rejectThreshold`       | `15`                             | Score à partir duquel `action` vaut `reject`                                                                                                                                                                          |
| `scores`                | `{}`                             | Points par test : clés de réglage ou noms de tests ([tests et scores](scoring.md))                                                                                                                                    |
| `classifier`            | modèle fourni                    | Un `Classifier`, un objet modèle, le chemin d’un fichier de modèle, ou `false`                                                                                                                                        |
| `classifierOptions`     | `{}`                             | Options du modèle fourni (voir [Classifieur](#classifier))                                                                                                                                                            |
| `allowedLanguages`      | `[]`                             | Codes ISO 639-1 (`no` est lu comme `nb`, `fil` comme `tl`, et les anciens `iw`, `in`, `ji` comme `he`, `id`, `yi`) ; les autres langues obtiennent `LANGUAGE_NOT_ALLOWED`                                             |
| `phishing.cloudflare`   | `true`                           | Interroger les résolveurs filtrants de Cloudflare sur les hôtes des liens                                                                                                                                             |
| `phishing.adult`        | `true`                           | Interroger aussi le résolveur familial, qui bloque les sites pour adultes                                                                                                                                             |
| `phishing.maxHosts`     | `25`                             | Nombre d’hôtes de liens vérifiés par message                                                                                                                                                                          |
| `phishing.maxLength`    | `1000000`                        | Caractères du texte lus pour trouver les liens (deux fois plus pour le HTML) ; un texte plus long active `results.linksTruncated` ; `Infinity`, ou toute autre valeur qu'un nombre positif, vaut la valeur par défaut |
| `phishing.homograph`    | `{}`                             | `brands` (remplace la liste intégrée), `extraBrands`, `allowlist` (domaines jamais signalés), `strictMode`                                                                                                            |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zones de listes de blocage DNS pour l’IP du client et pour les domaines des liens                                                                                                                                     |
| `dns`                   | `{servers: null, timeout: 3000}` | Serveurs de noms pour les vérifications DNS (par défaut : ceux du système)                                                                                                                                            |
| `attachments`           | `true`                           | Inspecter les pièces jointes                                                                                                                                                                                          |
| `macros`                | `true`                           | Signaler les macros, les PDF actifs et les objets RTF                                                                                                                                                                 |
| `arbitrary`             | `true`                           | Appliquer les [règles](scoring.md#rules)                                                                                                                                                                              |
| `authentication`        | `false`                          | `true`, ou `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}` : SPF, DKIM, DMARC, ARC ([score](scoring.md#authentication))                                                                       |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}` ; les réponses sont conservées par service et en-têtes, et `cacheSize` vaut pour tout le scanner                                  |
| `allowlist`, `denylist` |                                  | Adresses IP, domaines ou adresses e-mail ; raccourci pour `reputation` → [Liste d'autorisation et liste de blocage](#allowlist-and-denylist)                                                                          |
| `clamav`                | `false`                          | `true` (socket par défaut), `{socket}` ou `{host, port}`, avec `timeout` : millisecondes pour toutes les pièces jointes d’un message (`60000`)                                                                        |
| `llm`                   | `null`                           | [Réglages du modèle de langage](llm.md#any-server-port-and-authentication), avec `mode`, `minScore`, `maxScore`                                                                                                       |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}` : un modèle dont `classify([text])` répond comme `@tensorflow-models/toxicity`                                                                                                             |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}` : un modèle dont `classify(imageBuffer)` répond comme `nsfwjs`                                                                                                                             |
| `maxLength`             | `100000`                         | Nombre de caractères du corps lus                                                                                                                                                                                     |
| `timeout`               | `10000`                          | Millisecondes accordées à chaque vérification réseau ; l'authentification et le modèle d'images disposent de ce délai au total (ClamAV a son propre `clamav.timeout`)                                                 |
| `session`               | `{}`                             | Détails de session SMTP par défaut                                                                                                                                                                                    |

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

Un serveur qui a déjà vérifié SPF, DKIM, DMARC et ARC (avec [mailauth](https://github.com/postalsys/mailauth)) peut transmettre ses résultats dans `authenticationResults`, qui sont alors notés au lieu d’être vérifiés à nouveau :

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Liste d'autorisation et liste de blocage

La liste de blocage compare l'adresse IP et le nom d'hôte du client, les adresses From, d'expéditeur d'enveloppe et Reply-To, ainsi que leurs domaines, quels qu'ils soient : un nom situé sous un domaine de la liste de blocage y correspond même s'il n'est pas un nom d'hôte valide (comme `a_b!.evil.example`, ou un nom dont une étiquette dépasse 63 caractères), par ses 127 dernières étiquettes et ses 253 derniers caractères. La liste d'autorisation, ainsi que la liste d'autorisation et les sources de confiance d'un service de réputation, ne comparent que ce qu'un expéditeur ne peut pas falsifier : l'adresse IP et le nom d'hôte vérifié du client (`remoteAddress`, `resolvedClientHostname`), une adresse From lorsque DMARC réussit pour son domaine ou qu'une signature DKIM valide est alignée sur elle (et s'il s'agit d'un nom d'hôte valide ; de façon souple, comme dans DMARC : le domaine From et le domaine signataire ou SPF ont le même domaine enregistrable, que mailauth nomme domaine DMARC ; une entrée qui nomme un sous-domaine, comme `news.example.com`, ne compte que lorsque ce domaine, un domaine situé en dessous ou un domaine parent a signé le message ou réussi SPF, pas un autre sous-domaine comme `evil.example.com`, ni un suffixe public ; une réussite DMARC pour le domaine enregistrable sans les détails d’alignement de mailauth ne compte que pour une entrée qui nomme le domaine enregistrable ; en alignement strict, `adkim=s` ou `aspf=s` dans l’enregistrement DMARC du domaine, quels qu'en soient la casse ou l'espacement, seule compte une signature ou une réussite SPF du domaine From lui-même, et DMARC échoue sans elle), et l'expéditeur d'enveloppe lorsque SPF réussit pour son domaine. Une signature DKIM du seul début du corps (une longueur de corps, `l=`, plus courte que le corps : n’importe qui peut ajouter du texte après) ne compte pour rien, pas plus qu’une réussite DMARC qui repose sur une telle signature, et aucune signature ne compte quand DMARC échoue, ni pour un champ From trop long pour être lu en entier (`mail.from.truncated`). Les résultats passés dans `authenticationResults` ne comptent que s'ils nomment le domaine pour lequel ils ont réussi, et un domaine qui n’est pas un nom d’hôte (comme `bank.example/x.attacker.example`, que les analyseurs d’URL lisent comme `bank.example`) ne compte pour aucun, pas plus qu’une réussite DMARC qui repose sur un tel domaine. Les domaines internationaux correspondent sous l’une ou l’autre forme : `bücher.example` ou `xn--bcher-kva.example`. Reply-To ne compte jamais. Pour autoriser un domaine, activez `authentication` ou passez `authenticationResults`.

Chaque entrée est une seule adresse IP, un seul domaine ou une seule adresse e-mail, comparé exactement : une entrée de domaine couvre aussi ses sous-domaines et les adresses qui s’y trouvent, mais il n’y a ni plages d’adresses (`192.0.2.0/24`), ni jokers (`*.example.com`), ni motifs (`@example.com`). Les adresses IPv6 correspondent sous n’importe quelle forme (`2001:0db8::0001` est `2001:db8::1`, la forme de la RFC 5952), une adresse IPv4 mappée dans IPv6 (`::ffff:192.0.2.1`) correspond à l’adresse IPv4, et une adresse IPv4 traduite dans IPv6 ou placée sous le préfixe NAT64 s’écrit avec l’adresse IPv4 sous forme pointée (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), dans les entrées comme dans les adresses des clients.


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
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` d’un message           |
| `getTokens(text, locale)`            | Les mots d’un texte                                                                      |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                               |
| `parse(source)`                      | `{raw, mail, error}`, avec `mail` issu de mailparser (voir ci-dessous)                   |

`scan`, `parse`, `learn`, `unlearn` et `getTokensAndMailFromSource` lisent tous un message de la même façon : un message qui dépasse les limites de l’analyseur MIME (plus de 1000 parties, l’en-tête d’une partie de plus de 1 Mo) est lu aussi loin que l’analyseur le permet. Les champs d’adresse (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To et List-\*), du message, de ses parties et des messages joints, sont lus jusqu’à 16 Ko chacun, 2000 virgules et points-virgules et 16 groupes imbriqués, et 64 Ko au total pour chaque message, toujours jusqu’à la fin d’une adresse entière, si bien qu’aucune adresse n’est lue que le champ ne donne pas ; un champ coupé est marqué `truncated` (`mail.to.truncated`), et un champ From coupé ne donne aucun crédit pour l’authentification de l’expéditeur. Un texte dont la première ligne n’est pas un champ d’en-tête (`Name: value`, ou la ligne `From` qui commence chaque message dans les fichiers mbox) est lu comme le corps d’un message sans en-tête, si bien que `mail.text` est ce texte. Les autres erreurs sont levées. `parse` indique la limite de l'analyseur qu'un message dépasse dans `error`, comme `scan` l'indique dans `parseError`, et null pour un message lu en entier.

Dans `getFeatures`, `text` est le texte affiché par un client de messagerie, dont sont tirés les mots, et `hidden` le nombre de caractères de texte que le HTML cache. mailparser ne tire pas ici de texte du HTML : `mail.text` ne contient que les parties en texte brut, et il est vide pour un message uniquement en HTML ; le texte qu’affiche son HTML est `getFeatures(mail).text`.

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
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    virusScanErrors: [], // attachments ClamAV could not scan: {filename, error}
    virusScanSkipped: [], // attachments larger than clamd accepts, not scanned: {filename, reason}
    unopenedAttachments: [], // attached messages not opened, past the limits they are read within: {filename, reason}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value, answers} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'], // the links checked, of the whole message up to phishing.maxLength
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser; mail.text: the plain text parts only */},
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

Les résultats dans `phishing`, `attachments`, `executables`, `macros`, `viruses` et `arbitrary` sont des objets avec un `type` et un `message`. `String(finding)` donne le message. Les pièces jointes d'un message joint (`message/rfc822`, `message/global`, `.eml`, `.u8msg`) portent son nom : `fw.eml/invoice.exe`. Un virus que ClamAV trouve dans une telle pièce jointe est signalé pour elle seule, pas une seconde fois pour le message joint qui la contient. `virusScanErrors` liste les pièces jointes que ClamAV n'a pas pu analyser, sous la forme `{filename, error}` : un tel message peut contenir un virus, retenez-le donc plutôt que de le distribuer. Le milter et le filtre de contenu le diffèrent, sauf si `onError` (`--on-error`) vaut `accept`, et chaque serveur marque un tel message qu'il laisse passer avec `X-Spam-Virus-Scan: failed`. `virusScanSkipped` liste celles qui sont plus grandes que ce qu’accepte clamd (son `StreamMaxLength`), sous la forme `{filename, reason}` : clamd les refuse à chaque tentative, elles ne sont donc pas des échecs, de même que clamav-milter ignore un fichier qui dépasse son `MaxFileSize`. Ses autres limites (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), qu’atteint une bombe d’archive, sont des échecs. Les messages joints sont ouverts sur trois niveaux, pour au plus 100 pièces jointes et 25 Mo au total ; `unopenedAttachments` liste ceux qui n'ont pas été ouverts au-delà de ces limites, sous la forme `{filename, reason}`, et dont les pièces jointes n'ont pas été inspectées. Il n'est pas compté dans le score, car des messages transférés peuvent être imbriqués ainsi, mais un appelant qui a besoin d'un message lu en entier, par exemple pour bloquer un programme qu'il contient, peut refuser un message qui en a. Au plus 100 messages joints sont ouverts au total.

Chaque élément de `dnsbl` porte les `answers` de la liste (des adresses dans 127.0.0.0/8, dont chaque liste documente la signification). Les réponses que les listes donnent aux requêtes qu’elles refusent ou auxquelles elles ne peuvent pas répondre ne sont pas des inscriptions, ni pour l’adresse du client ni pour les domaines des liens (résultats `uribl` dans `phishing`) : 127.255.255.x chez Spamhaus (comme 127.255.255.254 pour une requête passant par un résolveur public, et 127.255.255.255 pour trop de requêtes), 127.0.1.255 pour la DBL de Spamhaus, 127.0.0.255 pour toute liste, et 127.0.0.1 chez SURBL et URIBL, qui la répondent aux résolveurs qu’elles bloquent.


## Exports

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, unwrapLink, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export
// unwrapLink(address): the URL a link goes to, through Safe Links and
// Proofpoint URL Defense, as the scanner reads it (null for no URL)

import ArfParser from 'spamscanner/arf';
```

### Classifieur

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Option                                 | Valeur par défaut | Signification                                                                                                                                                                 |
| -------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`     | s et x de Robinson : à quel point les caractéristiques rares sont ramenées vers 0,5                                                                                           |
| `minDistance`                          | `0.1`             | Les caractéristiques plus proches de 0,5 que cette valeur sont ignorées                                                                                                       |
| `maxClues`                             | `150`             | Nombre de caractéristiques les plus fortes combinées par message                                                                                                              |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`     | Bornes de la plage `unsure`                                                                                                                                                   |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02`    | Messages ham nécessaires dans une langue pour une confiance totale, et cinq fois moins de messages spam ; moins quand `languageShare` de tout le ham ou le spam est inférieur |
| `languagePrior`                        | `true`            | Pondérer les mots par rapport aux décomptes de leur propre langue                                                                                                             |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` et `entries()` sont aussi disponibles. `Classifier.fromJSON` vérifie le modèle et lève une `TypeError` commençant par `Corrupt classifier model` sur des données endommagées. JSON n’a pas d’`Infinity`, donc une option enregistrée comme `Infinity` par la version 7.0.3 est relue comme `null` : elle est lue comme `Infinity` pour `maxClues`, `minDistance` et `minLanguageExamples`, comme `-Infinity` pour `hamCutoff` (jamais ham) et `Infinity` pour `spamCutoff` (jamais spam), et comme la valeur par défaut pour les autres. `toJSON` enregistre un seuil au-delà de 0 et 1 comme -1 ou 2, ce qui revient au même. `loadModel` relit un fichier lorsqu'il change, et `saveModel` écrit en passant par un nouveau fichier temporaire, vidé sur le disque avant de remplacer le modèle, qui conserve ses permissions.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

L'option `onError` du milter est sa réponse lorsqu'une analyse échoue ou que ClamAV n'a pas pu analyser une pièce jointe : `'tempfail'` (par défaut) ou `'accept'`, qui laisse passer le message marqué `X-Spam-Virus-Scan: failed`, sans les en-têtes `X-Spam-*` ajoutés par l’expéditeur.

### Rapports ARF

`spamscanner/arf` lit et écrit des rapports de signalement d’abus (RFC 5965), le format qu’utilisent les fournisseurs de messagerie pour signaler les plaintes pour spam :

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders?.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`parse()` accepte un Buffer, un Uint8Array ou une chaîne. `ArfParser.tryParse()` renvoie `null` au lieu de lever une exception pour les messages qui ne sont pas des rapports, et `isArfMessage(mail)` vérifie un message analysé. `originalHeaders` vaut `null` pour un rapport sans le message d’origine. `create()` renvoie une chaîne, ou un `Buffer` lorsque `originalMessage` en est un, afin que ses octets soient conservés quel que soit leur jeu de caractères.
