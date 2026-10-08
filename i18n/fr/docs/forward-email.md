<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner a été développé par [Forward Email](https://forwardemail.net), le service de messagerie open source axé sur la confidentialité, pour ses propres serveurs de messagerie. Forward Email ne conserve aucun journal du contenu des messages : aucun service de filtrage externe ne pouvait donc convenir. Le filtre devait s’exécuter sur ses propres serveurs et expliquer chaque décision sans que personne ne lise le courrier.

Cette page montre comment un serveur de messagerie comme celui de Forward Email l’utilise, et ce qui a changé pour le code écrit pour Spam Scanner 5 ou 6.


## Sur un serveur de messagerie entrant

Forward Email reçoit le courrier avec [smtp-server](https://nodemailer.com/extras/smtp-server/). Le schéma, pour tout serveur construit sur cette bibliothèque :

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

`scanner.scan()` accepte directement le flux SMTP. Si des résultats de [mailauth](https://github.com/postalsys/mailauth) sont déjà disponibles, laissez de côté `authentication` et passez seulement l’adresse IP.

Une réponse 421 ou 451 amène le serveur expéditeur à mettre le message en file d’attente et à réessayer plus tard. De nouvelles règles de rejet peuvent commencer avec un code temporaire et passer à 550 une fois leurs résultats vérifiés, sans perdre de courrier entre-temps.


## Mise à niveau depuis la version 5 ou 6

La version 7 est une réécriture. Le constructeur, `scan()` et les champs de résultat que lit le code des versions 5 et 6 fonctionnent toujours ; le classifieur, le modèle et les vérifications TensorFlow facultatives ont changé.

### Ce qui ne change pas

* `new SpamScanner(options)` et `await scanner.scan(source)`.
* `require('spamscanner')` renvoie la classe, et `import SpamScanner from 'spamscanner'` fonctionne.
* `result.isSpam`, `result.message`, ainsi que `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` et `.idnHomographAttack`.
* Chaque élément de `results.phishing`, `.executables`, `.arbitrary` et `.viruses` se convertit en le même type de chaîne de message qu’avant (`String(item)`, littéraux de gabarit, `message.includes('adult-related content')`). Ce sont désormais des objets avec `type`, `message` et des détails.
* `getTokensAndMailFromSource()`, `getClassification()` et `getTokens()`.
* Ces options correspondent à leurs nouveaux noms : `clamscan` devient `clamav`, `enableMacroDetection: false` devient `macros: false`, `enableArbitraryDetection: false` devient `arbitrary: false`, `enableAuthentication` avec `authOptions` devient `authentication` et `session`, `enableReputation` avec `reputationOptions.apiUrl` devient `reputation`, `strictIDNDetection` devient `phishing.homograph.strictMode`, et `allowlist` et `denylist` restent. `logger` et `memoize` sont acceptés et ignorés.

### Ce qui a changé

| Avant                                                                                                               | Maintenant                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` lisait le fichier                                                                        | Une chaîne est le texte d’un message. Utilisez `scanFile(path)` ou passez un Buffer                                                                                                          |
| Un modèle bayésien naïf de mots (`classifier.json`), qui ne peut plus être chargé                                   | Un nouveau classifieur et un nouveau format de modèle ; réentraînez avec `spamscanner train` ([entraînement](training.md))                                                                   |
| Les vérifications de toxicité et NSFW chargeaient des modèles TensorFlow depuis le réseau à la première utilisation | Apportez votre propre modèle : `toxicity: {model}` et `nsfw: {model}` acceptent tout objet doté d’une méthode `classify()`, par exemple issu de `@tensorflow-models/toxicity` et de `nsfwjs` |
| `results.arbitrary` listait chaque motif reconnu                                                                    | Il liste les règles assez fortes pour marquer un spam à elles seules ; toutes les règles figurent dans `result.tests`                                                                        |
| Une réponse par oui ou non                                                                                          | `result.score`, `result.action` (`accept`, `tag` ou `reject`) et `result.tests`, chacun avec des points et une raison                                                                        |
| `isSpam` décidé par le classifieur ou par une seule vérification                                                    | `isSpam` correspond à un score de 5 ou plus ; les seuils et les points sont modifiables                                                                                                      |
| Vérifications de réputation auprès d’un point d’accès de Forward Email                                              | Un service de réputation générique, désactivé tant que `reputation.apiUrl` n’est pas défini                                                                                                  |

### Nouveautés

* Des [modèles de langage](llm.md) pour les cas limites, locaux ou hébergés.
* SPF, DKIM, DMARC et ARC ; listes de blocage DNS ; résolveurs filtrants de Cloudflare.
* Vérification des pièces jointes d’après leur contenu : exécutables déguisés, archives, macros, PDF actifs.
* Un [milter, une API HTTP, un serveur TCP et un serveur spamd](mail-servers.md), et une [ligne de commande](cli.md).
* Entraînement, évaluation et apprentissage à partir des signalements, en ligne de commande ou via l’API.
