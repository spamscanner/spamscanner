<!-- source: 8263c06f1dab -->

# Prise en main

Spam Scanner nécessite Node.js 18 ou une version ultérieure, ou rien du tout avec le binaire autonome.


## Installation

Comme outil en ligne de commande :

```sh
npm install --global spamscanner
spamscanner version
```

Comme bibliothèque dans un projet Node.js :

```sh
npm install spamscanner
```

Comme binaire autonome pour Linux ou macOS, avec Node.js et le modèle intégrés :

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Des binaires pour Linux (x64 et arm64), macOS (Intel et Apple silicon) et Windows sont joints à chaque [version publiée](https://github.com/spamscanner/spamscanner/releases).


## Analyser un message

Enregistrez un message dans un fichier (la plupart des logiciels de messagerie appellent cela « Enregistrer sous » ou « Afficher l’original ») et analysez-le :

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

Le code de sortie vaut 0 pour du ham (courrier légitime), 1 pour du spam et 2 en cas d’erreur : les scripts peuvent donc l’utiliser directement. `--json` affiche le résultat complet et `--headers` affiche le message avec les en-têtes `X-Spam-*` ajoutés.

Les messages peuvent aussi provenir de l’entrée standard :

```sh
cat message.eml | spamscanner scan -
```


## L’utiliser depuis Node.js

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

CommonJS fonctionne aussi :

```js
const SpamScanner = require('spamscanner');
```

`scan()` prend le message brut sous forme de Buffer, de chaîne, de Uint8Array ou de flux lisible. Une chaîne est toujours le texte d’un message : Spam Scanner ne lit jamais un fichier parce qu’une chaîne ressemble à un chemin. Utilisez `scanner.scanFile(path)` pour les fichiers.


## Lui décrire la session SMTP

L’adresse IP du client, son nom d’hôte vérifié, le nom HELO et l’enveloppe rendent le résultat plus précis : l’authentification a besoin de l’adresse IP, et la règle d’usurpation de son propre domaine a besoin des destinataires.

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

La même chose en ligne de commande :

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Activer d’autres vérifications

Aucune n’est activée par défaut, car chacune nécessite un service ou une décision :

| Vérification                         | Option de la bibliothèque                        | Ligne de commande           |
| ------------------------------------ | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC                | `authentication: true`                           | `--auth`                    |
| Liste de blocage d’IP                | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Liste de blocage de domaines (liens) | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                               | `clamav: true` ou `clamav: {socket}`             | `--clamav [socket]`         |
| Un modèle de langage                 | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Listes d’autorisation et de refus    | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Les résolveurs filtrants de Cloudflare (1.1.1.2 pour les logiciels malveillants, 1.1.1.3 pour le contenu pour adultes) sont interrogés par défaut sur les hôtes des liens. Désactivez-les avec `phishing: {cloudflare: false}` ou `--no-cloudflare`. [Ce qui quitte la machine](security.md)

Spamhaus et certaines autres listes de blocage ne répondent pas aux requêtes envoyées par des résolveurs publics comme 8.8.8.8 ou 1.1.1.1. Utilisez-les avec un résolveur cache local, et vérifiez leurs conditions d’utilisation pour votre volume.


## Étapes suivantes

* Placez-le devant un serveur de messagerie : [Postfix et Sendmail](postfix.md), [autres serveurs](mail-servers.md).
* Apprenez-lui votre propre courrier : [entraînement](training.md).
* Ajoutez un modèle de langage pour les cas limites : [modèles de langage](llm.md).
