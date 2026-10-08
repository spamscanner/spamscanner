<!-- source: c061da9312ad -->

# Ligne de commande

```text
spamscanner <command> [options]
```

| Commande                                   | Ce qu’elle fait                                                                              |
| ------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Analyse un message depuis un fichier ou l’entrée standard                                    |
| `filter -f <sender> -- <recipients...>`    | Filtre de contenu Postfix : analyse l’entrée standard, ajoute des en-têtes, la transmet      |
| `milter`                                   | Milter pour Postfix et Sendmail, port 7831                                                   |
| `http`                                     | API HTTP, port 7832                                                                          |
| `server`                                   | Serveur TCP simple, port 7830                                                                |
| `spamd`                                    | Serveur spamd compatible avec SpamAssassin, port 783                                         |
| `train`                                    | Entraîne un modèle à partir de fichiers mbox, de Maildirs, de dossiers ou de jeux de données |
| `eval`                                     | Mesure un modèle sur du courrier étiqueté                                                    |
| `learn spam\|ham [file\|-] --model <file>` | Apprend un message à un modèle                                                               |
| `llm-test`                                 | Vérifie les réglages du modèle de langage avec trois messages d’exemple                      |
| `models`                                   | Liste les modèles ouverts recommandés                                                        |
| `version`, `help`                          |                                                                                              |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Option                     | Signification                                                              |
| -------------------------- | -------------------------------------------------------------------------- |
| `--json`                   | Affiche le résultat complet en JSON                                        |
| `--headers`                | Affiche le message avec les en-têtes `X-Spam-*` ajoutés                    |
| `--subject-tag <tag>`      | Ajoute aussi un préfixe à l’objet du spam                                  |
| `--verbose`                | Affiche chaque test, et les indices les plus forts du classifieur          |
| `--threshold <n>`          | Score à partir duquel le courrier est du spam (5 par défaut)               |
| `--reject-threshold <n>`   | Score à partir duquel le courrier est rejeté (15 par défaut)               |
| `--model <file>`           | Un fichier de modèle à la place du modèle fourni                           |
| `--no-classifier`          | N’utilise pas le classifieur                                               |
| `--config <file>`          | Un fichier JSON contenant des [options de la bibliothèque](api.md#options) |
| `--allow-language <codes>` | Langues acceptées, par exemple `en,de,fr`                                  |

Codes de sortie : 0 ham, 1 spam, 2 erreur.

### Session SMTP

| Option              | Signification                                          |
| ------------------- | ------------------------------------------------------ |
| `--ip <address>`    | Adresse IP du client qui a envoyé le message           |
| `--hostname <name>` | Nom DNS inverse vérifié du client                      |
| `--helo <name>`     | Le nom qu’il a donné dans HELO ou EHLO                 |
| `--from <address>`  | Expéditeur de l’enveloppe (MAIL FROM)                  |
| `--to <address>`    | Destinataire de l’enveloppe ; à répéter pour plusieurs |

### Vérifications

| Option                | Signification                                                                           |
| --------------------- | --------------------------------------------------------------------------------------- |
| `--auth`              | Vérifie SPF, DKIM, DMARC et ARC (nécessite `--ip`)                                      |
| `--dnsbl <zone>`      | Liste de blocage d’IP, par exemple `zen.spamhaus.org` ; répétable                       |
| `--uribl <zone>`      | Liste de blocage de domaines pour les liens, par exemple `dbl.spamhaus.org` ; répétable |
| `--dns-server <ip>`   | Serveur de noms pour les vérifications DNS ; répétable                                  |
| `--no-cloudflare`     | N’interroge pas les résolveurs filtrants de Cloudflare sur les liens                    |
| `--clamav [socket]`   | Analyse les pièces jointes avec clamd, sur son socket par défaut ou celui indiqué       |
| `--allowlist <value>` | Accepte toujours cette adresse IP, ce domaine ou cette adresse ; répétable              |
| `--denylist <value>`  | Rejette toujours cette adresse IP, ce domaine ou cette adresse ; répétable              |

### Modèle de langage

| Option                                                     | Signification                                                                                                                                                                   |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` et d’autres ([liste](llm.md#providers))                                                                                    |
| `--llm-model <name>`                                       | Modèle, par exemple `qwen3.5:4b` ou `claude-haiku-4-5`                                                                                                                          |
| `--llm-method <method>`                                    | `decision` (une probabilité pour chaque verdict, en une seule étape ; la valeur par défaut quand elle est disponible) ou `generate` ([méthodes](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | Identifiant de compte Cloudflare, pour `clef` et `clef-flash`                                                                                                                   |
| `--llm-url <url>`                                          | URL de base, par exemple `http://10.0.0.5:11434`                                                                                                                                |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Modifie une partie de l’URL du fournisseur                                                                                                                                      |
| `--llm-api-key <key>`                                      | Clé d’API ; voir aussi les variables d’environnement ci-dessous                                                                                                                 |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` ou `none`                                                                                                                   |
| `--llm-auth-header <name>`                                 | En-tête portant la clé, avec `--llm-auth header`                                                                                                                                |
| `--llm-username`, `--llm-password`                         | Pour `--llm-auth basic`                                                                                                                                                         |
| `--llm-header "Name: value"`                               | En-tête de requête supplémentaire ; répétable                                                                                                                                   |
| `--llm-mode <mode>`                                        | `auto` (cas limites uniquement, par défaut) ou `always`                                                                                                                         |
| `--llm-timeout <ms>`                                       | 30000 par défaut                                                                                                                                                                |
| `--llm-policy <text>`                                      | Règles supplémentaires pour le modèle, par exemple « Nous n’envoyons jamais de factures »                                                                                       |
| `--llm-redact`, `--no-llm-redact`                          | Retire d’abord les données personnelles ; activé par défaut pour les fournisseurs distants                                                                                      |


## filter

Un [filtre de contenu Postfix](postfix.md#content-filter). Il lit un message sur l’entrée standard, ajoute les en-têtes `X-Spam-*` et le transmet à sendmail avec la même enveloppe.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Option                | Signification                                                                  |
| --------------------- | ------------------------------------------------------------------------------ |
| `--sendmail <path>`   | `/usr/sbin/sendmail` par défaut                                                |
| `--subject-tag <tag>` | Ajoute un préfixe à l’objet du spam                                            |
| `--reject`            | Renvoie à l’expéditeur le courrier au seuil de rejet au lieu de le transmettre |
| `--discard`           | Supprime le courrier au seuil de rejet au lieu de le transmettre               |

Les codes de sortie suivent les conventions de sendmail, que Postfix lit : 0 distribué (ou supprimé), 64 aucun destinataire indiqué, 69 rejeté comme spam (Postfix le renvoie à l’expéditeur), 75 tout autre échec, et Postfix conserve alors le message pour réessayer plus tard.


## milter, http, server et spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Le port 783 est celui qu’utilisent par défaut les clients SpamAssassin. Les ports inférieurs à 1024 nécessitent root ou la capacité `CAP_NET_BIND_SERVICE` ; utilisez un autre port, comme `--port 7833`, et indiquez-le au client.

| Option                | Signification                                                                   |
| --------------------- | ------------------------------------------------------------------------------- |
| `--port <n>`          | Port TCP                                                                        |
| `--host <ip>`         | Adresse d’écoute (127.0.0.1 par défaut)                                         |
| `--socket <path>`     | Écoute plutôt sur un socket Unix                                                |
| `--reject`            | Milter : refuse le courrier au seuil de rejet                                   |
| `--reject-code <n>`   | Milter : 451, réessayer plus tard (par défaut), ou 550                          |
| `--quarantine`        | Milter : place le spam dans la quarantaine du serveur de messagerie             |
| `--name <hostname>`   | Milter : le nom de ce serveur dans Authentication-Results                       |
| `--token <secret>`    | HTTP : exige `Authorization: Bearer <secret>` ; nécessaire pour `/learn`        |
| `--allow-tell`        | spamd : accepte les requêtes TELL (`spamc -L spam`) pour apprendre              |
| `--out <file>`        | HTTP et spamd : enregistre ce qui est appris dans ce fichier de modèle          |
| `--subject-tag <tag>` | Milter et spamd : ajoute un préfixe à l’objet du spam                           |
| `--verbose`           | Milter : journalise chaque analyse. Serveur TCP : répond par une ligne de texte |

Les options d’analyse ci-dessus s’appliquent aussi aux serveurs. [Le milter](postfix.md#milter), [l’API HTTP, le serveur TCP et spamd](http-api.md).


## train, eval et learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Option                                          | Signification                                                                      |
| ----------------------------------------------- | ---------------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam : un fichier mbox, un Maildir ou un dossier de fichiers `.eml` ; répétable    |
| `--ham <path>`                                  | Ham, de la même manière ; répétable                                                |
| `--dataset <file>`                              | Un fichier CSV ou JSON Lines avec des colonnes de texte et d’étiquette ; répétable |
| `--text-column <name>`, `--label-column <name>` | Noms des colonnes, quand ils ne sont pas détectés                                  |
| `--out <file>`                                  | Où écrire le modèle (`spamscanner-model.json` par défaut)                          |
| `--merge`                                       | Part du modèle fourni (ou de `--model`) au lieu d’un modèle vide                   |

`learn` met à jour le fichier de modèle sur place, en le créant à partir du modèle fourni la première fois. [Entraînement](training.md)


## llm-test et models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` envoie au modèle un message ordinaire et deux arnaques, en anglais et en italien, affiche ses verdicts, le temps pris par chacun, la méthode utilisée et le matériel, et ne sort avec le code 0 que si les trois sont corrects.


## Fichier de configuration

`--config file.json` (ou la variable d’environnement `SPAMSCANNER_CONFIG`) charge des [options de la bibliothèque](api.md#options). Les options de la ligne de commande ont priorité sur le fichier.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Variables d’environnement

| Variable                                                                                                                                                                                                                                                                                                                    | Signification                                         |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                        | Fichier de configuration                              |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                         | Fichier de modèle utilisé à la place du modèle fourni |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                         | Jeton pour l’API HTTP                                 |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                   | Clé d’API pour tout fournisseur de modèle de langage  |
| `CLOUDFLARE_API_TOKEN` et `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | La clé propre à chaque fournisseur                    |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                   | Journalisation de débogage                            |
