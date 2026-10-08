<!-- source: 7cc30ff4ad91 -->

# Entraînement

Le modèle fourni fonctionne dès l’installation. Un modèle entraîné sur votre propre courrier fonctionne mieux, car il apprend à quoi ressemble votre ham : vos lettres d’information, la façon d’écrire de vos collègues, les langues dans lesquelles vous recevez du courrier.


## Entraîner un modèle

Indiquez à `train` des dossiers de spam et de ham :

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Les sources peuvent être :

* des fichiers **mbox**, y compris compressés avec gzip (`.mbox.gz`),
* un **Maildir** (ses dossiers `cur` et `new` sont lus, `tmp` est ignoré),
* un **dossier** de fichiers `.eml`, lu récursivement,
* un **jeu de données** : un fichier CSV ou JSON Lines avec une colonne de texte et une colonne d’étiquette (`--dataset`). Les colonnes nommées `text`, `message`, `body`, `email` ou `content`, et `label`, `category`, `class`, `spam` ou `is_spam`, sont détectées automatiquement ; sinon, utilisez `--text-column` et `--label-column`. Les étiquettes comme `spam`, `1`, `phishing` et `ham`, `0`, `not_spam`, `legitimate` sont comprises.

Les messages en double ne sont comptés qu’une fois. Pour partir du modèle fourni plutôt que d’un modèle vide, ajoutez `--merge`.

Utilisez le modèle :

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Quelle quantité de courrier suffit : quelques centaines de messages de chaque type donnent un modèle utile, quelques milliers un bon modèle. Gardez les deux à peu près équilibrés, et gardez dans le ham le courrier que vous ne voulez pas filtrer (réinitialisations de mot de passe, factures de vos propres fournisseurs).


## Le mesurer

Gardez une partie du courrier hors de l’entraînement et mesurez le modèle sur celle-ci :

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Le modèle fourni, sur des SMS en 21 langues qu’il n’a jamais vus, la plupart dans des langues qu’il connaît à peine :

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

La précision indique quelle part de ce qu’il qualifie de spam en est vraiment ; le rappel, quelle part du spam il détecte. Les messages incertains comptent ici comme du spam manqué, alors que dans une analyse les autres vérifications et le modèle de langage peuvent encore les détecter. Le chiffre à surveiller est celui des faux positifs : du ham marqué comme spam. Dans l’exécution ci-dessus, le modèle est incertain sur la plupart de ces messages plutôt que dans l’erreur, ce qui est le comportement voulu pour les langues dans lesquelles il a vu peu de courrier.

`--json` fournit les mêmes chiffres pour les scripts.


## Apprendre des signalements

Quand les utilisateurs déplacent du courrier vers un dossier Junk ou hors de celui-ci, apprenez-le au modèle un message à la fois :

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Le premier `learn` crée le fichier à partir du modèle fourni. En HTTP, `POST /learn/spam` et `/learn/ham` de l’[API HTTP](http-api.md) font de même, et `spamc -L spam` fonctionne avec le [serveur spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) lancé avec `--allow-tell`. [L’IMAPSieve de Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) peut appeler l’un ou l’autre quand un message est déplacé.

Depuis Node.js :

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Un message signalé comme mal classé doit être désappris de la mauvaise classe avant d’être appris dans la bonne, s’il avait déjà été appris.


## Le modèle fourni

`model/classifier.json` est construit par `npm run model:train` à partir de ces jeux de données publics sur Hugging Face, tous sous licence ouverte :

| Jeu de données                                                                                                                                                                                                                                                                                                             | Licence                    | Contenu                           |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                 | Messages et e-mails en 43 langues |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Corpus de recherche public | Le corpus Enron-Spam              |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                    | Messages Telegram en russe        |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                        | Messages synthétiques             |

Il a appris à partir de 62 480 messages de spam et 76 489 messages de ham. Le script met de côté un message sur dix, entraîne sur le reste et mesure le classifieur seul, sans les autres vérifications :

| Test sur messages mis de côté | Messages | Précision | Rappel | Faux positifs | Incertains |
| ----------------------------- | -------: | --------: | -----: | ------------: | ---------: |
| Anglais                       |    6 564 |   100,0 % | 97,0 % |         0,0 % |      2,4 % |
| Russe                         |    1 682 |   100,0 % | 97,4 % |         0,0 % |      2,2 % |
| Italien                       |    1 389 |    98,1 % | 85,3 % |         1,8 % |     10,9 % |
| Allemand                      |    1 309 |    97,7 % | 76,1 % |         2,2 % |     20,7 % |
| Espagnol                      |    1 281 |    97,5 % | 82,5 % |         2,6 % |     16,8 % |
| Enron-Spam                    |    2 888 |   100,0 % | 93,1 % |         0,0 % |      4,5 % |
| all-scam-spam                 |    4 236 |   100,0 % | 88,8 % |         0,0 % |     11,2 % |
| Tout                          |   13 840 |    99,2 % | 85,1 % |         0,5 % |     12,4 % |

Le spam correspond ici à une probabilité du classifieur de 99 % ou plus, le point à partir duquel le classifieur atteint seul le seuil de spam. Dans une analyse, le spam dont il est moins sûr obtient tout de même des points, et les autres vérifications ajoutent les leurs.

Les résultats en allemand, en espagnol et en italien proviennent de jeux de données synthétiques, qui contiennent des messages presque identiques étiquetés à la fois comme spam et comme ham : une partie de cette erreur tient aux étiquettes, pas au modèle. Le courrier dans vos propres langues est la meilleure solution. Les chiffres, pour chaque langue et chaque jeu de données, figurent dans le `metadata.metrics` du modèle.

### Plus de langues

`npm run model:train -- --with multilingual-sms` ajoute la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) : la SMS Spam Collection traduite automatiquement dans 21 langues. Elle est exclue du modèle fourni car sa fiche indique une licence GPL ; vérifiez qu’elle convient à la manière dont vous partagez le modèle. Avec elle, les résultats sur les messages mis de côté, pour des langues que le modèle fourni connaît à peine, étaient les suivants :

| Langue   | Messages | Précision | Rappel | Faux positifs |
| -------- | -------: | --------: | -----: | ------------: |
| Chinois  |      430 |   100,0 % | 82,3 % |         0,0 % |
| Arabe    |      430 |   100,0 % | 84,6 % |         0,0 % |
| Coréen   |      412 |   100,0 % | 80,4 % |         0,0 % |
| Japonais |      486 |    96,0 % | 85,7 % |         0,5 % |
| Hindi    |      412 |   100,0 % | 63,9 % |         0,0 % |
| Français |      480 |    98,6 % | 94,2 % |         0,6 % |
| Turc     |      220 |   100,0 % | 73,1 % |         0,0 % |

### Le réentraîner

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Le fichier de modèle

Un modèle est un fichier JSON : le nombre de messages de spam et de ham appris et, pour chaque caractéristique hachée, le nombre de messages de spam et de ham qui la contenaient, triés et encodés en base64. Il ne contient aucun mot et aucun texte de message. `--max-features` ne conserve que les caractéristiques les plus fréquentes et `--min-count` écarte les plus rares, échangeant de la précision contre de la taille ; le modèle fourni conserve 400 000 caractéristiques en 6 Mo environ.

Les modèles de Spam Scanner 6 et antérieurs ne peuvent pas être chargés : ils hachaient d’autres caractéristiques. Entraînez-en un nouveau à partir du même courrier.
