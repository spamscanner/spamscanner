<!-- source: c4f8c2c7aa5a -->

# Entraînement

Le modèle fourni fonctionne dès l’installation. Un modèle entraîné sur votre propre courrier fonctionne mieux, car il apprend à quoi ressemble votre ham : vos lettres d’information, la façon d’écrire de vos collègues, les langues dans lesquelles vous recevez du courrier.


## Entraîner un modèle

Indiquez à `train` des dossiers de spam et de ham :

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Les sources peuvent être :

* des fichiers **mbox**, y compris compressés avec gzip (`.mbox.gz` ; les autres fichiers `.gz` sont ignorés),
* un **Maildir** (ses dossiers `cur` et `new` sont lus, `tmp` est ignoré),
* un **dossier** de fichiers `.eml`, lu récursivement,
* un **jeu de données** : un fichier CSV ou JSON Lines avec une colonne de texte et une colonne d’étiquette (`--dataset`). Les colonnes, ou champs JSON, nommées `text`, `message`, `body`, `email text`, `email`, `content`, `sms` ou `v2`, et `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` ou `labels`, quelle que soit la casse, sont détectées automatiquement (en JSON Lines, `label_text` avant `label`) ; sinon, utilisez `--text-column` et `--label-column`. Une ligne JSON qui n’est pas un objet est ignorée. Les étiquettes comme `spam`, `1`, `phishing` et `ham`, `0`, `not_spam`, `legitimate` sont comprises.

Les messages en double ne sont comptés qu’une fois. Un message présent à la fois dans les sources de spam et de ham est conservé comme spam, car les sources de spam sont lues en premier. Pour partir du modèle fourni plutôt que d’un modèle vide, ajoutez `--merge`.

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
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
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

| Jeu de données                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Licence                    | Contenu                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | -------------------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | Messages et e-mails en 43 langues                                                      |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Corpus de recherche public | Le corpus Enron-Spam                                                                   |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | Messages Telegram en russe                                                             |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Messages synthétiques                                                                  |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Listes de diffusion, newsletters, spam, hameçonnage et courriels de fraude             |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Messages dans 14 langues de l'Inde                                                     |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | Courriels indonésiens par catégorie                                                    |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | Le courrier d'une entreprise en espagnol                                               |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | Courrier ordinaire : factures, réservations, newsletters, promotions et avis de compte |

Le ham comprend le courrier ordinaire des entreprises et des boutiques (factures, avis de commande et de compte, newsletters, promotions), de sorte qu'un tel courrier ne passe pas à lui seul pour du spam.

Il a appris à partir de 77 564 messages de spam et 112 586 messages de ham. Le script met de côté un message sur dix, entraîne sur le reste et mesure le classifieur seul, sans les autres vérifications :

| Test sur messages mis de côté | Messages | Précision | Rappel | Faux positifs | Incertains |
| ----------------------------- | -------: | --------: | -----: | ------------: | ---------: |
| Anglais                       |    8 515 |   100,0 % | 96,4 % |         0,0 % |      2,6 % |
| Russe                         |    1 680 |   100,0 % | 97,4 % |         0,0 % |      2,3 % |
| Italien                       |    1 392 |    98,6 % | 81,0 % |         1,2 % |     12,5 % |
| Allemand                      |    1 314 |    97,8 % | 72,5 % |         2,1 % |     22,6 % |
| Espagnol                      |    2 088 |    98,5 % | 56,1 % |         0,4 % |     15,7 % |
| Enron-Spam                    |    2 888 |   100,0 % | 92,4 % |         0,0 % |      4,4 % |
| all-scam-spam                 |    4 236 |   100,0 % | 89,3 % |         0,0 % |     11,6 % |
| Tout                          |   18 967 |    99,6 % | 77,2 % |         0,2 % |     15,8 % |

Le spam correspond ici à une probabilité du classifieur de 99 % ou plus, le point à partir duquel le classifieur atteint seul le seuil de spam. Dans une analyse, le spam dont il est moins sûr obtient tout de même des points, et les autres vérifications ajoutent les leurs.

Les résultats en allemand, en espagnol et en italien proviennent de jeux de données synthétiques, qui contiennent des messages presque identiques étiquetés à la fois comme spam et comme ham : une partie de cette erreur tient aux étiquettes, pas au modèle. Le courrier dans vos propres langues est la meilleure solution. Les chiffres, pour chaque langue et chaque jeu de données, figurent dans le `metadata.metrics` du modèle.

### Plus de langues

`npm run model:train -- --with multilingual-sms` ajoute la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) : la SMS Spam Collection traduite automatiquement dans 21 langues. Elle est exclue du modèle fourni car sa fiche indique une licence GPL ; vérifiez qu’elle convient à la manière dont vous partagez le modèle. Avec elle, les résultats sur les messages mis de côté, pour des langues que le modèle fourni connaît à peine, étaient les suivants :

| Langue   | Messages | Précision | Rappel | Faux positifs |
| -------- | -------: | --------: | -----: | ------------: |
| Chinois  |      432 |   100,0 % | 86,1 % |         0,0 % |
| Arabe    |      432 |   100,0 % | 83,1 % |         0,0 % |
| Coréen   |      412 |   100,0 % | 78,3 % |         0,0 % |
| Japonais |      486 |    96,1 % | 87,5 % |         0,5 % |
| Hindi    |      494 |   100,0 % | 76,2 % |         0,0 % |
| Français |      511 |    98,7 % | 88,6 % |         0,6 % |
| Turc     |      222 |   100,0 % | 70,4 % |         0,0 % |

### Le réentraîner

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Le fichier de modèle

Un modèle est un fichier JSON : le nombre de messages de spam et de ham appris et, pour chaque caractéristique hachée, le nombre de messages de spam et de ham qui la contenaient, triés et encodés en base64. Il ne contient aucun mot et aucun texte de message. `--max-features` ne conserve que les caractéristiques les plus fréquentes et `--min-count` écarte les plus rares, échangeant de la précision contre de la taille ; le modèle fourni conserve 400 000 caractéristiques en 6 Mo environ.

Les modèles de Spam Scanner 6 et antérieurs ne peuvent pas être chargés : ils hachaient d’autres caractéristiques. Entraînez-en un nouveau à partir du même courrier.
