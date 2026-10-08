<!-- source: c93fa1a3f9c7 -->

<!--
label: FAQ
title: Questions fréquentes
description: Réponses sur Spam Scanner : sa précision, les langues prises en charge, ce qu’il envoie sur le réseau, les modèles de langage, SpamAssassin et Forward Email.
keywords: FAQ Spam Scanner, questions filtre antispam, précision filtre antispam, confidentialité filtre antispam
-->

# Questions fréquentes


## Qu’est-ce que Spam Scanner ?

Un filtre antispam pour Node.js, la ligne de commande et les serveurs de messagerie. Il lit un message électronique brut et détermine s’il s’agit de spam, d’hameçonnage, d’une arnaque ou s’il contient un logiciel malveillant, avec un score et la liste des tests qui ont décidé. Il fonctionne comme bibliothèque, milter pour Postfix et Sendmail, serveur spamd compatible avec SpamAssassin, filtre de contenu Postfix, API HTTP ou serveur TCP.


## Est-il gratuit ?

Sa [licence](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), la Business Source License 1.1, autorise toute utilisation sauf la fourniture de détection de spam en tant que service à des tiers, et indique la date à laquelle elle devient la licence Apache 2.0.


## Quelle est sa précision ?

Sur des messages en anglais mis de côté parmi ses données d’entraînement, le classifieur fourni, seul, n’a marqué aucun ham comme spam et a détecté 97 % du spam ; les chiffres complets par langue figurent dans le [guide d’entraînement](../../docs/training.md#the-bundled-model). Les liens, les pièces jointes, l’authentification, les listes de blocage et un modèle de langage s’y ajoutent. Votre propre courrier est le vrai test : `spamscanner eval` mesure n’importe quel modèle sur n’importe quel courrier étiqueté.


## Quelles langues prend-il en charge ?

Toutes. Il segmente les mots selon les règles Unicode, y compris en chinois, en japonais et en thaï, qui n’ont pas d’espaces. Quand le modèle fourni a vu peu de courrier dans une langue, il reste incertain plutôt que de signaler le message, et c’est un modèle de langage ou votre propre entraînement qui décide. [Langues](../../docs/languages.md)


## Envoie-t-il mon courrier quelque part ?

Non. Par défaut, il interroge les résolveurs DNS filtrants de Cloudflare sur les noms d’hôte des liens, et rien d’autre ne quitte la machine. L’authentification, les listes de blocage, les modèles de langage et les services de réputation sont désactivés tant qu’ils ne sont pas configurés, et les données personnelles sont retirées avant que le courrier soit envoyé à un modèle de langage hébergé. [Sécurité et confidentialité](../../docs/security.md)


## Ai-je besoin d’un modèle de langage ?

Non. C’est un second avis pour les cas limites. Sans modèle, ces messages sont tranchés par leur seul score.


## Quel modèle de langage utiliser ?

`qwen3.5:4b` via Ollama sur un processeur, ou `qwen3.5:9b` avec un GPU. Les deux sont sous licence Apache et lisent 201 langues. Les modèles hébergés d’Anthropic, d’OpenAI, de Google et d’autres fonctionnent aussi. [Modèles recommandés](../../docs/llm.md#recommended-open-models)


## Peut-il remplacer SpamAssassin ?

Pour la plupart des installations, oui : il parle le protocole de spamd, donc spamc, Exim et Haraka fonctionnent sans modification, et il écrit les mêmes en-têtes `X-Spam-*`. Il n’exécute pas les fichiers de règles de SpamAssassin. [Alternative à SpamAssassin](/spamassassin-alternative/)


## Va-t-il rejeter du courrier légitime ?

Le refus du courrier est désactivé par défaut : le milter se contente de marquer. Avec `--reject`, seuls les messages qui obtiennent 15 points ou plus sont refusés, avec une erreur temporaire 451 : les expéditeurs réessaient et une erreur peut être corrigée en modifiant un réglage. Le filtre de contenu ne refuse jamais rien pendant la session SMTP.


## Comment l’entraîner sur mon courrier ?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, puis `--model model.json`. Les fichiers mbox, les Maildirs, les dossiers de fichiers `.eml` et les jeux de données CSV ou JSON Lines fonctionnent tous. [Entraînement](../../docs/training.md)


## Fonctionne-t-il sans Node.js ?

Oui : des binaires autonomes pour Linux, macOS et Windows incluent Node.js et le modèle. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Qui le développe ?

[Forward Email](https://forwardemail.net), pour ses propres serveurs de messagerie.
