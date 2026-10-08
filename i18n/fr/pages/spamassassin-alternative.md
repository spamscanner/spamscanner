<!-- source: 1562b843d858 -->

<!--
label: Alternative à SpamAssassin
title: Une alternative à SpamAssassin qui parle spamd
description: Remplacez spamd par Spam Scanner : spamc, Exim et Haraka fonctionnent toujours, les en-têtes X-Spam ne changent pas et toutes les langues sont gérées.
keywords: alternative à SpamAssassin, remplacer SpamAssassin, remplacement de spamd, spamc, antispam Exim, Haraka spamassassin, alternative à rspamd, X-Spam-Status
-->

# Une alternative à SpamAssassin qui parle spamd

Spam Scanner répond au protocole spamd de SpamAssassin : les logiciels écrits pour SpamAssassin l’utilisent donc sans modification, qu’il s’agisse de spamc, de la condition `spam` d’Exim, du plugin `spamassassin` de Haraka ou d’autres.


## Le mettre à la place

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

Il répond à `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` et, avec `--allow-tell`, à `TELL` pour l’apprentissage. Les tests de bout en bout du projet utilisent le propre spamc de SpamAssassin contre lui.


## Ce qui ne change pas

* Les en-têtes : `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` et `X-Spam-Status` au format de SpamAssassin ; les règles Sieve, procmail et de logiciel de messagerie existantes continuent donc de fonctionner.
* Un score avec un seuil de 5, composé de tests nommés dotés de points : `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS`, etc.
* Les scores de chaque test sont modifiables par nom de test.


## Ce qui diffère

* **Langues.** Les mots sont segmentés selon les règles Unicode : le chinois, le japonais et le thaï sont lus comme des mots et non comme une seule longue chaîne, et les déguisements comme les caractères invisibles ou les lettres cyrilliques dans des mots latins sont d’abord neutralisés.
* **Hameçonnage.** Les domaines sosies, les liens trompeurs et les noms de marque dans les noms d’affichage sont vérifiés sans règles supplémentaires.
* **Les pièces jointes** sont identifiées par leurs octets : un exécutable renommé en `.pdf` reste un exécutable.
* **Modèles de langage.** Les cas limites peuvent être confiés à un modèle local via Ollama ou à un modèle hébergé.
* **Node.js.** Un seul `npm install`, ou un binaire autonome ; aucun module Perl ni aucune mise à jour de règles à gérer.

Spam Scanner n’exécute pas les fichiers de règles de SpamAssassin, et le format de sa base bayésienne lui est propre : entraînez-le à partir du même courrier avec `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot et procmail](../../docs/mail-servers.md)
