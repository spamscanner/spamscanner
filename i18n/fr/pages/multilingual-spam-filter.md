<!-- source: 0ad167ddd34e -->

<!--
label: Filtre antispam multilingue
title: Antispam multilingue : chinois, arabe, russe, toutes écritures
description: Comment Spam Scanner filtre le spam dans toutes les langues : segmentation Unicode, déguisements neutralisés, aucune alerte pour une langue mal connue.
keywords: filtre antispam multilingue, antispam chinois, antispam arabe, antispam russe, antispam japonais, détection de spam Unicode, spam homoglyphes
-->

# Filtre antispam multilingue

Beaucoup de filtres antispam ont été conçus pour l’anglais. Le spam dans d’autres langues leur échappe, et le courrier ordinaire dans d’autres langues est signalé à cause de son écriture. Spam Scanner est conçu pour éviter les deux.


## Lire les mots

Les mots sont repérés avec `Intl.Segmenter`, les règles Unicode de découpage en mots avec des dictionnaires pour le chinois, le japonais, le thaï, le lao, le khmer et le birman. Une phrase chinoise devient des mots comme 恭喜, 获得 et 大奖, et non une seule longue chaîne qui ne se répète jamais.

Les déguisements sont neutralisés avant le comptage : caractères invisibles à l’intérieur des mots, lettres cyrilliques ou grecques dans des mots latins (`pаypal`), chiffres à la place de lettres (`v1agra`), et lettres mathématiques ou cerclées (𝐅𝐑𝐄𝐄). Chaque déguisement est aussi un indice à part entière.


## Ne pas signaler ce qu’il ne connaît pas

Les jeux de données publics de spam contiennent beaucoup plus de spam en langue étrangère que de ham en langue étrangère : un classifieur naïf apprend donc qu’un texte arabe ou coréen est en soi du spam. Spam Scanner n’utilise jamais la langue comme indice, pèse chaque mot par rapport aux décomptes de spam et de ham de sa propre langue, et reste « incertain » d’autant plus qu’il a vu peu de ham dans une langue.

Lors d’un test sur des SMS en 21 langues que le modèle fourni n’avait jamais vus, cela a ramené à zéro ses faux positifs en chinois, arabe, coréen, japonais, hindi, bengali, ourdou, turc, ukrainien et suédois.


## Détecter le spam dans toutes les langues

* **Des vérifications qui ne lisent pas les mots :** domaines sosies, liens trompeurs, exécutables, macros, SPF, DKIM, DMARC et listes de blocage.
* **Un modèle de langage** pour les messages incertains. Les modèles ouverts comme Qwen 3.5 et Gemma 4 lisent de 140 à 200 langues ; les tests de bout en bout vérifient le spam et le ham en chinois, arabe, coréen, hindi et thaï avec un vrai modèle.
* **Votre propre courrier.** Quelques centaines de messages de chaque type dans une langue donnent à un modèle entraîné sur votre courrier une confiance totale dans cette langue.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Pour n’accepter que certaines langues, `--allow-language en,de` ajoute des points au courrier détecté avec certitude dans toute autre langue.

[Les langues en détail](../../docs/languages.md)
