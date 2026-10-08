<!-- source: 9537a0e62eb0 -->

# Langues

Le spam arrive dans toutes les langues, et le courrier ordinaire aussi. Spam Scanner lit l’un comme l’autre, et il fait preuve de prudence avec les langues qu’il connaît mal : un filtre antispam qui signale chaque message en arabe ou en chinois est pire que pas de filtre du tout.


## Lire toutes les écritures

* **Mots.** Le texte est découpé avec `Intl.Segmenter`, qui suit les règles Unicode de découpage en mots et utilise des dictionnaires pour le chinois, le japonais, le thaï, le lao, le khmer et le birman, des écritures sans espaces. Les textes longs sont d’abord découpés en morceaux, car le segmenteur de Node.js 18 ralentit sur les chaînes très longues.
* **Normalisation.** La normalisation Unicode NFKC transforme les lettres pleine chasse et la plupart des lettres stylisées (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) en lettres simples. Le texte est mis en minuscules selon les règles Unicode.
* **Déguisements.** Les caractères invisibles à l’intérieur des mots (`free` avec une espace sans chasse entre deux lettres, traits d’union conditionnels) sont retirés et comptés. Les mots qui mélangent les alphabets, comme `pаypal` avec un а cyrillique, sont ramenés à un seul alphabet et comptés. Les chiffres utilisés comme lettres (`v1agra`) sont convertis. Chaque déguisement est une caractéristique à part entière, et trois caractères invisibles ou plus, ou deux mots mélangés ou plus, ajoutent aussi des points.


## Détecter la langue

La langue de chaque message est détectée d’après son écriture et, pour les écritures partagées par de nombreuses langues, d’après ses lettres :

* Le hangeul désigne le coréen ; les hiragana et les katakana, le japonais ; le thaï, le grec, l’hébreu, l’arménien, le géorgien, le bengali, le tamoul et les autres écritures propres à une seule langue la désignent directement.
* Les lettres cyrilliques propres à une seule langue permettent de trancher entre l’ukrainien (і, ї, є, ґ), le biélorusse (ў), le serbe (ђ, ћ, џ), le macédonien (ѓ, ќ, ѕ) et le russe (ы, э, ё).
* Le texte dans une écriture partagée par plusieurs langues (latin, cyrillique, arabe, devanagari et d’autres), s’il est assez long pour en juger, est confié à [franc](https://github.com/wooorm/franc), limité aux langues courantes dans le courrier électronique afin que les messages courts ne soient pas étiquetés avec des langues rares.

La langue est indiquée dans `result.language`, et `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) ajoute 3 points au courrier détecté avec certitude dans toute autre langue.


## Les langues que le modèle connaît mal

Un classifieur apprend à partir d’exemples. Les jeux de données publics de spam contiennent beaucoup plus de spam en langue étrangère que de ham en langue étrangère : un classifieur naïf apprend donc qu’un texte chinois ou arabe signifie en soi du spam. Spam Scanner corrige cela de trois manières :

1. **La langue n’est jamais une preuve.** La langue et l’écriture détectées ne sont pas utilisées comme indices.
2. **Les mots sont pesés au sein de leur langue.** La probabilité de spam d’un mot est calculée par rapport au nombre de messages de spam et de ham que le classifieur a vus dans la langue du message, et non dans toutes les langues. Un mot portugais courant, dans un modèle qui a vu surtout du spam portugais, reste neutre.
3. **La confiance suit la couverture.** Le résultat est ramené vers « incertain » en proportion du nombre de messages de chaque type que le classifieur a vus dans cette langue : la confiance totale exige 1 000 messages de chaque (ou 2 % de la plus petite classe, pour les petits modèles personnels). Une langue sans aucun ham dans les données d’entraînement obtient toujours « incertain ».

Le modèle fourni n’a jamais vu la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), des SMS traduits automatiquement dans 21 langues. Avant ces règles, il marquait comme spam 5,7 % de ce ham, dont 55 % du portugais et 41 % du français. Avec elles, 0,18 % : aucun en chinois, arabe, coréen, japonais, hindi, portugais, français ou dans 20 autres langues, et 0,27 % en anglais.


## Détecter le spam dans ces langues

« Incertain » est sans danger, mais n’arrête pas le spam. Trois choses le font :

* **Les autres vérifications** ne dépendent pas de la langue : domaines sosies, liens trompeurs, exécutables, macros, authentification, listes de blocage, règles.
* **Un modèle de langage.** Les modèles ouverts modernes lisent de 100 à 200 langues, et Spam Scanner en consulte un chaque fois que le classifieur est incertain. Les tests de bout en bout vérifient que `qwen3.5:4b` détecte le spam et laisse passer le ham en chinois, arabe, coréen, hindi et thaï. [Modèles de langage](llm.md)
* **L’entraînement sur votre courrier.** Dans un modèle entraîné sur votre propre courrier, quelques centaines de messages de chaque type dans une langue donnent au classifieur une confiance totale dans cette langue. [Entraînement](training.md), et [un jeu de données facultatif](training.md#more-languages) qui ajoute 21 langues.
