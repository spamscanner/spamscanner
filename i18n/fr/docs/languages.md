<!-- source: 5d22e36f3f16 -->

# Langues

Le spam arrive dans toutes les langues, et le courrier ordinaire aussi. Spam Scanner lit l’un comme l’autre, et il fait preuve de prudence avec les langues qu’il connaît mal : un filtre antispam qui signale chaque message en arabe ou en chinois est pire que pas de filtre du tout.


## Lire toutes les écritures

* **Mots.** Le texte est découpé avec `Intl.Segmenter`, qui suit les règles Unicode de découpage en mots et utilise des dictionnaires pour le chinois, le japonais, le thaï, le lao, le khmer et le birman, des écritures sans espaces. Les textes longs sont d’abord découpés en morceaux, car le segmenteur de Node.js 18 ralentit sur les chaînes très longues.
* **Normalisation.** La normalisation Unicode NFKC transforme les lettres pleine chasse et la plupart des lettres stylisées (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) en lettres simples. Le texte est mis en minuscules selon les règles Unicode.
* **Déguisements.** Les caractères invisibles à l’intérieur des mots (`free` avec une espace sans chasse entre deux lettres, ou `v1agra` avec de tels caractères autour du 1) sont retirés et comptés, mais pas ceux placés entre des chiffres, que les expéditeurs insèrent dans les numéros pour que les téléphones n’en fassent pas des liens, ni une espace sans chasse entre des lettres thaïes, laotiennes, khmères, birmanes ou tibétaines, que ceux qui écrivent ces écritures placent là où un mot se termine. Les liants (U+200C, U+200D), dont le persan, les écritures indiennes et les emoji ont besoin, ne comptent qu’entre lettres latines. Les traits d’union conditionnels, et les marques de direction, incorporations et isolats dont les textes hébreux et arabes ont besoin, sont retirés sans être comptés ; les forçages qui affichent les lettres dans un autre ordre (U+202D, U+202E) comptent dans n’importe quel texte. Les mots qui mélangent les alphabets, comme `pаypal` avec un а cyrillique, sont ramenés à l’alphabet de la plupart de leurs lettres et comptés ; une désinence casuelle russe après le nom d’une marque et une apostrophe (`iPhone'ы`) ne mélange rien. Les chiffres utilisés comme lettres (`v1agra`) sont convertis. Chaque déguisement est une caractéristique à part entière, et trois caractères invisibles ou plus, ou deux mots mélangés ou plus, ajoutent aussi des points.


## Détecter la langue

La langue de chaque message est détectée d’après son écriture et, pour les écritures partagées par de nombreuses langues, d’après ses lettres :

* Le hangeul désigne le coréen ; les hiragana et les katakana, le japonais ; le thaï, le grec, l’hébreu, l’arménien, le géorgien, le bengali, le tamoul et les autres écritures propres à une seule langue la désignent directement.
* Les lettres cyrilliques propres à une seule langue permettent de trancher entre l’ukrainien (і, ї, є, ґ), le biélorusse (ў), le serbe (ђ, ћ, џ), le macédonien (ѓ, ќ, ѕ) et le russe (ы, э, ё) dans les mots autres que les noms (les mots dont seule l’initiale est en majuscule, ailleurs qu’au début d’une phrase ou d’une ligne, pas les mots en capitales, dont les lettres ne comptent que dans un texte trop court pour le détecteur statistique : un texte bulgare qui nomme « господин Рыскулов » est bulgare), sauf si le texte contient aussi des lettres du kazakh, de l’ouzbek, du kirghiz, du tadjik, du tatar, du bachkir ou du mongol (ә, ө, ү, ұ, қ, ғ, ң, һ, ҳ, ҷ et d’autres), dont les alphabets partagent certaines de ces lettres : c’est alors le détecteur statistique qui tranche, et quand il répond par une langue slave (un texte russe ou bulgare contenant un nom ou un mot kazakh), ce sont les mots sans ces lettres, autres que les noms, qui tranchent comme ci-dessus.
* Le texte dans une écriture partagée par plusieurs langues (latin, cyrillique, arabe, devanagari et d’autres), s’il est assez long pour en juger, est confié à [franc](https://github.com/wooorm/franc), limité aux langues courantes dans le courrier électronique afin que les messages courts ne soient pas étiquetés avec des langues rares.

La langue est indiquée dans `result.language`, et `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) ajoute 3 points au courrier détecté avec certitude dans toute autre langue.


## Les langues que le modèle connaît mal

Un classifieur apprend à partir d’exemples. Les jeux de données publics de spam contiennent beaucoup plus de spam en langue étrangère que de ham en langue étrangère : un classifieur naïf apprend donc qu’un texte chinois ou arabe signifie en soi du spam. Spam Scanner corrige cela de trois manières :

1. **La langue n’est jamais une preuve.** La langue et l’écriture détectées ne sont pas utilisées comme indices.
2. **Les mots sont pesés au sein de leur langue.** La probabilité de spam d’un mot est calculée par rapport au nombre de messages de spam et de ham que le classifieur a vus dans la langue du message, et non dans toutes les langues. Un mot portugais courant, dans un modèle qui a vu surtout du spam portugais, reste neutre.
3. **La confiance suit la couverture.** Le résultat est ramené vers « incertain » en proportion du nombre de messages de chaque type que le classifieur a vus dans cette langue : la confiance totale exige 1 000 messages de chaque (ou 2 % de la plus petite classe, pour les petits modèles personnels). Une langue sans aucun ham dans les données d’entraînement obtient toujours « incertain ».

Le modèle fourni n’a jamais vu la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), des SMS traduits automatiquement dans 21 langues. Avant ces règles, il marquait comme spam 5,7 % de ce ham, dont 55 % du portugais et 41 % du français. Avec elles, 0,18 % : aucun en chinois, arabe, coréen, japonais, hindi, portugais, français ou dans 13 autres langues, et 0,27 % en anglais.


## Détecter le spam dans ces langues

« Incertain » est sans danger, mais n’arrête pas le spam. Trois choses le font :

* **Les autres vérifications** ne dépendent pas de la langue : domaines sosies, liens trompeurs, exécutables, macros, authentification, listes de blocage, règles.
* **Un modèle de langage.** Les modèles ouverts modernes lisent de 100 à 200 langues, et Spam Scanner en consulte un chaque fois que le classifieur est incertain. Les tests de bout en bout vérifient que `qwen3.5:4b` détecte le spam et laisse passer le ham en chinois, arabe, coréen, hindi et thaï. [Modèles de langage](llm.md)
* **L’entraînement sur votre courrier.** Dans un modèle entraîné sur votre propre courrier, quelques centaines de messages de chaque type dans une langue donnent au classifieur une confiance totale dans cette langue. [Entraînement](training.md), et [un jeu de données facultatif](training.md#more-languages) qui ajoute 21 langues.
