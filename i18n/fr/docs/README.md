<!-- source: 8860e232d858 -->

# Documentation de Spam Scanner

Spam Scanner est un filtre antispam pour Node.js et la ligne de commande, dont le code source est sur GitHub. Il lit un message électronique brut et détermine s’il s’agit de spam, d’hameçonnage (phishing), d’une arnaque ou s’il contient un logiciel malveillant, dans n’importe quelle langue. Il fonctionne comme bibliothèque, outil en ligne de commande, milter Postfix ou Sendmail, filtre de contenu Postfix, serveur spamd compatible avec SpamAssassin, API HTTP ou serveur TCP.

Il est développé par [Forward Email](https://forwardemail.net) pour ses propres serveurs de messagerie.


## Comment un message est évalué

Chaque vérification ajoute ou retire des points. Le total détermine le résultat :

| Score       | Action   | Ce que fait un serveur de messagerie |
| ----------- | -------- | ------------------------------------ |
| Moins de 5  | `accept` | Distribue le message                 |
| De 5 à 14,9 | `tag`    | Le distribue marqué comme spam       |
| 15 et plus  | `reject` | Le refuse pendant la session SMTP    |

Les deux seuils sont modifiables. Chaque résultat liste les tests déclenchés, avec leurs points et une raison : une décision peut donc toujours être expliquée.

Les vérifications :

* **Un classifieur entraîné** lit les mots du message dans n’importe quelle écriture, la forme de ses liens, son expéditeur et ses pièces jointes. Il est livré entraîné sur des jeux de données publics et apprend de votre propre courrier. [Fonctionnement du classifieur](how-it-works.md#the-classifier)
* **La détection de l’hameçonnage** repère les domaines sosies (`paypa1.com`, `pаypal.com` avec un а cyrillique), les liens dont le texte affiche une adresse et dont la cible en est une autre, et les noms d’affichage qui se réclament d’une marque. [Hameçonnage](how-it-works.md#phishing)
* **La vérification des pièces jointes** repère les exécutables, les exécutables renommés en documents, les doubles extensions, les astuces de nom de fichier écrit de droite à gauche, les exécutables dans des fichiers ZIP, les macros Office et le contenu PDF actif. ClamAV peut analyser les pièces jointes à la recherche de virus. [Pièces jointes](how-it-works.md#attachments)
* **Authentification** : SPF, DKIM, DMARC et ARC, quand l’adresse IP du client est connue. [Authentification](how-it-works.md#authentication)
* **Des listes de blocage DNS** pour l’adresse IP du client et les domaines des liens, et les résolveurs filtrants de Cloudflare pour les logiciels malveillants et les sites pour adultes connus. [Listes de blocage](how-it-works.md#blocklists)
* **Des règles** pour les motifs qu’aucun classifieur n’a besoin d’apprendre : la chaîne de test GTUBE, les objets de sextorsion, les arnaques aux factures PayPal, l’usurpation de son propre domaine et les instructions cachées à destination des filtres d’IA. [Règles](scoring.md#rules)
* **Un modèle de langage**, facultatif, donne un second avis sur les cas limites : un modèle local via Ollama ou tout serveur compatible OpenAI, un modèle de décision comme Clef de Cloudflare, ou bien Claude, ChatGPT, Gemini et d’autres. Par défaut, il renvoie une probabilité pour chaque verdict en une seule étape au lieu de rédiger une réponse. [Modèles de langage](llm.md)


## Par où commencer

* [Prise en main](getting-started.md) : l’installer et analyser un premier message.
* [Ligne de commande](cli.md) : toutes les commandes et options.
* [Postfix et Sendmail](postfix.md) : filtrer un serveur de messagerie avec le milter ou un filtre de contenu.
* [Autres serveurs de messagerie](mail-servers.md) : Exim, Haraka, Dovecot, procmail et tout ce qui peut appeler une API HTTP.
* [Entraînement](training.md) : lui apprendre votre propre courrier et mesurer le résultat.
* [Modèles de langage](llm.md) : décision et génération, précision et vitesse mesurées, modèles de décision, fournisseurs, modèles ouverts recommandés, confidentialité et injection de prompt.
* [Langues](languages.md) : comment il lit le chinois, l’arabe, le thaï et toutes les autres écritures.
* [Forward Email](forward-email.md) : comment Forward Email l’utilise, et la mise à niveau depuis la version 5 ou 6.
* [Référence de l’API](api.md) et [tests et scores](scoring.md).
* [Sécurité et confidentialité](security.md) : ce qui quitte la machine, et comment l’empêcher.
