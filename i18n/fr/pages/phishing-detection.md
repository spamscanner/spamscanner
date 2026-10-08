<!-- source: 0378a5e0f12b -->

<!--
label: Détection de l’hameçonnage
title: Détection du phishing : domaines sosies, liens piégés, usurpation
description: Comment Spam Scanner détecte l’hameçonnage : domaines sosies Unicode, liens trompeurs, marques dans les noms d’affichage, résolveur de Cloudflare et DMARC.
keywords: détection de phishing, détection d’hameçonnage, filtre anti-phishing e-mail, attaque par homographe, homographe IDN, détection de domaines sosies, lien trompeur, usurpation de marque e-mail
-->

# Détection de l’hameçonnage dans les e-mails

L’hameçonnage fonctionne en se faisant passer pour quelqu’un d’autre. Spam Scanner vérifie les endroits où le déguisement se voit.


## Domaines sosies

Chaque domaine d’un lien est réduit à un squelette à l’aide de la table Unicode des caractères confusables, puis comparé à près de 100 marques couramment usurpées :

| Domaine                             | Détecté comme                               |
| ----------------------------------- | ------------------------------------------- |
| `pаypal.com` (а cyrillique)         | Caractères confusables                      |
| `paypa1-secure.top`                 | Caractères intervertis                      |
| `xn--pple-43d.com`                  | Punycode pour `аpple.com`                   |
| `paypal.com.account-verify.example` | Marque dans le domaine de quelqu’un d’autre |
| `paypall.com`                       | À une lettre près                           |

Des marques peuvent être ajoutées, et les domaines qui vous appartiennent peuvent être mis sur liste d’autorisation.


## Liens trompeurs

Un lien HTML dont le texte est une adresse et la cible une autre, par exemple le texte `https://www.paypal.com/signin` pointant vers `http://paypa1-secure.top/login`, ajoute 3 points.


## Noms d’affichage et usurpation

* Un nom d’affichage contenant une marque (« PayPal Security ») associé à une adresse d’un autre domaine.
* Un nom d’affichage contenant une autre adresse e-mail.
* Un courrier qui prétend venir du propre domaine du destinataire et qui échoue à SPF, DKIM et DMARC.


## Sites malveillants connus

Les hôtes des liens sont interrogés sur le résolveur 1.1.1.2 de Cloudflare, qui bloque les sites de logiciels malveillants et d’hameçonnage connus, et éventuellement sur des listes de blocage de domaines comme Spamhaus DBL.


## Pièces jointes

L’hameçonnage arrive aussi sous forme de pièces jointes HTML qui affichent hors ligne une fausse page de connexion, et d’exécutables renommés en `.pdf`. Les deux sont repérés d’après leur contenu.

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

[Fonctionnement des vérifications](../../docs/how-it-works.md#phishing)
