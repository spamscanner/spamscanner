<!-- source: 599bd320e55a -->

<!--
label: À propos
title: À propos de Spam Scanner, sa licence et la confidentialité
description: Qui fait Spam Scanner, comment signaler un bug ou une vulnérabilité, sa licence, et ce que ce site collecte : ni cookies ni statistiques.
keywords: à propos de Spam Scanner, Forward Email, licence Spam Scanner, BUSL-1.1, contact Spam Scanner, confidentialité Spam Scanner
-->

# À propos de Spam Scanner

Spam Scanner est un filtre antispam pour l’e-mail créé par [Forward Email](https://forwardemail.net), le service de messagerie axé sur la confidentialité, qui l’a conçu pour ses propres serveurs. Le code source, les tickets et les versions sont sur [GitHub](https://github.com/spamscanner/spamscanner), et le paquet sur [npm](https://www.npmjs.com/package/spamscanner).


## Qui le développe

L’équipe de Forward Email écrit et maintient Spam Scanner. Forward Email ne conserve aucun journal du contenu des messages ; il ne pouvait donc pas envoyer le courrier à un service de filtrage externe : le filtre devait tourner sur ses propres serveurs et expliquer chaque décision sans qu’une personne lise le courrier. [Comment Forward Email l’utilise](../../docs/forward-email.md)

Forward Email est lui aussi open source, sur [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Son fondateur a été l’un des premiers employés de DuckDuckGo.


## Contact

* **Questions, bugs et demandes de fonctionnalités :** ouvrez un ticket sur [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Vulnérabilités de sécurité :** signalez-les en privé via [le signalement de vulnérabilités de GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), pas dans des tickets publics. La même adresse figure dans [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Autres licences :** contactez [Forward Email](https://forwardemail.net).


## Conditions de licence

La [licence](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) de Spam Scanner est la Business Source License 1.1, avec l’Apache License 2.0 comme Change License. La Change Date indiquée dans la licence est passée, et depuis cette date la licence vous accorde les droits de l’Apache License 2.0.


## Confidentialité

Ce site ne dépose aucun cookie et ne charge aucune statistique, aucun traceur, aucune publicité, aucune police ni aucun script depuis d’autres sites. Chaque fichier vient de spamscanner.net.

* Le thème, la langue choisie et le serveur Mastodon vers lequel vous partagez sont enregistrés dans le stockage local de votre navigateur et ne sont envoyés nulle part.
* La vidéo ne se charge que lorsque vous la lancez.
* Les liens de partage sont de simples liens : rien de ces réseaux ne se charge avant que vous en suiviez un.
* Le site est hébergé sur GitHub Pages, et GitHub enregistre l’adresse IP de chaque visiteur à des fins de sécurité. Voir [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) et la [déclaration de confidentialité de GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Ce que le logiciel envoie

Spam Scanner n’envoie aucune télémétrie et ne vérifie pas les mises à jour. Par défaut, il recherche les noms d’hôte des liens d’un message sur les résolveurs DNS filtrants de Cloudflare, et rien d’autre ne quitte la machine. Ses autres contrôles réseau restent désactivés jusqu’à ce que vous les activiez. [Sécurité et confidentialité](../../docs/security.md)


## Versions

Les binaires autonomes sont construits par GitHub Actions à partir du dépôt public. Chaque version liste leurs empreintes dans un fichier `SHA256SUMS`, que le script d’installation vérifie, et chaque binaire porte une attestation de provenance de build signée. Les versions et leurs notes sont sur [GitHub](https://github.com/spamscanner/spamscanner/releases).
