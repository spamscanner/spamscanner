<!-- source: 988243aec4f3 -->

<!--
label: Filtre antispam auto-hébergé
title: Filtre antispam auto-hébergé pour votre propre serveur de messagerie
description: Un filtre antispam sur votre propre serveur. Spam Scanner garde le courrier sur la machine, inclut son modèle dans le paquet, n’envoie aucune télémétrie et s’intègre à Postfix ou Exim.
keywords: filtre antispam auto-hébergé, filtre antispam sur site, filtre antispam privé, filtre antispam local, filtre antispam pour serveur de messagerie, antispam sans cloud
-->

# Filtre antispam auto-hébergé

Spam Scanner fonctionne sur votre propre serveur et y garde le courrier. Le modèle du classifieur est inclus dans le paquet, il n’y a ni télémétrie ni vérification de mises à jour, et par défaut la seule chose qu’il envoie est une requête DNS pour le nom d’hôte de chaque lien.


## Ce qui quitte le serveur

Par défaut, seulement les noms d’hôte des liens d’un message. Ils sont recherchés sur les résolveurs filtrants de Cloudflare (1.1.1.2 et 1.1.1.3) par des requêtes DNS ordinaires, et aucune partie du message ni de ses adresses n’est envoyée. `--no-cloudflare` désactive aussi cela.

Tout autre contrôle qui utilise le réseau reste désactivé jusqu’à ce que vous l’activiez :

| Contrôle              | Pour l’activer       | Ce qu’il envoie                                                   |
| --------------------- | -------------------- | ----------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | Des requêtes DNS sur les enregistrements de l’expéditeur          |
| Listes de blocage DNS | `--dnsbl`, `--uribl` | L’adresse IP du client et les domaines des liens, en requêtes DNS |
| ClamAV                | `--clamav`           | Les pièces jointes, à votre propre clamd                          |
| Un modèle de langage  | `--llm`              | Un résumé du message, au serveur que vous indiquez                |

Les analyses ne sont ni journalisées ni conservées. [Sécurité et confidentialité](../../docs/security.md)


## Installer sur un serveur

```sh
npm install --global spamscanner
```

Ou le binaire autonome, avec Node.js et le modèle intégrés :

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Le script d’installation vérifie le binaire avec le fichier `SHA256SUMS` de la version avant de l’installer, et chaque binaire a une attestation de provenance de build signée que `gh attestation verify` contrôle. Les binaires couvrent Linux (x64 et arm64), macOS et Windows. Les binaires Linux ont besoin de glibc : sur Alpine, installez avec npm. [Premiers pas](../../docs/getting-started.md)

Il n’y a pas de vérification de mises à jour. Pour mettre à jour, relancez la commande d’installation : les deux commandes installent la dernière version.


## Le faire tourner comme service

Les serveurs milter, HTTP, TCP et spamd écoutent sur 127.0.0.1 sauf si `--host` indique autre chose. Faites-les tourner sous un utilisateur sans privilèges, par exemple avec systemd :

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

L’[unité complète et sa mise en place](../../docs/postfix.md#1-run-the-milter) se trouvent dans le guide Postfix. Aucun des serveurs ne parle TLS : pour en joindre un depuis une autre machine, utilisez un réseau privé, un tunnel SSH ou un proxy inverse avec TLS.


## Connecter votre serveur de messagerie

| Serveur de messagerie                     | Commande                                   | Port  |
| ----------------------------------------- | ------------------------------------------ | ----- |
| Postfix ou Sendmail                       | `spamscanner milter`                       | 7831  |
| Postfix, sans jamais refuser de courrier  | `spamscanner filter`, un filtre de contenu | aucun |
| Exim, Haraka ou spamc                     | `spamscanner spamd`                        | 783   |
| Tout ce qui parle HTTP                    | `spamscanner http`                         | 7832  |
| Un client TCP simple                      | `spamscanner server`                       | 7830  |
| Un serveur de messagerie écrit en Node.js | `import SpamScanner from 'spamscanner'`    | aucun |

Les serveurs peuvent ajouter au message les en-têtes `X-Spam-Flag`, `X-Spam-Score` et `X-Spam-Status`, et la bibliothèque renvoie le score et chaque test déclenché. Guides : [filtre antispam Postfix](/postfix-spam-filter/), [autres serveurs de messagerie](../../docs/mail-servers.md) et [l’API HTTP](../../docs/http-api.md).


## Garder les modèles de langage en local

Un modèle de langage est facultatif et ne lit que les cas limites : le spam évident et le ham évident ne l’atteignent jamais. Avec Ollama, il tourne sur le même serveur, si bien qu’aucun message ne le quitte :

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` tourne sur un CPU. Avec un fournisseur hébergé, les données personnelles sont retirées du message avant l’envoi. [Modèles de langage](../../docs/llm.md)


## L’entraîner sur votre propre courrier

Le modèle fourni est entraîné sur des jeux de données publics. Un modèle entraîné sur le courrier que reçoit votre serveur fait mieux, et il reste sur ce serveur :

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Un fichier de modèle contient des comptes de caractéristiques hachées, pas de mots ni de texte de message. [Entraînement](../../docs/training.md)


## Prérequis

Node.js 18 ou plus récent sous Linux, macOS ou Windows, ou rien du tout avec un binaire autonome. ClamAV et Ollama sont facultatifs et tournent comme services séparés.
