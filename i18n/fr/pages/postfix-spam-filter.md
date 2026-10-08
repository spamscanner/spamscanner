<!-- source: f33722183f00 -->

<!--
label: Antispam Postfix
title: Filtre antispam Postfix avec un milter ou un filtre de contenu
description: Filtrez le spam sur Postfix avec le milter ou le filtre de contenu de Spam Scanner : installation, unité systemd, rejet en 4xx ou 5xx, dossier Junk.
keywords: antispam Postfix, filtre antispam Postfix, milter Postfix, smtpd_milters, content_filter Postfix, rejeter le spam Postfix
-->

# Filtre antispam Postfix

Spam Scanner filtre un serveur Postfix en cinq minutes environ. Il fonctionne comme milter : Postfix l’interroge sur chaque message pendant la session SMTP et peut refuser le spam avant de l’accepter.


## Installer et lancer

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` vérifie SPF, DKIM, DMARC et ARC ; `--subject-tag` marque le spam dans l’objet. Chaque message reçoit les en-têtes `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` et `X-Spam-Action`, et tout en-tête `X-Spam-*` ajouté par l’expéditeur est d’abord supprimé.


## Raccorder Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` laisse passer le courrier sans filtrage si le milter est arrêté ; `tempfail` demande plutôt aux expéditeurs de réessayer.


## Refuser le spam pendant la session SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

Les messages au seuil de rejet (15 points) sont refusés avec `451 4.7.1 Message rejected as spam`. Un 451 est temporaire : l’expéditeur conserve le message et réessaie ; une mauvaise décision coûte donc un délai, pas un message perdu. Une fois que les résultats semblent corrects, `--reject-code 550` rend le refus définitif.


## Sans milter

Un filtre de contenu s’exécute après que Postfix a accepté un message : Postfix le transmet par un pipe à `spamscanner filter`, qui ajoute des en-têtes et le lui rend. Rien n’est jamais refusé pendant la session, et un échec diffère toujours la distribution au lieu de renvoyer le message à l’expéditeur. [Configuration du filtre de contenu](../../docs/postfix.md#content-filter)


## Le spam dans Junk

Avec Dovecot, une règle Sieve range le courrier marqué :

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Testé avec un vrai Postfix

Les tests de bout en bout du projet font tourner Postfix avec le milter et le filtre de contenu : le ham est distribué avec des en-têtes et un `X-Spam-Flag` falsifié supprimé, le spam est marqué, et GTUBE est refusé avec un 550 pendant la session SMTP.

Ensuite : [le guide complet Postfix et Sendmail](../../docs/postfix.md), avec une unité systemd et le `INPUT_MAIL_FILTER` de Sendmail.
