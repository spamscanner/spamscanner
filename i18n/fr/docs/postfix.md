<!-- source: 6675649d593a -->

# Postfix et Sendmail

Spam Scanner se connecte à Postfix de deux manières :

* **Comme milter** (recommandé). Postfix l’interroge sur chaque message pendant la session SMTP, avant de l’accepter. Le spam peut être refusé par une réponse 4xx ou 5xx : c’est alors le serveur expéditeur, et non le vôtre, qui doit s’en occuper. Sendmail utilise le même protocole.
* **Comme filtre de contenu.** Postfix accepte le message et le transmet par un pipe à `spamscanner filter`, qui ajoute des en-têtes et le renvoie avec sendmail. Rien n’est jamais refusé pendant la session SMTP.

Les deux ajoutent ces en-têtes à chaque message :

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.3
X-Spam-Action: tag
```

Les en-têtes `X-Spam-*` déjà présents dans le message sont d’abord supprimés : un expéditeur ne peut donc pas marquer son propre courrier comme sain.

Un message dont une pièce jointe n’a pas pu être analysée par ClamAV peut contenir un virus : les deux le diffèrent donc (Postfix ou l’expéditeur réessaie plus tard), comme lorsqu’une analyse échoue. Avec `--on-error accept`, il est transmis avec l’en-tête `X-Spam-Virus-Scan: failed` ajouté.


## Milter

### 1. Lancer le milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Avec `--reject`, les messages au seuil de rejet (15 points) sont refusés avec `451 4.7.1 Message rejected as spam`. Un 451 est temporaire : l’expéditeur réessaie plus tard, et une erreur peut encore être corrigée en modifiant un réglage. Utilisez `--reject-code 550` pour un refus définitif une fois que les résultats semblent corrects. Avec `--quarantine`, le spam est plutôt placé dans la file d’attente « hold » de Postfix. Un message que le milter n’a pas pu analyser entièrement reçoit une réponse 4xx ; `--on-error accept` le laisse passer à la place.

Comme service systemd, dans `/etc/systemd/system/spamscanner-milter.service` :

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. Y raccorder Postfix

Dans `/etc/postfix/main.cf` :

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters` couvre le courrier qui arrive par SMTP. Laissez `non_smtpd_milters` vide, sauf si le courrier soumis avec la commande `sendmail` doit lui aussi être analysé.

### 3. Le tester

[swaks](https://www.jetmore.org/john/code/swaks/) envoie des messages de test. GTUBE est une chaîne de test que tout filtre antispam traite comme du spam :

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Sans `--reject`, le message est distribué avec `X-Spam-Flag: YES` et un objet marqué. Avec `--reject`, swaks affiche la réponse 451 ou 550.


## Filtre de contenu

Utilisez-le quand le courrier ne doit jamais être refusé pendant la session SMTP, ou pour un serveur qui ne peut pas utiliser de milters.

Dans `/etc/postfix/master.cf`, ajoutez un service de filtrage et utilisez-le sur l’écouteur SMTP :

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] --from=${sender} -- ${recipient}
```

Postfix exécute le filtre avec un environnement presque vide : `argv` désigne donc Node.js et le script par leurs chemins complets (`command -v node` et `npm root --global` les affichent). Ensuite :

```sh
sudo postfix reload
```

Le filtre renvoie le message avec `sendmail -G -i`. Le courrier soumis de cette manière ne repasse pas par l’écouteur `smtp` : il n’est donc pas filtré deux fois.

Les codes de sortie indiquent à Postfix ce qui s’est passé : 0 distribué, 69 refusé (avec `--reject` : Postfix le renvoie à l’expéditeur), 75 échec temporaire (Postfix conserve le message et réessaie). Tout échec d’analyse ou de distribution donne 75, de même qu’un message dont une pièce jointe n’a pas pu être analysée par ClamAV : un réglage défectueux ne fait donc jamais perdre ni renvoyer de courrier. Avec `--on-error accept`, un message dont l’analyse a échoué, ou que ClamAV n’a pas pu analyser entièrement, est transmis à la place, marqué `X-Spam-Virus-Scan: failed` (voir [la CLI](cli.md#filter)).


## Sendmail

Dans `sendmail.mc` :

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` fait répondre Sendmail par un échec temporaire tant que le milter est indisponible ; retirez-le pour accepter plutôt le courrier sans filtrage. Régénérez `sendmail.cf` et redémarrez Sendmail.

Le nom d’hôte du client ne peut placer un message sur la liste d’autorisation que s’il est vérifié. Postfix ne l’envoie que lorsque le nom DNS inverse du client se résout de nouveau vers son adresse, et `unknown` sinon. Sendmail envoie le nom DNS inverse même quand il ne se résout pas en retour (un nom que n’importe qui disposant du DNS inverse de sa propre adresse peut choisir), et l’indique dans sa macro `{client_resolve}`, qu’il n’envoie pas par défaut. Ajoutez-la aux macros envoyées à la connexion, avant `INPUT_MAIL_FILTER`, pour que seul compte un nom d’hôte qu’il donne comme `OK` :

```text
define(`confMILTER_MACROS_CONNECT', `j, _, {daemon_name}, {if_name}, {if_addr}, {client_resolve}')
```


## Ranger le spam dans un dossier Junk

Le marquage seul distribue le spam dans la boîte de réception. Avec Dovecot, une règle Sieve le déplace :

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Autres serveurs de messagerie](mail-servers.md) couvre Dovecot, Exim, Haraka et procmail, et [l’entraînement](training.md#learning-from-reports) montre comment apprendre du courrier que les utilisateurs déplacent vers Junk ou hors de Junk.


## Testé

Les tests de bout en bout du dépôt font tourner un vrai Postfix : le ham est distribué avec des en-têtes, un `X-Spam-Flag` falsifié est supprimé, le spam est marqué, GTUBE est refusé avec un 550 pendant la session SMTP, et le filtre de contenu marque le courrier sur un second port. `scripts/e2e-postfix.sh` configure ce Postfix et `test/e2e/postfix.test.js` envoie le courrier.
