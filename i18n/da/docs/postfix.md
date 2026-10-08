<!-- source: f1043eb5fc58 -->

# Postfix og Sendmail

Spam Scanner kobles på Postfix på to måder:

* **Som milter** (anbefalet). Postfix spørger den om hver besked under SMTP-sessionen, før beskeden modtages. Spam kan afvises med et 4xx- eller 5xx-svar, så det er den afsendende server og ikke din, der håndterer den. Sendmail bruger den samme protokol.
* **Som indholdsfilter.** Postfix modtager beskeden og sender den videre til `spamscanner filter`, som tilføjer headere og giver den tilbage med sendmail. Intet afvises nogensinde under SMTP-sessionen.

Begge tilføjer disse headere til hver besked:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

`X-Spam-*`-headere, der allerede står i beskeden, fjernes først, så en afsender ikke kan markere sin egen post som ren.


## Milter

### 1. Kør milteren

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Med `--reject` afvises beskeder ved afvisningsgrænsen (15 point) med `451 4.7.1 Message rejected as spam`. En 451 er midlertidig: afsenderen prøver igen senere, og en fejl kan stadig rettes ved at ændre en indstilling. Brug `--reject-code 550` for en permanent afvisning, når resultaterne ser rigtige ud. Med `--quarantine` går spam i stedet til Postfix' hold-kø.

Som systemd-tjeneste i `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Peg Postfix på den

I `/etc/postfix/main.cf`:

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

`smtpd_milters` dækker post, der kommer ind via SMTP. Lad `non_smtpd_milters` være tom, medmindre post, der indsendes med kommandoen `sendmail`, også skal scannes.

### 3. Test den

[swaks](https://www.jetmore.org/john/code/swaks/) sender testbeskeder. GTUBE er en teststreng, som alle spamfiltre behandler som spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Uden `--reject` leveres beskeden med `X-Spam-Flag: YES` og et markeret emne. Med `--reject` viser swaks 451- eller 550-svaret.


## Indholdsfilter

Brug dette, når post aldrig må afvises under SMTP-sessionen, eller til en server, der ikke kan bruge miltere.

Tilføj i `/etc/postfix/master.cf` en filtertjeneste, og brug den på SMTP-lytteren:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix kører filteret med et næsten tomt miljø, så `argv` angiver Node.js og scriptet med deres fulde stier (`command -v node` og `npm root --global` viser dem). Derefter:

```sh
sudo postfix reload
```

Filteret sender beskeden tilbage med `sendmail -G -i`. Post, der indsendes på denne måde, går ikke gennem `smtp`-lytteren igen, så den filtreres ikke to gange.

Afslutningskoderne fortæller Postfix, hvad der skete: 0 leveret, 69 afvist (med `--reject`: Postfix sender den retur til afsenderen), 75 midlertidig fejl (Postfix beholder beskeden og prøver igen). Enhver fejl ved scanning eller levering giver 75, så en forkert indstilling aldrig mister post eller sender den retur.


## Sendmail

I `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` får Sendmail til at svare med en midlertidig fejl, mens milteren ikke er tilgængelig; fjern det for i stedet at modtage post ufiltreret. Byg `sendmail.cf` igen, og genstart Sendmail.


## Spam sorteres i en Junk-mappe

Markering alene leverer spam i indbakken. Med Dovecot flytter en Sieve-regel den:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Andre mailservere](mail-servers.md) dækker Dovecot, Exim, Haraka og procmail, og [træning](training.md#learning-from-reports) viser, hvordan modellen lærer af post, som brugerne flytter ind i og ud af Junk.


## Testet

Repositoriets end-to-end-test kører en rigtig Postfix: ham leveres med headere, en forfalsket `X-Spam-Flag` fjernes, spam markeres, GTUBE afvises med en 550 under SMTP-sessionen, og indholdsfilteret markerer post på en anden port. `scripts/e2e-postfix.sh` sætter den Postfix op, og `test/e2e/postfix.test.js` sender posten.
