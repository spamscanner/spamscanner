<!-- source: 6675649d593a -->

# Postfix og Sendmail

Spam Scanner kobles til Postfix på to måter:

* **Som milter** (anbefalt). Postfix spør den om hver melding under SMTP-økten, før meldingen mottas. Spam kan avvises med et 4xx- eller 5xx-svar, så det er avsenderserveren, ikke din, som må håndtere den. Sendmail bruker den samme protokollen.
* **Som innholdsfilter.** Postfix mottar meldingen og sender den gjennom en pipe til `spamscanner filter`, som legger til hoder og leverer den tilbake med sendmail. Ingenting avvises noen gang under SMTP-økten.

Begge legger til disse hodene i hver melding:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.3
X-Spam-Action: tag
```

`X-Spam-*`-hoder som allerede finnes i meldingen, fjernes først, så en avsender ikke kan merke sin egen e-post som ren.

En melding med et vedlegg ClamAV ikke kunne skanne, kan inneholde virus, så begge utsetter den (Postfix eller avsenderen prøver igjen senere), slik de gjør når en skanning mislykkes. Med `--on-error accept` sendes den videre med `X-Spam-Virus-Scan: failed` lagt til.


## Milter

### 1. Kjør milteren

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Med `--reject` avvises meldinger ved avvisningsterskelen (15 poeng) med `451 4.7.1 Message rejected as spam`. En 451 er midlertidig: avsenderen prøver igjen senere, og en feil kan fortsatt rettes ved å endre en innstilling. Bruk `--reject-code 550` for en permanent avvisning når resultatene ser riktige ut. Med `--quarantine` går spam i stedet til hold-køen i Postfix. En melding milteren ikke kunne skanne fullt ut, får et 4xx-svar; `--on-error accept` slipper den gjennom i stedet.

Som systemd-tjeneste, i `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Pek Postfix mot den

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

`smtpd_milters` dekker e-post som kommer inn over SMTP. La `non_smtpd_milters` være tom med mindre e-post sendt inn med kommandoen `sendmail` også skal skannes.

### 3. Test den

[swaks](https://www.jetmore.org/john/code/swaks/) sender testmeldinger. GTUBE er en teststreng som alle spamfiltre behandler som spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Uten `--reject` leveres meldingen med `X-Spam-Flag: YES` og et merket emne. Med `--reject` viser swaks svaret 451 eller 550.


## Innholdsfilter

Bruk dette når e-post aldri må avvises under SMTP-økten, eller for en server som ikke kan bruke miltere.

I `/etc/postfix/master.cf` legger du til en filtertjeneste og bruker den på SMTP-lytteren:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] --from=${sender} -- ${recipient}
```

Postfix kjører filteret med et nesten tomt miljø, så `argv` oppgir Node.js og skriptet med fulle stier (`command -v node` og `npm root --global` viser dem). Deretter:

```sh
sudo postfix reload
```

Filteret sender meldingen tilbake med `sendmail -G -i`. E-post som sendes inn på denne måten, går ikke gjennom `smtp`-lytteren igjen, så den filtreres ikke to ganger.

Avslutningskodene forteller Postfix hva som skjedde: 0 levert, 69 avvist (med `--reject`: Postfix returnerer den til avsenderen), 75 midlertidig feil (Postfix beholder meldingen og prøver igjen). Enhver feil ved skanning eller levering gir 75, og det samme gjør en melding med et vedlegg ClamAV ikke kunne skanne, så en feil innstilling aldri fører til at e-post går tapt eller returneres. Med `--on-error accept` sendes en melding der skanningen mislyktes, eller som ClamAV ikke kunne skanne fullstendig, videre i stedet, merket med `X-Spam-Virus-Scan: failed` (se [CLI-en](cli.md#filter)).


## Sendmail

I `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` får Sendmail til å svare med en midlertidig feil mens milteren er utilgjengelig; fjern den for i stedet å motta e-post ufiltrert. Bygg `sendmail.cf` på nytt og start Sendmail på nytt.

Klientens vertsnavn kan bare sette en melding på tillatelseslisten når det er verifisert. Postfix sender det bare når klientens omvendte DNS-navn slås opp tilbake til adressen, og ellers `unknown`. Sendmail sender det omvendte DNS-navnet selv når det ikke slås opp tilbake (et navn hvem som helst med omvendt DNS for sin egen adresse kan velge), og sier fra om det i makroen `{client_resolve}`, som den ikke sender som standard. Legg den til i makroene som sendes ved tilkobling, før `INPUT_MAIL_FILTER`, slik at bare et vertsnavn den oppgir som `OK`, teller:

```text
define(`confMILTER_MACROS_CONNECT', `j, _, {daemon_name}, {if_name}, {if_addr}, {client_resolve}')
```


## Sortere spam i en Søppelpost-mappe

Merking alene leverer spam til innboksen. Med Dovecot flytter en Sieve-regel den:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Andre e-postservere](mail-servers.md) dekker Dovecot, Exim, Haraka og procmail, og [trening](training.md#learning-from-reports) viser hvordan modellen kan lære av e-post som brukerne flytter inn i og ut av Junk.


## Testet

Ende-til-ende-testene i repositoriet kjører en ekte Postfix: ham leveres med hoder, et forfalsket `X-Spam-Flag` fjernes, spam merkes, GTUBE avvises med 550 under SMTP-økten, og innholdsfilteret merker e-post på en annen port. `scripts/e2e-postfix.sh` setter opp denne Postfix-installasjonen, og `test/e2e/postfix.test.js` sender e-posten.
