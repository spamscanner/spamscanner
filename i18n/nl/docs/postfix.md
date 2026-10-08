<!-- source: f1043eb5fc58 -->

# Postfix en Sendmail

Spam Scanner sluit op twee manieren aan op Postfix:

* **Als milter** (aanbevolen). Postfix raadpleegt het voor elk bericht tijdens de SMTP-sessie, voordat het bericht wordt geaccepteerd. Spam kan worden geweigerd met een 4xx- of 5xx-antwoord, zodat de verzendende server ermee moet omgaan, niet de jouwe. Sendmail gebruikt hetzelfde protocol.
* **Als contentfilter.** Postfix accepteert het bericht en geeft het via een pipe door aan `spamscanner filter`, dat headers toevoegt en het met sendmail teruggeeft. Er wordt tijdens de SMTP-sessie nooit iets geweigerd.

Beide voegen deze headers aan elk bericht toe:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

`X-Spam-*`-headers die al in het bericht staan, worden eerst verwijderd, zodat een afzender zijn eigen mail niet als schoon kan markeren.


## Milter

### 1. De milter draaien

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Met `--reject` worden berichten op de weigerdrempel (15 punten) geweigerd met `451 4.7.1 Message rejected as spam`. Een 451 is tijdelijk: de afzender probeert het later opnieuw en een fout is nog te herstellen door een instelling aan te passen. Gebruik `--reject-code 550` voor een definitieve weigering zodra de resultaten kloppen. Met `--quarantine` gaat spam in plaats daarvan naar de hold-queue van Postfix.

Als systemd-service, in `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Postfix ernaar laten wijzen

In `/etc/postfix/main.cf`:

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

`smtpd_milters` geldt voor mail die via SMTP binnenkomt. Laat `non_smtpd_milters` leeg, tenzij mail die met de opdracht `sendmail` wordt ingediend ook gescand moet worden.

### 3. Testen

[swaks](https://www.jetmore.org/john/code/swaks/) verstuurt testberichten. GTUBE is een teststring die elk spamfilter als spam behandelt:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Zonder `--reject` wordt het bericht bezorgd met `X-Spam-Flag: YES` en een gemarkeerd onderwerp. Met `--reject` toont swaks het antwoord 451 of 550.


## Contentfilter

Gebruik dit als mail tijdens de SMTP-sessie nooit geweigerd mag worden, of voor een server die geen milters kan gebruiken.

Voeg in `/etc/postfix/master.cf` een filterservice toe en gebruik die op de SMTP-listener:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix draait het filter met een bijna lege omgeving, dus `argv` noemt Node.js en het script met hun volledige paden (`command -v node` en `npm root --global` tonen ze). Daarna:

```sh
sudo postfix reload
```

Het filter geeft het bericht terug met `sendmail -G -i`. Mail die zo wordt ingediend, gaat niet opnieuw door de `smtp`-listener en wordt dus niet twee keer gefilterd.

Exitcodes vertellen Postfix wat er gebeurde: 0 bezorgd, 69 geweigerd (met `--reject`: Postfix stuurt het terug naar de afzender), 75 tijdelijke fout (Postfix houdt het bericht vast en probeert het opnieuw). Elke fout bij het scannen of bezorgen is 75, zodat een kapotte instelling nooit mail kwijtraakt of terugstuurt.


## Sendmail

In `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` laat Sendmail met een tijdelijke fout antwoorden zolang de milter niet beschikbaar is; laat het weg om mail in dat geval ongefilterd te accepteren. Bouw `sendmail.cf` opnieuw en herstart Sendmail.


## Spam naar een Junk-map sorteren

Alleen markeren bezorgt spam in de inbox. Met Dovecot verplaatst een Sieve-regel het:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Andere mailservers](mail-servers.md) behandelt Dovecot, Exim, Haraka en procmail, en [training](training.md#learning-from-reports) laat zien hoe je leert van mail die gebruikers naar Junk en terug verplaatsen.


## Getest

De end-to-endtests van de repository draaien een echte Postfix: ham wordt met headers bezorgd, een vervalste `X-Spam-Flag` wordt verwijderd, spam wordt gemarkeerd, GTUBE wordt tijdens de SMTP-sessie met een 550 geweigerd, en het contentfilter markeert mail op een tweede poort. `scripts/e2e-postfix.sh` zet die Postfix op en `test/e2e/postfix.test.js` verstuurt de mail.
