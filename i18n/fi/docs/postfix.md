<!-- source: f1043eb5fc58 -->

# Postfix ja Sendmail

Spam Scanner liitetään Postfixiin kahdella tavalla:

* **Milterinä** (suositeltu). Postfix kysyy siltä jokaisesta viestistä SMTP-istunnon aikana, ennen viestin vastaanottamista. Roskaposti voidaan hylätä 4xx- tai 5xx-vastauksella, jolloin sen käsittelee lähettävä palvelin, ei sinun palvelimesi. Sendmail käyttää samaa protokollaa.
* **Sisältösuodattimena.** Postfix ottaa viestin vastaan ja putkittaa sen komennolle `spamscanner filter`, joka lisää otsakkeet ja palauttaa viestin sendmailin avulla. SMTP-istunnon aikana mitään ei koskaan hylätä.

Molemmat lisäävät jokaiseen viestiin nämä otsakkeet:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Viestissä jo olevat `X-Spam-*`-otsakkeet poistetaan ensin, joten lähettäjä ei voi merkitä omaa postiaan puhtaaksi.


## Milter

### 1. Käynnistä milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Valitsimella `--reject` hylkäysrajan (15 pistettä) ylittävät viestit hylätään vastauksella `451 4.7.1 Message rejected as spam`. 451 on väliaikainen: lähettäjä yrittää myöhemmin uudelleen, ja virheen voi vielä korjata muuttamalla asetusta. Käytä valitsinta `--reject-code 550` pysyvää hylkäystä varten, kun tulokset näyttävät oikeilta. Valitsimella `--quarantine` roskaposti menee sen sijaan Postfixin pitojonoon.

systemd-palveluna tiedostossa `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Osoita Postfix siihen

Tiedostossa `/etc/postfix/main.cf`:

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

`smtpd_milters` kattaa SMTP:n kautta saapuvan postin. Jätä `non_smtpd_milters` tyhjäksi, ellei myös `sendmail`-komennolla lähetettyä postia pidä tarkistaa.

### 3. Testaa se

[swaks](https://www.jetmore.org/john/code/swaks/) lähettää testiviestejä. GTUBE on testimerkkijono, jota jokainen roskapostisuodatin pitää roskapostina:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Ilman valitsinta `--reject` viesti toimitetaan otsakkeella `X-Spam-Flag: YES` ja merkityllä aiherivillä. Valitsimella `--reject` swaks näyttää vastauksen 451 tai 550.


## Sisältösuodatin

Käytä tätä, kun postia ei saa koskaan hylätä SMTP-istunnon aikana, tai palvelimella, joka ei voi käyttää miltereitä.

Lisää tiedostoon `/etc/postfix/master.cf` suodatinpalvelu ja käytä sitä SMTP-kuuntelijassa:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix ajaa suodattimen lähes tyhjällä ympäristöllä, joten `argv` nimeää Node.js:n ja skriptin täysillä poluilla (`command -v node` ja `npm root --global` näyttävät ne). Sitten:

```sh
sudo postfix reload
```

Suodatin palauttaa viestin komennolla `sendmail -G -i`. Tällä tavalla lähetetty posti ei kulje uudelleen `smtp`-kuuntelijan kautta, joten sitä ei suodateta kahdesti.

Paluukoodit kertovat Postfixille, mitä tapahtui: 0 toimitettu, 69 hylätty (valitsimella `--reject`: Postfix palauttaa sen lähettäjälle), 75 väliaikainen virhe (Postfix säilyttää viestin ja yrittää uudelleen). Mikä tahansa tarkistus- tai toimitusvirhe on 75, joten rikkinäinen asetus ei koskaan hukkaa tai palauta postia.


## Sendmail

Tiedostossa `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` saa Sendmailin vastaamaan väliaikaisella virheellä, kun milter ei ole käytettävissä; poista se, jos haluat sen sijaan ottaa postin vastaan suodattamattomana. Koosta `sendmail.cf` uudelleen ja käynnistä Sendmail uudelleen.


## Roskapostin lajittelu Junk-kansioon

Pelkkä merkitseminen toimittaa roskapostin saapuneisiin. Dovecotin kanssa Sieve-sääntö siirtää sen:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Muut postipalvelimet](mail-servers.md) käsittelee Dovecotin, Eximin, Harakan ja procmailin, ja [koulutus](training.md#learning-from-reports) näyttää, miten oppia postista, jota käyttäjät siirtävät Junk-kansioon ja sieltä pois.


## Testattu

Repositorion päästä päähän -testit ajavat oikeaa Postfixia: ham toimitetaan otsakkeineen, väärennetty `X-Spam-Flag` poistetaan, roskaposti merkitään, GTUBE hylätään koodilla 550 SMTP-istunnon aikana, ja sisältösuodatin merkitsee postin toisessa portissa. `scripts/e2e-postfix.sh` määrittää kyseisen Postfixin ja `test/e2e/postfix.test.js` lähettää postin.
