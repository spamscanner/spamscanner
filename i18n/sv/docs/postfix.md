<!-- source: f1043eb5fc58 -->

# Postfix och Sendmail

Spam Scanner ansluts till Postfix på två sätt:

* **Som milter** (rekommenderas). Postfix frågar det om varje meddelande under SMTP-sessionen, innan meddelandet tas emot. Spam kan nekas med ett 4xx- eller 5xx-svar, så att den sändande servern, inte din, får hantera det. Sendmail använder samma protokoll.
* **Som innehållsfilter.** Postfix tar emot meddelandet och skickar det vidare till `spamscanner filter`, som lägger till huvuden och lämnar tillbaka det med sendmail. Ingenting nekas någonsin under SMTP-sessionen.

Båda lägger till dessa huvuden i varje meddelande:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

`X-Spam-*`-huvuden som redan finns i meddelandet tas bort först, så en avsändare kan inte märka sin egen e-post som ren.


## Milter

### 1. Kör miltern

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Med `--reject` nekas meddelanden som når gränsen för avvisning (15 poäng) med `451 4.7.1 Message rejected as spam`. En 451 är tillfällig: avsändaren försöker igen senare och ett misstag kan fortfarande rättas genom att ändra en inställning. Använd `--reject-code 550` för en permanent avvisning när resultaten ser rätt ut. Med `--quarantine` hamnar spam i stället i Postfix kö för kvarhållna meddelanden (hold).

Som systemd-tjänst, i `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Peka Postfix mot den

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

`smtpd_milters` gäller e-post som kommer in över SMTP. Lämna `non_smtpd_milters` tomt om inte e-post som skickas in med kommandot `sendmail` också ska skannas.

### 3. Testa den

[swaks](https://www.jetmore.org/john/code/swaks/) skickar testmeddelanden. GTUBE är en teststräng som alla spamfilter behandlar som spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Utan `--reject` levereras meddelandet med `X-Spam-Flag: YES` och en märkt ämnesrad. Med `--reject` visar swaks svaret 451 eller 550.


## Innehållsfilter

Använd detta när e-post aldrig får nekas under SMTP-sessionen, eller för en server som inte kan använda milters.

I `/etc/postfix/master.cf`, lägg till en filtertjänst och använd den på SMTP-lyssnaren:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix kör filtret med en nästan tom miljö, så `argv` anger Node.js och skriptet med fullständiga sökvägar (`command -v node` och `npm root --global` visar dem). Sedan:

```sh
sudo postfix reload
```

Filtret lämnar tillbaka meddelandet med `sendmail -G -i`. E-post som skickas in på det sättet passerar inte `smtp`-lyssnaren igen, så den filtreras inte två gånger.

Slutkoderna talar om för Postfix vad som hände: 0 levererat, 69 nekat (med `--reject`: Postfix studsar det tillbaka till avsändaren), 75 tillfälligt fel (Postfix behåller meddelandet och försöker igen). Varje fel vid skanning eller leverans ger 75, så en felaktig inställning gör aldrig att e-post förloras eller studsar.


## Sendmail

I `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` gör att Sendmail svarar med ett tillfälligt fel medan miltern inte är tillgänglig; ta bort det för att i stället ta emot e-post ofiltrerad. Bygg om `sendmail.cf` och starta om Sendmail.


## Sortera spam till en skräppostmapp

Enbart märkning levererar spam till inkorgen. Med Dovecot flyttar en Sieve-regel den:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Andra e-postservrar](mail-servers.md) beskriver Dovecot, Exim, Haraka och procmail, och [träning](training.md#learning-from-reports) visar hur den lär sig av e-post som användare flyttar till och från skräpposten.


## Testat

Repositoriets end-to-end-tester kör en riktig Postfix: ham levereras med huvuden, ett förfalskat `X-Spam-Flag` tas bort, spam märks, GTUBE nekas med 550 under SMTP-sessionen och innehållsfiltret märker e-post på en andra port. `scripts/e2e-postfix.sh` konfigurerar den Postfix-installationen och `test/e2e/postfix.test.js` skickar e-posten.
