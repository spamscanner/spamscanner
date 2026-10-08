<!-- source: f1043eb5fc58 -->

# Postfix és Sendmail

A Spam Scanner kétféleképpen kapcsolódik a Postfixhez:

* **Milterként** (ajánlott). A Postfix az SMTP-munkamenet közben, az átvétel előtt kérdezi meg minden levélről. A spam 4xx vagy 5xx válasszal visszautasítható, így a küldő szervernek kell foglalkoznia vele, nem a sajátjának. A Sendmail ugyanezt a protokollt használja.
* **Tartalomszűrőként.** A Postfix átveszi a levelet, és továbbítja a `spamscanner filter` parancsnak, amely hozzáadja a fejléceket, majd a sendmaillel visszaadja. Az SMTP-munkamenet közben soha semmi nem kerül visszautasításra.

Mindkettő hozzáadja ezeket a fejléceket minden levélhez:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

A levélben már meglévő `X-Spam-*` fejléceket előbb eltávolítja, így a feladó nem jelölheti tisztának a saját levelét.


## Milter

### 1. A milter futtatása

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

A `--reject` kapcsolóval az elutasítási küszöböt (15 pont) elérő leveleket `451 4.7.1 Message rejected as spam` válasszal utasítja vissza. A 451 ideiglenes: a feladó később újra próbálkozik, és a hiba egy beállítás módosításával még javítható. Ha az eredmények megfelelőnek tűnnek, a `--reject-code 550` véglegessé teszi az elutasítást. A `--quarantine` kapcsolóval a spam ehelyett a Postfix hold sorába kerül.

systemd szolgáltatásként, a `/etc/systemd/system/spamscanner-milter.service` fájlban:

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

### 2. A Postfix beállítása a milterre

Az `/etc/postfix/main.cf` fájlban:

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

Az `smtpd_milters` az SMTP-n érkező levelekre vonatkozik. A `non_smtpd_milters` maradjon üres, hacsak a `sendmail` paranccsal beküldött leveleket is vizsgálni kell.

### 3. Tesztelés

A [swaks](https://www.jetmore.org/john/code/swaks/) tesztleveleket küld. A GTUBE egy tesztkarakterlánc, amelyet minden spamszűrő spamnek tekint:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

A `--reject` nélkül a levél `X-Spam-Flag: YES` fejléccel és megjelölt tárggyal kerül kézbesítésre. A `--reject` kapcsolóval a swaks a 451-es vagy 550-es választ mutatja.


## Tartalomszűrő

Akkor érdemes használni, ha a leveleket soha nem szabad az SMTP-munkamenet közben visszautasítani, vagy olyan szervernél, amely nem tud miltereket használni.

Az `/etc/postfix/master.cf` fájlban adjon hozzá egy szűrőszolgáltatást, és használja az SMTP-figyelőn:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

A Postfix szinte üres környezettel futtatja a szűrőt, ezért az `argv` teljes elérési úttal adja meg a Node.js-t és a szkriptet (a `command -v node` és az `npm root --global` megmutatja ezeket). Ezután:

```sh
sudo postfix reload
```

A szűrő a `sendmail -G -i` paranccsal adja vissza a levelet. Az így beküldött levél nem halad át újra az `smtp` figyelőn, így nem kerül kétszer szűrésre.

A kilépési kódok közlik a Postfixszel, mi történt: 0 kézbesítve, 69 visszautasítva (a `--reject` kapcsolóval: a Postfix visszapattintja a feladónak), 75 ideiglenes hiba (a Postfix megtartja a levelet, és újra próbálkozik). Minden vizsgálati vagy kézbesítési hiba 75-ös kódot ad, így egy hibás beállítás soha nem okoz levélvesztést vagy visszapattanást.


## Sendmail

A `sendmail.mc` fájlban:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

Az `F=T` hatására a Sendmail ideiglenes hibával válaszol, amíg a milter nem érhető el; ha ehelyett szűrés nélkül kell átvenni a leveleket, ezt el kell hagyni. Ezután újra kell építeni a `sendmail.cf` fájlt, és újra kell indítani a Sendmailt.


## A spam áthelyezése a Levélszemét mappába

A megjelölés önmagában a beérkezett levelek közé kézbesíti a spamet. Dovecottal egy Sieve-szabály áthelyezi:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

A [Más levelezőszerverek](mail-servers.md) oldal a Dovecotot, az Eximet, a Harakát és a procmailt tárgyalja, a [tanítás](training.md#learning-from-reports) pedig bemutatja, hogyan lehet tanulni azokból a levelekből, amelyeket a felhasználók a Levélszemét mappába vagy onnan kifelé mozgatnak.


## Tesztelve

A tároló végpontok közötti tesztjei valódi Postfixet futtatnak: a ham fejlécekkel kerül kézbesítésre, a hamisított `X-Spam-Flag` eltávolításra kerül, a spam megjelölést kap, a GTUBE-ot az SMTP-munkamenet közben 550-es kóddal utasítja vissza, a tartalomszűrő pedig egy második porton jelöli meg a leveleket. A `scripts/e2e-postfix.sh` állítja be ezt a Postfixet, a `test/e2e/postfix.test.js` pedig elküldi a leveleket.
