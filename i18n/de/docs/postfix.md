<!-- source: f1043eb5fc58 -->

# Postfix und Sendmail

Spam Scanner lässt sich auf zwei Arten mit Postfix verbinden:

* **Als Milter** (empfohlen). Postfix fragt ihn während der SMTP-Sitzung zu jeder Nachricht, bevor es sie annimmt. Spam lässt sich mit einer 4xx- oder 5xx-Antwort abweisen, sodass sich der sendende Server darum kümmert, nicht Ihrer. Sendmail verwendet dasselbe Protokoll.
* **Als Content-Filter.** Postfix nimmt die Nachricht an und leitet sie per Pipe an `spamscanner filter` weiter, das Header hinzufügt und sie über sendmail zurückgibt. Während der SMTP-Sitzung wird nie etwas abgewiesen.

Beide fügen jeder Nachricht diese Header hinzu:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Bereits in der Nachricht vorhandene `X-Spam-*`-Header werden zuerst entfernt, sodass ein Absender seine eigene E-Mail nicht als sauber markieren kann.


## Milter

### 1. Den Milter starten

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Mit `--reject` werden Nachrichten ab dem Ablehnungsschwellenwert (15 Punkte) mit `451 4.7.1 Message rejected as spam` abgewiesen. Ein 451 ist temporär: Der Absender versucht es später erneut, und ein Fehler lässt sich noch durch Ändern einer Einstellung korrigieren. Verwenden Sie `--reject-code 550` für eine dauerhafte Ablehnung, sobald die Ergebnisse stimmen. Mit `--quarantine` landet Spam stattdessen in der Hold-Queue von Postfix.

Als systemd-Dienst, in `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Postfix darauf ausrichten

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

`smtpd_milters` gilt für E-Mails, die über SMTP eintreffen. Lassen Sie `non_smtpd_milters` leer, sofern nicht auch mit dem Befehl `sendmail` eingelieferte E-Mails geprüft werden sollen.

### 3. Testen

[swaks](https://www.jetmore.org/john/code/swaks/) sendet Testnachrichten. GTUBE ist eine Testzeichenkette, die jeder Spamfilter als Spam behandelt:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Ohne `--reject` wird die Nachricht mit `X-Spam-Flag: YES` und markiertem Betreff zugestellt. Mit `--reject` zeigt swaks die Antwort 451 oder 550.


## Content-Filter

Verwenden Sie diesen Weg, wenn E-Mails während der SMTP-Sitzung nie abgewiesen werden dürfen, oder für einen Server, der keine Milter verwenden kann.

Fügen Sie in `/etc/postfix/master.cf` einen Filterdienst hinzu und verwenden Sie ihn am SMTP-Listener:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix führt den Filter mit einer fast leeren Umgebung aus, daher nennt `argv` Node.js und das Skript mit vollständigen Pfaden (`command -v node` und `npm root --global` zeigen sie an). Danach:

```sh
sudo postfix reload
```

Der Filter gibt die Nachricht mit `sendmail -G -i` zurück. So eingelieferte E-Mails laufen nicht erneut durch den `smtp`-Listener und werden daher nicht doppelt gefiltert.

Exit-Codes teilen Postfix mit, was geschehen ist: 0 zugestellt, 69 abgewiesen (mit `--reject`: Postfix schickt sie an den Absender zurück), 75 temporärer Fehler (Postfix behält die Nachricht und versucht es erneut). Jeder Fehler beim Prüfen oder Zustellen ergibt 75, sodass eine fehlerhafte Einstellung nie E-Mails verliert oder zurückschickt.


## Sendmail

In `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` lässt Sendmail mit einem temporären Fehler antworten, solange der Milter nicht erreichbar ist. Ohne diese Angabe werden E-Mails stattdessen ungefiltert angenommen. Erzeugen Sie `sendmail.cf` neu und starten Sie Sendmail neu.


## Spam in einen Junk-Ordner sortieren

Markieren allein stellt Spam in den Posteingang zu. Mit Dovecot verschiebt eine Sieve-Regel ihn:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Andere Mailserver](mail-servers.md) behandelt Dovecot, Exim, Haraka und procmail, und [Training](training.md#learning-from-reports) zeigt, wie aus E-Mails gelernt wird, die Benutzer in den Junk-Ordner oder aus ihm heraus verschieben.


## Getestet

Die End-to-End-Tests des Repositorys verwenden ein echtes Postfix: Ham wird mit Headern zugestellt, ein gefälschtes `X-Spam-Flag` wird entfernt, Spam wird markiert, GTUBE wird während der SMTP-Sitzung mit 550 abgewiesen, und der Content-Filter markiert E-Mails auf einem zweiten Port. `scripts/e2e-postfix.sh` richtet dieses Postfix ein, und `test/e2e/postfix.test.js` sendet die E-Mails.
