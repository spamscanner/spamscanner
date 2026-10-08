<!-- source: f33722183f00 -->

<!--
label: Postfix-Spamfilter
title: Spamfilter für Postfix mit Milter oder Content-Filter
description: Spam auf Postfix mit dem Milter oder Content-Filter von Spam Scanner filtern: Einrichtung, systemd-Unit, Abweisen mit 4xx oder 5xx und ein Junk-Ordner.
keywords: Postfix Spamfilter, Postfix Milter, smtpd_milters, Postfix Content-Filter, Postfix Anti-Spam, Spam abweisen Postfix
-->

# Spamfilter für Postfix

Spam Scanner filtert einen Postfix-Server in etwa fünf Minuten. Er läuft als Milter, sodass Postfix ihn während der SMTP-Sitzung zu jeder Nachricht fragt und Spam abweisen kann, bevor er angenommen wird.


## Installieren und starten

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` prüft SPF, DKIM, DMARC und ARC; `--subject-tag` kennzeichnet Spam im Betreff. Jede Nachricht erhält die Header `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` und `X-Spam-Action`, und jeder `X-Spam-*`-Header, den der Absender eingefügt hat, wird zuerst entfernt.


## Postfix anbinden

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` lässt E-Mails ungefiltert durch, wenn der Milter nicht läuft; `tempfail` bittet Absender stattdessen, es erneut zu versuchen.


## Spam während der SMTP-Sitzung abweisen

```sh
spamscanner milter --port 7831 --auth --reject
```

Nachrichten ab dem Ablehnungsschwellenwert (15 Punkte) werden mit `451 4.7.1 Message rejected as spam` abgewiesen. Ein 451 ist temporär: Der Absender behält die Nachricht und versucht es erneut, sodass eine falsche Entscheidung eine Verzögerung kostet, keine verlorene Nachricht. Sobald die Ergebnisse stimmen, macht `--reject-code 550` die Ablehnung dauerhaft.


## Ohne Milter

Ein Content-Filter läuft, nachdem Postfix eine Nachricht angenommen hat: Postfix leitet sie per Pipe an `spamscanner filter` weiter, das Header hinzufügt und sie zurückgibt. Während der Sitzung wird nie etwas abgewiesen, und ein Fehler verzögert die Zustellung immer, statt eine Unzustellbarkeitsnachricht auszulösen. [Einrichtung des Content-Filters](../../docs/postfix.md#content-filter)


## Spam in den Junk-Ordner

Mit Dovecot legt eine Sieve-Regel markierte E-Mails ab:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Gegen ein echtes Postfix getestet

Die End-to-End-Tests des Projekts betreiben Postfix mit dem Milter und dem Content-Filter: Ham wird mit Headern zugestellt und ein gefälschtes `X-Spam-Flag` entfernt, Spam wird markiert, und GTUBE wird während der SMTP-Sitzung mit 550 abgewiesen.

Weiter: [die vollständige Anleitung zu Postfix und Sendmail](../../docs/postfix.md), mit einer systemd-Unit und `INPUT_MAIL_FILTER` für Sendmail.
