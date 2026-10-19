<!-- source: 599bd320e55a -->

<!--
label: Über
title: Über Spam Scanner, seine Lizenz und den Datenschutz
description: Wer Spam Scanner entwickelt, wie Sie einen Fehler oder eine Sicherheitslücke melden, welche Lizenz gilt und was diese Website erfasst: keine Cookies, keine Analyse.
keywords: über Spam Scanner, Forward Email, Spam Scanner Lizenz, BUSL-1.1, Spam Scanner Kontakt, Spam Scanner Datenschutz
-->

# Über Spam Scanner

Spam Scanner ist ein E-Mail-Spamfilter von [Forward Email](https://forwardemail.net), dem auf Datenschutz ausgerichteten E-Mail-Dienst, der ihn für seine eigenen Mailserver gebaut hat. Quellcode, Issues und Releases liegen auf [GitHub](https://github.com/spamscanner/spamscanner), das Paket auf [npm](https://www.npmjs.com/package/spamscanner).


## Wer ihn entwickelt

Das Team von Forward Email schreibt und pflegt Spam Scanner. Forward Email protokolliert keine Nachrichteninhalte und konnte E-Mails daher nicht an einen externen Filterdienst senden: Der Filter musste auf den eigenen Servern laufen und jede Entscheidung begründen, ohne dass ein Mensch die E-Mail liest. [Wie Forward Email ihn nutzt](../../docs/forward-email.md)

Auch Forward Email ist Open Source, unter [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Sein Gründer war einer der ersten Mitarbeiter von DuckDuckGo.


## Kontakt

* **Fragen, Fehler und Wünsche:** Eröffnen Sie ein Issue auf [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Sicherheitslücken:** Melden Sie sie vertraulich über [die Schwachstellenmeldung von GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), nicht in öffentlichen Issues. Dieselbe Adresse steht in [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Andere Lizenzen:** Wenden Sie sich an [Forward Email](https://forwardemail.net).


## Lizenzbedingungen

Die [Lizenz](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) von Spam Scanner ist die Business Source License 1.1 mit der Apache License 2.0 als Change License. Das in der Lizenz genannte Change Date ist verstrichen, und seit diesem Datum gewährt Ihnen die Lizenz Rechte nach der Apache License 2.0.


## Datenschutz

Diese Website setzt keine Cookies und lädt keine Analyse, Tracker, Werbung, Schriften oder Skripte von anderen Websites. Jede Datei kommt von spamscanner.net.

* Das Theme, die gewählte Sprache und der Mastodon-Server, an den Sie teilen, werden im lokalen Speicher Ihres Browsers abgelegt und nirgendwohin gesendet.
* Das Video lädt erst, wenn Sie es abspielen.
* Die Teilen-Links sind einfache Links, daher lädt nichts von diesen Netzwerken, bis Sie einem folgen.
* Die Website wird auf GitHub Pages gehostet, und GitHub protokolliert aus Sicherheitsgründen die IP-Adresse jedes Besuchers. Siehe [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) und die [Datenschutzerklärung von GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Was die Software sendet

Spam Scanner sendet keine Telemetrie und sucht nicht nach Updates. Standardmäßig schlägt er die Hostnamen der Links einer Nachricht bei den filternden DNS-Resolvern von Cloudflare nach, und sonst verlässt nichts den Rechner. Seine anderen Netzwerkprüfungen sind aus, bis Sie sie einschalten. [Sicherheit und Datenschutz](../../docs/security.md)


## Releases

Die eigenständigen Binärdateien baut GitHub Actions aus dem öffentlichen Repository. Jedes Release listet ihre Hashes in einer Datei `SHA256SUMS`, die das Installationsskript prüft, und jede Binärdatei trägt eine signierte Build-Provenienz-Attestierung. Releases und ihre Hinweise stehen auf [GitHub](https://github.com/spamscanner/spamscanner/releases).
