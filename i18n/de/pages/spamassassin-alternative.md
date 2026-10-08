<!-- source: 1562b843d858 -->

<!--
label: Alternative zu SpamAssassin
title: Eine Alternative zu SpamAssassin, die spamd spricht
description: spamd von SpamAssassin durch Spam Scanner ersetzen. spamc, Exim und Haraka funktionieren weiter, die X-Spam-Header bleiben, und jede Sprache wird unterstützt.
keywords: SpamAssassin Alternative, spamd Ersatz, spamc, Exim Spamfilter, Haraka spamassassin, rspamd Alternative, X-Spam-Status
-->

# Eine Alternative zu SpamAssassin, die spamd spricht

Spam Scanner beantwortet das spamd-Protokoll von SpamAssassin, sodass für SpamAssassin geschriebene Software ihn unverändert verwendet: spamc, die Bedingung `spam` von Exim, das Plugin `spamassassin` von Haraka und andere.


## Austauschen

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

Er beantwortet `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` und, mit `--allow-tell`, `TELL` zum Lernen. Die End-to-End-Tests des Projekts lassen das spamc von SpamAssassin selbst dagegen laufen.


## Was gleich bleibt

* Die Header: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` und `X-Spam-Status` im Format von SpamAssassin, sodass bestehende Regeln für Sieve, procmail und E-Mail-Programme weiter funktionieren.
* Ein Score mit dem Schwellenwert 5, zusammengesetzt aus benannten Tests mit Punkten: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` und so weiter.
* Die Punkte einzelner Tests lassen sich über den Testnamen ändern.


## Was anders ist

* **Sprachen.** Wörter werden nach den Unicode-Regeln segmentiert, sodass Chinesisch, Japanisch und Thai als Wörter gelesen werden statt als eine lange Zeichenkette, und Tarnungen wie unsichtbare Zeichen oder kyrillische Buchstaben in lateinischen Wörtern werden zuerst aufgelöst.
* **Phishing.** Doppelgänger-Domains, irreführende Links und Markennamen in Anzeigenamen werden ohne zusätzliche Regeln geprüft.
* **Anhänge** werden an ihren Bytes erkannt: Eine in `.pdf` umbenannte ausführbare Datei bleibt eine ausführbare Datei.
* **Sprachmodelle.** Knappe Fälle können an ein lokales Modell über Ollama oder an ein gehostetes gehen.
* **Node.js.** Ein `npm install` oder eine eigenständige Binärdatei; keine Perl-Module oder Regel-Updates zu pflegen.

Spam Scanner führt die Regeldateien von SpamAssassin nicht aus, und sein Format für die Bayes-Datenbank ist ein eigenes: Trainieren Sie ihn mit `spamscanner train` aus denselben E-Mails.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot und procmail](../../docs/mail-servers.md)
