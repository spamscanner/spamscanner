<!-- source: 1562b843d858 -->

<!--
label: Alternatief voor SpamAssassin
title: Een alternatief voor SpamAssassin dat spamd spreekt
description: Vervang spamd van SpamAssassin door Spam Scanner. spamc, Exim en Haraka blijven werken, de X-Spam-headers houden hun namen en elke taal wordt ondersteund.
keywords: SpamAssassin alternatief, alternatief voor SpamAssassin, spamd vervangen, spamc, Exim spamfilter, Haraka spamassassin, rspamd alternatief, X-Spam-Status
-->

# Een alternatief voor SpamAssassin dat spamd spreekt

Spam Scanner beantwoordt het spamd-protocol van SpamAssassin, zodat software die voor SpamAssassin is geschreven het ongewijzigd gebruikt: spamc, de voorwaarde `spam` van Exim, de plug-in `spamassassin` van Haraka en andere.


## Inwisselen

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

Het beantwoordt `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` en, met `--allow-tell`, `TELL` om te leren. De end-to-endtests van het project draaien de eigen spamc van SpamAssassin ertegen.


## Wat hetzelfde blijft

* De headers: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` en `X-Spam-Status` in het formaat van SpamAssassin, zodat bestaande regels in Sieve, procmail en mailclients blijven werken.
* Een score met een drempel van 5, opgebouwd uit benoemde tests met punten: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` enzovoort.
* De scores per test zijn via de testnaam aan te passen.


## Wat anders is

* **Talen.** Woorden worden gesegmenteerd met de Unicode-regels, zodat Chinees, Japans en Thai als woorden worden gelezen in plaats van als één lange string, en vermommingen zoals onzichtbare tekens of Cyrillische letters in Latijnse woorden worden eerst ongedaan gemaakt.
* **Phishing.** Lookalike-domeinen, misleidende links en merknamen in weergavenamen worden zonder extra regels gecontroleerd.
* **Bijlagen** worden herkend aan hun bytes: een uitvoerbaar bestand dat is hernoemd naar `.pdf` blijft een uitvoerbaar bestand.
* **Taalmodellen.** Twijfelgevallen kunnen naar een lokaal model via Ollama of naar een gehost model.
* **Node.js.** Eén `npm install`, of een standalone binary; geen Perl-modules of regelupdates om te beheren.

Spam Scanner voert de regelbestanden van SpamAssassin niet uit, en het formaat van de Bayes-database is eigen: train het op dezelfde mail met `spamscanner train`.


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

[Exim, Haraka, Dovecot en procmail](../../docs/mail-servers.md)
