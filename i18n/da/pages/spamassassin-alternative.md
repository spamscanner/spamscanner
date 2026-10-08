<!-- source: 1562b843d858 -->

<!--
label: Alternativ til SpamAssassin
title: Et alternativ til SpamAssassin, der taler spamd
description: Erstat SpamAssassins spamd med Spam Scanner. spamc, Exim og Haraka virker fortsat, X-Spam-headerne beholder deres navne, og alle sprog understøttes.
keywords: alternativ til SpamAssassin, SpamAssassin alternativ, erstatning for spamd, spamc, Exim spamfilter, Haraka spamassassin, alternativ til rspamd, X-Spam-Status
-->

# Et alternativ til SpamAssassin, der taler spamd

Spam Scanner svarer på SpamAssassins spamd-protokol, så software, der er skrevet til SpamAssassin, bruger den uændret: spamc, Exims `spam`-betingelse, Harakas `spamassassin`-plugin og andre.


## Skift den ind

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

Den svarer på `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` og, med `--allow-tell`, `TELL` til indlæring. Projektets end-to-end-test kører SpamAssassins egen spamc mod den.


## Hvad forbliver det samme

* Headerne: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` og `X-Spam-Status` i SpamAssassins format, så eksisterende regler i Sieve, procmail og mailklienter fortsat virker.
* En score med en grænse på 5, sammensat af navngivne test med point: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` og så videre.
* Scoren for hver test kan ændres ud fra testens navn.


## Hvad er anderledes

* **Sprog.** Ord opdeles efter Unicode-reglerne, så kinesisk, japansk og thai læses som ord i stedet for én lang streng, og forklædninger som usynlige tegn eller kyrilliske bogstaver i latinske ord omgøres først.
* **Phishing.** Forvekslelige domæner, vildledende links og varemærker i visningsnavne tjekkes uden ekstra regler.
* **Vedhæftede filer** identificeres ud fra deres bytes: en programfil, der er omdøbt til `.pdf`, er stadig en programfil.
* **Sprogmodeller.** Tvivlstilfælde kan sendes til en lokal model via Ollama eller til en hostet model.
* **Node.js.** Én `npm install` eller en selvstændig binærfil; ingen Perl-moduler eller regelopdateringer at holde styr på.

Spam Scanner kører ikke SpamAssassins regelfiler, og dens format for Bayes-databasen er dens eget: træn den fra den samme post med `spamscanner train`.


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

[Exim, Haraka, Dovecot og procmail](../../docs/mail-servers.md)
