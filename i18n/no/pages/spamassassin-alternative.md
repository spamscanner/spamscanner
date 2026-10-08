<!-- source: 1562b843d858 -->

<!--
label: Alternativ til SpamAssassin
title: Et alternativ til SpamAssassin som snakker spamd
description: Erstatt SpamAssassins spamd med Spam Scanner. spamc, Exim og Haraka virker fortsatt, X-Spam-hodene beholder navnene, og alle språk støttes.
keywords: alternativ til SpamAssassin, erstatning for spamd, spamc, spamfilter Exim, Haraka spamassassin, alternativ til rspamd, X-Spam-Status
-->

# Et alternativ til SpamAssassin som snakker spamd

Spam Scanner svarer på SpamAssassins spamd-protokoll, så programvare skrevet for SpamAssassin bruker det uendret: spamc, `spam`-betingelsen i Exim, `spamassassin`-tillegget i Haraka og andre.


## Bytt det inn

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

Det svarer på `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` og, med `--allow-tell`, `TELL` for læring. Ende-til-ende-testene i prosjektet kjører SpamAssassins egen spamc mot det.


## Hva som forblir det samme

* Hodene: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` og `X-Spam-Status` i SpamAssassins format, så eksisterende regler i Sieve, procmail og e-postklienter fortsetter å virke.
* En poengsum med terskel 5, satt sammen av navngitte tester med poeng: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` og så videre.
* Poengene for hver test kan endres med testnavnet.


## Hva som er annerledes

* **Språk.** Ord segmenteres med Unicode-reglene, så kinesisk, japansk og thai leses som ord i stedet for én lang streng, og forkledninger som usynlige tegn eller kyrilliske bokstaver i latinske ord gjøres om først.
* **Phishing.** Forvekslingsdomener, villedende lenker og merkenavn i visningsnavn sjekkes uten ekstra regler.
* **Vedlegg** identifiseres ut fra bytene: en kjørbar fil omdøpt til `.pdf` er fortsatt en kjørbar fil.
* **Språkmodeller.** Vanskelige tilfeller kan sendes til en lokal modell via Ollama eller til en driftet modell.
* **Node.js.** Én `npm install`, eller en frittstående binærfil; ingen Perl-moduler eller regeloppdateringer å administrere.

Spam Scanner kjører ikke SpamAssassins regelfiler, og formatet på Bayes-databasen er dets eget: tren det fra den samme e-posten med `spamscanner train`.


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
