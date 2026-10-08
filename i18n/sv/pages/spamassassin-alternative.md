<!-- source: 1562b843d858 -->

<!--
label: Alternativ till SpamAssassin
title: Ett alternativ till SpamAssassin som talar spamd
description: Ersätt SpamAssassins spamd med Spam Scanner. spamc, Exim och Haraka fortsätter att fungera, X-Spam-huvudena behåller sina namn och alla språk stöds.
keywords: SpamAssassin alternativ, ersätta spamd, spamc, Exim spamfilter, Haraka spamassassin, rspamd alternativ, X-Spam-Status
-->

# Ett alternativ till SpamAssassin som talar spamd

Spam Scanner svarar på SpamAssassins spamd-protokoll, så programvara som skrivits för SpamAssassin använder det oförändrad: spamc, Exims villkor `spam`, Harakas insticksprogram `spamassassin` och andra.


## Byt in det

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

Det svarar på `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` och, med `--allow-tell`, `TELL` för inlärning. Projektets end-to-end-tester kör SpamAssassins egen spamc mot det.


## Vad som förblir detsamma

* Huvudena: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` och `X-Spam-Status` i SpamAssassins format, så befintliga regler i Sieve, procmail och e-postklienter fortsätter att fungera.
* En poäng med gränsvärdet 5, uppbyggd av namngivna tester med poäng: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` och så vidare.
* Poängen per test kan ändras med testets namn.


## Vad som skiljer sig

* **Språk.** Ord segmenteras med Unicode-reglerna, så kinesiska, japanska och thailändska läses som ord i stället för en lång sträng, och förklädnader som osynliga tecken eller kyrilliska bokstäver i latinska ord återställs först.
* **Nätfiske.** Förväxlingsbara domäner, vilseledande länkar och varumärken i visningsnamn kontrolleras utan extra regler.
* **Bilagor** identifieras genom sina byte: en körbar fil som bytt namn till `.pdf` är fortfarande en körbar fil.
* **Språkmodeller.** Gränsfall kan gå till en lokal modell via Ollama eller till en molnbaserad.
* **Node.js.** En enda `npm install`, eller en fristående binärfil; inga Perl-moduler eller regeluppdateringar att hantera.

Spam Scanner kör inte SpamAssassins regelfiler, och dess Bayes-databas har ett eget format: träna den från samma e-post med `spamscanner train`.


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

[Exim, Haraka, Dovecot och procmail](../../docs/mail-servers.md)
