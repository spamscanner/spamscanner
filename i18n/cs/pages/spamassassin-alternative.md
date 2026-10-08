<!-- source: 1562b843d858 -->

<!--
label: Alternativa ke SpamAssassinu
title: Alternativa ke SpamAssassinu, která mluví protokolem spamd
description: Nahraďte spamd ze SpamAssassinu Spam Scannerem. spamc, Exim a Haraka fungují dál, hlavičky X-Spam si zachovají názvy a podporován je každý jazyk.
keywords: alternativa SpamAssassin, náhrada SpamAssassin, náhrada spamd, spamc, spamový filtr Exim, Haraka spamassassin, alternativa rspamd, X-Spam-Status
-->

# Alternativa ke SpamAssassinu, která mluví protokolem spamd

Spam Scanner odpovídá na protokol spamd ze SpamAssassinu, takže ho software napsaný pro SpamAssassin používá beze změn: spamc, podmínka `spam` v Eximu, plugin `spamassassin` v Haraka a další.


## Výměna

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

Odpovídá na `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` a s `--allow-tell` také na `TELL` pro učení. Testy end-to-end projektu proti němu spouštějí spamc přímo ze SpamAssassinu.


## Co zůstává stejné

* Hlavičky: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` a `X-Spam-Status` ve formátu SpamAssassinu, takže stávající pravidla Sieve, procmailu a poštovních klientů fungují dál.
* Skóre s prahem 5, složené z pojmenovaných testů s body: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` a tak dále.
* Skóre jednotlivých testů lze měnit podle názvu testu.


## Co je jinak

* **Jazyky.** Slova se dělí podle pravidel Unicode, takže čínština, japonština a thajština se čtou jako slova, a ne jako jeden dlouhý řetězec, a maskování jako neviditelné znaky nebo cyrilická písmena v latinkových slovech se nejprve odstraní.
* **Phishing.** Podobně vypadající domény, klamavé odkazy a názvy značek v zobrazovaných jménech se kontrolují bez dalších pravidel.
* **Přílohy** se rozpoznávají podle bajtů: spustitelný soubor přejmenovaný na `.pdf` zůstává spustitelným souborem.
* **Jazykové modely.** Hraniční případy může posoudit lokální model přes Ollama nebo hostovaný model.
* **Node.js.** Jediné `npm install` nebo samostatná binárka; žádné moduly Perlu ani aktualizace pravidel ke správě.

Spam Scanner nespouští soubory pravidel SpamAssassinu a jeho formát Bayesovy databáze je vlastní: natrénujte ho ze stejné pošty pomocí `spamscanner train`.


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

[Exim, Haraka, Dovecot a procmail](../../docs/mail-servers.md)
