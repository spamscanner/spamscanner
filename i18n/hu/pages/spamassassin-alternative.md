<!-- source: 1562b843d858 -->

<!--
label: SpamAssassin alternatíva
title: SpamAssassin alternatíva, amely ismeri a spamd protokollt
description: A SpamAssassin spamd cseréje Spam Scannerre. A spamc, az Exim és a Haraka tovább működik, az X-Spam fejlécek neve marad, és minden nyelv támogatott.
keywords: SpamAssassin alternatíva, spamd csere, spamc, Exim spamszűrő, Haraka spamassassin, rspamd alternatíva, X-Spam-Status, spamszűrő levelezőszerverhez
-->

# SpamAssassin alternatíva, amely ismeri a spamd protokollt

A Spam Scanner a SpamAssassin spamd protokollján válaszol, így a SpamAssassinhoz írt szoftverek változatlanul használhatják: a spamc, az Exim `spam` feltétele, a Haraka `spamassassin` bővítménye és mások.


## Csere

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

Válaszol a `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` parancsokra, a `--allow-tell` kapcsolóval pedig a tanuláshoz használt `TELL` parancsra is. A projekt végpontok közötti tesztjei magát a SpamAssassin spamc-jét futtatják ellene.


## Ami ugyanaz marad

* A fejlécek: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` és `X-Spam-Status` a SpamAssassin formátumában, így a meglévő Sieve-, procmail- és levelezőkliens-szabályok tovább működnek.
* Egy 5-ös küszöbű pontszám, amely pontokkal rendelkező, megnevezett tesztekből áll: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` és így tovább.
* A tesztenkénti pontszámok a teszt neve alapján módosíthatók.


## Ami más

* **Nyelvek.** A szavakat a Unicode-szabályok szerint szegmentálja, így a kínai, a japán és a thai szöveget szavakként olvassa, nem egyetlen hosszú karakterláncként, az olyan álcázásokat pedig, mint a láthatatlan karakterek vagy a latin szavakban lévő cirill betűk, előbb feloldja.
* **Adathalászat.** A hasonmás domaineket, a megtévesztő hivatkozásokat és a megjelenített nevekben szereplő márkaneveket külön szabályok nélkül ellenőrzi.
* **A mellékleteket** a bájtjaik alapján azonosítja: a `.pdf` kiterjesztésre átnevezett futtatható fájl is futtatható fájl marad.
* **Nyelvi modellek.** A kétes esetek egy Ollamán keresztül futó helyi modellhez vagy egy szolgáltatói modellhez kerülhetnek.
* **Node.js.** Egyetlen `npm install` vagy egy önálló bináris fájl; nincs kezelendő Perl-modul vagy szabályfrissítés.

A Spam Scanner nem futtatja a SpamAssassin szabályfájljait, és a Bayes-adatbázisának formátuma is saját: ugyanazokból a levelekből a `spamscanner train` paranccsal tanítható.


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

[Exim, Haraka, Dovecot és procmail](../../docs/mail-servers.md)
