<!-- source: 1562b843d858 -->

<!--
label: Vaihtoehto SpamAssassinille
title: SpamAssassin-vaihtoehto, joka puhuu spamd-protokollaa
description: Korvaa SpamAssassinin spamd Spam Scannerilla. spamc, Exim ja Haraka toimivat edelleen, X-Spam-otsakkeet säilyttävät nimensä, ja kaikkia kieliä tuetaan.
keywords: SpamAssassin vaihtoehto, spamd korvaaja, spamc, Exim roskapostisuodatin, Haraka spamassassin, rspamd vaihtoehto, X-Spam-Status
-->

# SpamAssassin-vaihtoehto, joka puhuu spamd-protokollaa

Spam Scanner vastaa SpamAssassinin spamd-protokollaan, joten SpamAssassinille kirjoitettu ohjelmisto käyttää sitä muuttamattomana: spamc, Eximin `spam`-ehto, Harakan `spamassassin`-laajennus ja muut.


## Vaihda se tilalle

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

Se vastaa komentoihin `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` ja valitsimella `--allow-tell` myös `TELL` oppimista varten. Projektin päästä päähän -testit ajavat SpamAssassinin omaa spamc:tä sitä vastaan.


## Mikä pysyy samana

* Otsakkeet: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` ja `X-Spam-Status` SpamAssassinin muodossa, joten olemassa olevat Sieve-, procmail- ja sähköpostiohjelmien säännöt toimivat edelleen.
* Pistemäärä, jonka raja on 5 ja joka koostuu nimetyistä testeistä pisteineen: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` ja niin edelleen.
* Testikohtaisia pisteitä voi muuttaa testin nimen mukaan.


## Mikä on erilaista

* **Kielet.** Sanat pilkotaan Unicoden sääntöjen mukaan, joten kiina, japani ja thai luetaan sanoina eikä yhtenä pitkänä merkkijonona, ja naamioinnit, kuten näkymättömät merkit tai kyrilliset kirjaimet latinalaisissa sanoissa, puretaan ensin.
* **Tietojenkalastelu.** Samannäköiset verkkotunnukset, harhaanjohtavat linkit ja tuotemerkkien nimet näyttönimissä tarkistetaan ilman lisäsääntöjä.
* **Liitteet** tunnistetaan niiden tavuista: muotoon `.pdf` nimetty suoritettava tiedosto on edelleen suoritettava tiedosto.
* **Kielimallit.** Epäselvät tapaukset voidaan lähettää paikalliselle mallille Ollaman kautta tai palveluna tarjotulle mallille.
* **Node.js.** Yksi `npm install` tai erillinen binääri; ei hallittavia Perl-moduuleja tai sääntöpäivityksiä.

Spam Scanner ei aja SpamAssassinin sääntötiedostoja, ja sen Bayes-tietokannan muoto on sen oma: kouluta se samasta postista komennolla `spamscanner train`.


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

[Exim, Haraka, Dovecot ja procmail](../../docs/mail-servers.md)
