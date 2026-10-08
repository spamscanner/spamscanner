<!-- source: 361732724f0e -->

<!--
label: UKK
title: Usein kysytyt kysymykset
description: Vastauksia Spam Scannerista: kuinka tarkka se on, mitä kieliä se tukee, mitä se lähettää verkkoon, kielimallit, SpamAssassin ja Forward Email.
keywords: Spam Scanner UKK, roskapostisuodatin kysymykset, roskapostisuodattimen tarkkuus, roskapostisuodatin yksityisyys
-->

# Usein kysytyt kysymykset


## Mikä Spam Scanner on?

Roskapostisuodatin Node.js:lle, komentoriville ja postipalvelimille. Se lukee raakamuotoisen sähköpostiviestin ja päättää, onko se roskapostia, tietojenkalastelua tai huijaus tai sisältääkö se haittaohjelman, ja antaa pistemäärän ja luettelon päätökseen vaikuttaneista testeistä. Se toimii kirjastona, milterinä Postfixille ja Sendmailille, SpamAssassin-yhteensopivana spamd-palvelimena, Postfixin sisältösuodattimena, HTTP API:na tai TCP-palvelimena.


## Onko se ilmainen?

Sen [lisenssi](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), Business Source License 1.1, sallii kaiken käytön paitsi roskapostin tunnistuksen tarjoamisen palveluna muille, ja se nimeää päivämäärän, jolloin lisenssi vaihtuu Apache License 2.0:ksi.


## Kuinka tarkka se on?

Koulutusaineistosta erilleen jätetyillä englanninkielisillä viesteillä mukana tuleva luokitin yksinään ei merkinnyt yhtään hamia roskapostiksi ja tunnisti 97 % roskapostista; kaikki luvut kielittäin ovat [koulutusoppaassa](../../docs/training.md#the-bundled-model). Linkit, liitteet, todennus, estolistat ja kielimalli lisäävät tähän. Oma postisi on todellinen testi: `spamscanner eval` mittaa minkä tahansa mallin millä tahansa luokitellulla postilla.


## Mitä kieliä se tukee?

Kaikkia. Se pilkkoo sanat Unicoden sääntöjen mukaan, myös kiinan, japanin ja thain, joissa ei ole välilyöntejä. Kun mukana tuleva malli on nähnyt kieltä vähän, se pysyy epävarmana eikä merkitse viestiä, ja kielimalli tai oma koulutuksesi ratkaisee. [Kielet](../../docs/languages.md)


## Lähettääkö se postiani minnekään?

Ei. Oletuksena se tarkistaa linkkien isäntänimet Cloudflaren suodattavista DNS-palveluista, eikä mikään muu lähde koneelta. Todennus, estolistat, kielimallit ja mainepalvelut ovat pois käytöstä, kunnes ne määritetään, ja henkilötiedot poistetaan ennen kuin posti lähetetään palveluna tarjotulle kielimallille. [Tietoturva ja yksityisyys](../../docs/security.md)


## Tarvitsenko kielimallin?

Et. Se on toinen mielipide epäselviin tapauksiin. Ilman sitä nämä viestit ratkaistaan pelkän pistemäärän perusteella.


## Mitä kielimallia minun kannattaa käyttää?

`qwen3.5:4b` Ollaman kautta suorittimella tai `qwen3.5:9b` näytönohjaimella. Molemmat ovat Apache-lisensoituja ja lukevat 201 kieltä. Spam Scanner lukee kunkin tuomion todennäköisyyden mallin yhdestä askeleesta, mikä kaksiytimisellä suorittimella vei noin 11 sekuntia viestiä kohden kirjoitetun vastauksen 31 sekunnin sijaan, samalla tarkkuudella. Palveluna toimivista vaihtoehdoista päätösmallit Cloudflare Clef ja TypeSafe Jev vastaavat alle sekunnissa; myös Anthropicin, OpenAI:n, Googlen ja muiden mallit toimivat. [Mittaukset](../../docs/llm.md#measured) ja [suositellut mallit](../../docs/llm.md#recommended-open-models)


## Voiko se korvata SpamAssassinin?

Useimmissa kokoonpanoissa kyllä: se puhuu spamd:n protokollaa, joten spamc, Exim ja Haraka toimivat muuttamattomina, ja se kirjoittaa samat `X-Spam-*`-otsakkeet. Se ei aja SpamAssassinin sääntötiedostoja. [Vaihtoehto SpamAssassinille](/spamassassin-alternative/)


## Hylkääkö se oikeaa postia?

Postin hylkääminen on oletuksena pois käytöstä: milter vain merkitsee. Valitsimella `--reject` hylätään vain viestit, joiden pistemäärä on 15 tai enemmän, ja hylkäys tehdään väliaikaisella 451-virheellä, joten lähettäjät yrittävät uudelleen ja virheen voi korjata muuttamalla asetusta. Sisältösuodatin ei koskaan hylkää SMTP-istunnon aikana.


## Miten koulutan sen omalla postillani?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json` ja sitten `--model model.json`. Mbox-tiedostot, Maildir-hakemistot, `.eml`-tiedostojen kansiot sekä CSV- ja JSON Lines -aineistot toimivat kaikki. [Koulutus](../../docs/training.md)


## Toimiiko se ilman Node.js:ää?

Kyllä: Linuxin, macOS:n ja Windowsin erilliset binäärit sisältävät Node.js:n ja mallin. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Kuka sen tekee?

[Forward Email](https://forwardemail.net) omille postipalvelimilleen.
