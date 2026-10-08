<!-- source: 0ad167ddd34e -->

<!--
label: Monikielinen roskapostisuodatin
title: Monikielinen roskapostisuodatin kiinalle, arabialle ja venäjälle
description: Miten Spam Scanner suodattaa roskapostia kaikilla kielillä: Unicode-sanojen pilkkominen, naamiointien purku eikä merkintöjä kielistä, joita malli ei tunne.
keywords: monikielinen roskapostisuodatin, kiinankielinen roskaposti, arabiankielinen roskaposti, venäjänkielinen roskaposti, japaninkielinen roskaposti, Unicode roskapostin tunnistus, homoglyfi roskaposti
-->

# Monikielinen roskapostisuodatin

Monet roskapostisuodattimet on tehty englannille. Muunkieliset roskapostit pääsevät niistä läpi, ja muunkielinen tavallinen posti merkitään kirjoitusjärjestelmänsä vuoksi. Spam Scanner on tehty välttämään molemmat.


## Sanojen lukeminen

Sanat löydetään `Intl.Segmenter`illä, eli Unicoden sanarajasäännöillä, joissa on sanakirjat kiinalle, japanille, thaille, laolle, khmerille ja burmalle. Kiinankielisestä lauseesta tulee sanoja kuten 恭喜, 获得 ja 大奖, ei yhtä pitkää merkkijonoa, joka ei koskaan toistu.

Naamioinnit puretaan ennen laskemista: näkymättömät merkit sanojen sisällä, kyrilliset tai kreikkalaiset kirjaimet latinalaisissa sanoissa (`pаypal`), numerot kirjainten tilalla (`v1agra`) sekä matemaattiset tai kehystetyt kirjaimet (𝐅𝐑𝐄𝐄). Jokainen naamiointi on myös oma vihjeensä.


## Tuntematonta ei merkitä

Julkisissa roskapostiaineistoissa on paljon enemmän vieraskielistä roskapostia kuin vieraskielistä hamia, joten naiivi luokitin oppii, että arabian- tai koreankielinen teksti itsessään on roskapostia. Spam Scanner ei koskaan käytä kieltä vihjeenä, punnitsee jokaista sanaa sen oman kielen roskaposti- ja ham-määriä vasten ja pysyy "epävarmana" suhteessa siihen, kuinka vähän hamia se on nähnyt kielellä.

Testissä 21 kielen tekstiviesteillä, joita mukana tuleva malli ei koskaan nähnyt, tämä pudotti väärät positiiviset nollaan kiinassa, arabiassa, koreassa, japanissa, hindissä, bengalissa, urdussa, turkissa, ukrainassa ja ruotsissa.


## Roskapostin tunnistaminen kaikilla kielillä

* **Tarkistukset, jotka eivät lue sanoja:** samannäköiset verkkotunnukset, harhaanjohtavat linkit, suoritettavat tiedostot, makrot, SPF, DKIM, DMARC ja estolistat.
* **Kielimalli** epävarmoille viesteille. Avoimet mallit, kuten Qwen 3.5 ja Gemma 4, lukevat 140–200 kieltä; päästä päähän -testit tarkistavat roskapostin ja hamin kiinaksi, arabiaksi, koreaksi, hindiksi ja thaiksi oikealla mallilla.
* **Oma postisi.** Muutama sata kunkin lajin viestiä kielellä antaa omalla postillasi koulutetulle mallille täyden varmuuden kyseisellä kielellä.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Jos haluat hyväksyä vain tietyt kielet, `--allow-language en,de` lisää pisteitä postille, joka on varmuudella tunnistettu millä tahansa muulla kielellä kirjoitetuksi.

[Kielet tarkemmin](../../docs/languages.md)
