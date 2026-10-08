<!-- source: 0ad167ddd34e -->

<!--
label: Többnyelvű spamszűrő
title: Többnyelvű spamszűrő: kínai, arab, orosz és minden írásrendszer
description: Hogyan szűri a Spam Scanner a spamet minden nyelven: Unicode-szószegmentálás, az álcázások feloldása, és nem jelöli meg a modell által alig ismert nyelveket.
keywords: többnyelvű spamszűrő, kínai spamszűrő, arab spamszűrő, orosz spamszűrő, japán spamszűrő, magyar spamszűrő, Unicode spamfelismerés, homoglif spam
-->

# Többnyelvű spamszűrő

Sok spamszűrőt angol nyelvre építettek. A más nyelvű spam átjut rajtuk, a más nyelvű hétköznapi leveleket pedig az írásrendszerük miatt jelölik meg. A Spam Scanner úgy készült, hogy mindkettőt elkerülje.


## A szavak olvasása

A szavakat az `Intl.Segmenter` határozza meg, vagyis a Unicode szóhatár-szabályai, a kínaihoz, japánhoz, thaihoz, laóhoz, khmerhez és burmaihoz szótárakkal. Egy kínai mondatból olyan szavak lesznek, mint 恭喜, 获得 és 大奖, nem pedig egyetlen hosszú, soha nem ismétlődő karakterlánc.

Az álcázásokat a számlálás előtt feloldja: a szavakon belüli láthatatlan karaktereket, a latin szavakon belüli cirill vagy görög betűket (`pаypal`), a betűk helyetti számjegyeket (`v1agra`) és a matematikai vagy bekarikázott betűket (𝐅𝐑𝐄𝐄). Minden álcázás önmagában is jelzés.


## Nem jelöli meg, amit nem ismer

A nyilvános spam-adatkészletek sokkal több idegen nyelvű spamet tartalmaznak, mint idegen nyelvű hamet (kért levelet), így egy naiv osztályozó azt tanulja meg, hogy már maga az arab vagy koreai szöveg is spam. A Spam Scanner soha nem használja jelként a nyelvet, minden szót a saját nyelvének spam- és hamszámlálóihoz mér, és annál inkább „bizonytalan” marad, minél kevesebb hamet látott egy nyelven.

Egy 21 nyelvű, a beépített modell által soha nem látott SMS-üzeneteken végzett tesztben ez nullára csökkentette a téves pozitívokat kínaiul, arabul, koreaiul, japánul, hindiül, bengáliul, urduul, törökül, ukránul és svédül.


## Spam kiszűrése minden nyelven

* **Szavakat nem olvasó ellenőrzések:** hasonmás domainek, megtévesztő hivatkozások, futtatható fájlok, makrók, SPF, DKIM, DMARC és tiltólisták.
* **Egy nyelvi modell** a bizonytalan levelekhez. Az olyan nyílt modellek, mint a Qwen 3.5 és a Gemma 4, 140–200 nyelven olvasnak; a végpontok közötti tesztek valódi modellel ellenőrzik a spamet és a hamet kínaiul, arabul, koreaiul, hindiül és thaiul.
* **A saját levelek.** Egy nyelven mindkét fajtából néhány száz levél teljes magabiztosságot ad a saját leveleken tanított modellnek az adott nyelven.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Ha csak bizonyos nyelvek fogadhatók el, a `--allow-language en,de` pontokat ad minden olyan levélhez, amelyet nagy biztonsággal más nyelvűnek ismer fel.

[A nyelvek részletesen](../../docs/languages.md)
