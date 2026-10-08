<!-- source: c93fa1a3f9c7 -->

<!--
label: GYIK
title: Gyakran ismételt kérdések
description: Válaszok a Spam Scannerről: mennyire pontos, milyen nyelveket támogat, mit küld a hálózaton, nyelvi modellek, SpamAssassin és Forward Email.
keywords: Spam Scanner GYIK, spamszűrő kérdések, spamszűrő pontossága, spamszűrő adatvédelem
-->

# Gyakran ismételt kérdések


## Mi a Spam Scanner?

Spamszűrő Node.js-hez, a parancssorhoz és levelezőszerverekhez. Beolvas egy nyers e-mail-üzenetet, és pontszámmal, valamint a döntést meghozó tesztek listájával eldönti, hogy spam, adathalászat, csalás, vagy kártevőt tartalmaz-e. Futhat könyvtárként, Postfix- és Sendmail-milterként, SpamAssassin-kompatibilis spamd szerverként, Postfix-tartalomszűrőként, HTTP API-ként vagy TCP-szerverként.


## Ingyenes?

A [licence](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), a Business Source License 1.1, bármilyen felhasználást megenged, kivéve a spamfelismerés szolgáltatásként való nyújtását másoknak, és megnevezi azt a dátumot, amikor Apache License 2.0-ra vált.


## Mennyire pontos?

A tanítóadatokból félretett angol leveleken a beépített osztályozó önmagában egyetlen hamet (kért levelet) sem jelölt spamnek, és a spam 97%-át kiszűrte; a nyelvenkénti teljes számok a [tanítási útmutatóban](../../docs/training.md#the-bundled-model) találhatók. A hivatkozások, a mellékletek, a hitelesítés, a tiltólisták és egy nyelvi modell ehhez még hozzátesz. Az igazi teszt a saját levelezés: a `spamscanner eval` bármely modellt megmér bármely címkézett leveleken.


## Milyen nyelveket támogat?

Mindegyiket. A szavakat a Unicode-szabályok szerint szegmentálja, a szóközök nélküli kínait, japánt és thait is beleértve. Ahol a beépített modell kevés levelet látott egy nyelven, ott megjelölés helyett bizonytalan marad, és egy nyelvi modell vagy a saját tanítás dönt. [Nyelvek](../../docs/languages.md)


## Elküldi valahova a leveleimet?

Nem. Alapértelmezetten a hivatkozások gépneveit lekérdezi a Cloudflare szűrő DNS-feloldóin, és semmi más nem hagyja el a gépet. A hitelesítés, a tiltólisták, a nyelvi modellek és a hírnévszolgáltatások ki vannak kapcsolva, amíg be nem állítják őket, és mielőtt egy levél szolgáltatónál futó nyelvi modellhez kerülne, a személyes adatok eltávolításra kerülnek. [Biztonság és adatvédelem](../../docs/security.md)


## Szükség van nyelvi modellre?

Nem. A kétes esetekben ad második véleményt. Nélküle ezekről a levelekről egyedül a pontszámuk dönt.


## Melyik nyelvi modellt érdemes használni?

CPU-n a `qwen3.5:4b` Ollamán keresztül, GPU-val a `qwen3.5:9b`. Mindkettő Apache-licencű, és 201 nyelven olvas. Az Anthropic, az OpenAI, a Google és mások szolgáltatói modelljei is működnek. [Ajánlott modellek](../../docs/llm.md#recommended-open-models)


## Leválthatja a SpamAssassint?

A legtöbb környezetben igen: ismeri a spamd protokollját, így a spamc, az Exim és a Haraka változatlanul működik, és ugyanazokat az `X-Spam-*` fejléceket írja. A SpamAssassin szabályfájljait nem futtatja. [SpamAssassin alternatíva](/spamassassin-alternative/)


## Elutasít jogos leveleket?

A levelek visszautasítása alapértelmezetten ki van kapcsolva: a milter csak megjelöl. A `--reject` kapcsolóval csak a legalább 15 pontos leveleket utasítja vissza, ideiglenes 451-es hibával, így a feladók újra próbálkoznak, és egy tévedés egy beállítás módosításával javítható. A tartalomszűrő soha nem utasít vissza az SMTP-munkamenet közben.


## Hogyan tanítható a saját leveleken?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, majd `--model model.json`. Az mbox-fájlok, a Maildirek, a `.eml` fájlokat tartalmazó mappák és a CSV- vagy JSON Lines-adatkészletek mind működnek. [Tanítás](../../docs/training.md)


## Működik Node.js nélkül?

Igen: a Linuxra, macOS-re és Windowsra készült önálló bináris fájlok tartalmazzák a Node.js-t és a modellt. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Ki készíti?

A [Forward Email](https://forwardemail.net), a saját levelezőszerverei számára.
