<!-- source: 9537a0e62eb0 -->

# Nyelvek

A spam minden nyelven érkezik, és ugyanígy a hétköznapi levelek is. A Spam Scanner mindkettőt olvassa, és körültekintően bánik azokkal a nyelvekkel, amelyekről keveset tud: az a spamszűrő, amely minden arab vagy kínai levelet megjelöl, rosszabb, mint ha nem is lenne.


## Minden írásrendszer olvasása

* **Szavak.** A szöveget az `Intl.Segmenter` bontja fel, amely a Unicode szóhatár-szabályait követi, és szótárakat használ a kínaihoz, a japánhoz, a thaihoz, a laóhoz, a khmerhez és a burmaihoz, vagyis a szóközök nélkül írt írásrendszerekhez. A hosszú szövegeket előbb darabokra bontja, mert a Node.js 18 szegmentálója nagyon hosszú karakterláncokon lelassul.
* **Normalizálás.** A Unicode NFKC a teljes szélességű betűket és a legtöbb díszített betűt (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) egyszerű betűkké alakítja. A szöveg kisbetűsítése a Unicode-szabályok szerint történik.
* **Álcázások.** A szavakon belüli láthatatlan karaktereket (a `free` két betűje közötti nulla szélességű szóközt, a feltételes elválasztójeleket) eltávolítja és megszámolja. A több ábécét keverő szavakat, például a cirill а-t tartalmazó `pаypal` szót, visszaalakítja egyetlen ábécére, és megszámolja. A betűként használt számjegyeket (`v1agra`) visszaalakítja. Minden álcázás önálló jellemző, és három vagy több láthatatlan karakter, illetve két vagy több kevert szó további pontokat is ad.


## A nyelv felismerése

Minden levél nyelvét az írásrendszeréből, a több nyelv által használt írásrendszereknél pedig a betűiből ismeri fel:

* A hangul koreai; a hiragana és a katakana japánt jelent; a thai, a görög, a héber, az örmény, a grúz, a bengáli, a tamil és más, egyetlen nyelv által használt írásrendszerek közvetlenül megnevezik a nyelvet.
* A csak egy nyelvben előforduló cirill betűk döntenek az ukrán (і, ї, є, ґ), a belarusz (ў), a szerb (ђ, ћ, џ), a macedón (ѓ, ќ, ѕ) és az orosz (ы, э, ё) között.
* A több nyelv által használt írásrendszerekben (latin, cirill, arab, dévanágari és mások) írt szöveg, ha elég hosszú a megítéléshez, a [franc](https://github.com/wooorm/franc) könyvtárhoz kerül, amely az e-mailekben gyakori nyelvekre van korlátozva, hogy a rövid leveleket ne címkézze ritka nyelvekkel.

A nyelvet a `result.language` adja meg, az `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) pedig 3 pontot ad minden olyan levélhez, amelyet nagy biztonsággal más nyelvűnek ismer fel.


## Nyelvek, amelyekről a modell keveset tud

Az osztályozó példákból tanul. A nyilvános spam-adatkészletek sokkal több idegen nyelvű spamet tartalmaznak, mint idegen nyelvű hamet (kért levelet), így egy naiv osztályozó azt tanulja meg, hogy a kínai vagy arab szöveg már önmagában spamet jelent. A Spam Scanner ezt háromféleképpen korrigálja:

1. **A nyelv soha nem bizonyíték.** A felismert nyelvet és írásrendszert nem használja jelként.
2. **A szavakat a saját nyelvükön belül súlyozza.** Egy szó spamvalószínűségét azoknak a spam- és hamleveleknek a számához viszonyítja, amelyeket az osztályozó a levél nyelvén látott, nem pedig az összes nyelven. Egy hétköznapi portugál szó semleges marad egy olyan modellben, amely főleg portugál spamet látott.
3. **A magabiztosság a lefedettséget követi.** Az eredményt a „bizonytalan” felé húzza aszerint, hogy az osztályozó hány levelet látott az adott nyelven mindkét fajtából: a teljes magabiztossághoz mindkettőből 1000 kell (kis személyes modelleknél a kisebbik osztály 2%-a). Az a nyelv, amelyen a tanítóadatokban nincs ham, mindig „bizonytalan” eredményt kap.

A beépített modell soha nem látta az [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) adatkészletet, amely 21 nyelvre gépi fordítással átültetett SMS-üzeneteket tartalmaz. E szabályok előtt a modell az ottani ham 5,7%-át jelölte spamnek, köztük a portugál 55%-át és a francia 41%-át. A szabályokkal 0,18%-ot: semmit kínaiul, arabul, koreaiul, japánul, hindiül, portugálul, franciául és 20 további nyelven, angolul pedig 0,27%-ot.


## Spam kiszűrése ezeken a nyelveken

A bizonytalan eredmény biztonságos, de nem szűri ki a spamet. Három dolog igen:

* **A többi ellenőrzés** nem függ a nyelvtől: hasonmás domainek, megtévesztő hivatkozások, futtatható fájlok, makrók, hitelesítés, tiltólisták, szabályok.
* **Egy nyelvi modell.** A modern nyílt modellek 100–200 nyelvet olvasnak, és a Spam Scanner mindig megkérdez egyet, amikor az osztályozó bizonytalan. A végpontok közötti tesztek ellenőrzik, hogy a `qwen3.5:4b` kiszűri a spamet és átengedi a hamet kínaiul, arabul, koreaiul, hindiül és thaiul. [Nyelvi modellek](llm.md)
* **Tanítás a saját leveleken.** A saját leveleken tanított modellben egy nyelven mindkét fajtából néhány száz levél teljes magabiztosságot ad az osztályozónak az adott nyelven. [Tanítás](training.md), valamint [egy opcionális adatkészlet](training.md#more-languages), amely 21 nyelvet ad hozzá.
