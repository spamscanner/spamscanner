<!-- source: 9537a0e62eb0 -->

# Talen

Spam komt in elke taal binnen, en gewone mail ook. Spam Scanner leest allebei en is voorzichtig met talen waarvan het weinig weet: een spamfilter dat elk Arabisch of Chinees bericht markeert, is slechter dan geen spamfilter.


## Elk schrift lezen

* **Woorden.** Tekst wordt gesplitst met `Intl.Segmenter`, dat de Unicode-regels voor woordgrenzen volgt en woordenboeken gebruikt voor Chinees, Japans, Thai, Lao, Khmer en Birmaans, schriften die zonder spaties worden geschreven. Lange teksten worden eerst in stukken gesplitst, omdat de segmenter in Node.js 18 trager wordt bij zeer lange strings.
* **Normalisatie.** Unicode NFKC zet letters met volle breedte en de meeste opgemaakte letters (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) om naar gewone. Tekst wordt naar kleine letters omgezet volgens de Unicode-regels.
* **Vermommingen.** Onzichtbare tekens in woorden (`free` met een spatie zonder breedte tussen twee letters, zachte afbreekstreepjes) worden verwijderd en geteld. Woorden die alfabetten mengen, zoals `pаypal` met een Cyrillische а, worden teruggezet naar één alfabet en geteld. Cijfers die als letters worden gebruikt (`v1agra`) worden omgezet. Elke vermomming is een eigen kenmerk, en drie of meer onzichtbare tekens, of twee of meer gemengde woorden, voegen ook punten toe.


## De taal herkennen

De taal van elk bericht wordt herkend aan het schrift en, bij schriften die door veel talen worden gedeeld, aan de letters:

* Hangul is Koreaans; Hiragana en Katakana betekenen Japans; Thai, Grieks, Hebreeuws, Armeens, Georgisch, Bengaals, Tamil en andere schriften die door één taal worden gebruikt, noemen die taal direct.
* Cyrillische letters die in maar één taal voorkomen, beslissen tussen Oekraïens (і, ї, є, ґ), Wit-Russisch (ў), Servisch (ђ, ћ, џ), Macedonisch (ѓ, ќ, ѕ) en Russisch (ы, э, ё).
* Tekst in schriften die door meerdere talen worden gedeeld (Latijn, Cyrillisch, Arabisch, Devanagari en andere) gaat, als hij lang genoeg is om te beoordelen, naar [franc](https://github.com/wooorm/franc), beperkt tot talen die vaak in e-mail voorkomen, zodat korte berichten geen zeldzame taal als label krijgen.

De taal wordt gemeld als `result.language`, en `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) voegt 3 punten toe aan mail die met zekerheid in een andere taal is herkend.


## Talen waarvan het model weinig weet

Een classifier leert van voorbeelden. Openbare spamdatasets bevatten veel meer anderstalige spam dan anderstalige ham, zodat een naïeve classifier leert dat Chinese of Arabische tekst op zich al spam betekent. Spam Scanner corrigeert dat op drie manieren:

1. **De taal is nooit bewijs.** De herkende taal en het schrift worden niet als aanwijzing gebruikt.
2. **Woorden worden binnen hun taal gewogen.** De spamkans van een woord wordt berekend tegen het aantal spam- en hamberichten dat de classifier in de taal van het bericht zag, niet in alle talen samen. Een alledaags Portugees woord in een model dat vooral Portugese spam zag, blijft neutraal.
3. **Zekerheid volgt dekking.** Het resultaat wordt naar „onzeker” getrokken naar verhouding van het aantal berichten van elk soort dat de classifier in die taal zag: volledige zekerheid vraagt 1.000 van elk (of 2% van de kleinste klasse, voor kleine persoonlijke modellen). Een taal zonder ham in de trainingsdata krijgt altijd „onzeker”.

Het meegeleverde model heeft de [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) nooit gezien: sms-berichten die machinaal in 21 talen zijn vertaald. Voor deze regels markeerde het 5,7% van die ham als spam, waaronder 55% van de Portugese en 41% van de Franse. Met de regels is dat 0,18%: geen enkel bericht in het Chinees, Arabisch, Koreaans, Japans, Hindi, Portugees, Frans of 20 andere talen, en 0,27% in het Engels.


## Spam vangen in die talen

Onzeker is veilig, maar vangt geen spam. Drie dingen doen dat wel:

* **De andere controles** hangen niet van de taal af: lookalike-domeinen, misleidende links, uitvoerbare bestanden, macro's, authenticatie, blocklists, de regels.
* **Een taalmodel.** Moderne open modellen lezen 100 tot 200 talen, en Spam Scanner raadpleegt er een als de classifier onzeker is. De end-to-endtests controleren dat `qwen3.5:4b` spam vangt en ham doorlaat in het Chinees, Arabisch, Koreaans, Hindi en Thai. [Taalmodellen](llm.md)
* **Trainen op je mail.** In een model dat op je eigen mail is getraind, geven een paar honderd berichten van elk soort in een taal de classifier daar volledige zekerheid. [Training](training.md), en [een optionele dataset](training.md#more-languages) die 21 talen toevoegt.
