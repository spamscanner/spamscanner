<!-- source: 0ad167ddd34e -->

<!--
label: Meertalig spamfilter
title: Meertalig spamfilter voor Chinees, Arabisch, Russisch en meer
description: Hoe Spam Scanner spam in elke taal filtert: Unicode-woordsegmentatie, vermommingen ongedaan maken en nooit een onbekende taal als spam markeren.
keywords: meertalig spamfilter, spamfilter meerdere talen, Chinese spam filteren, Arabische spam, Russische spam, Japanse spam, Unicode spamdetectie, homoglyph spam
-->

# Meertalig spamfilter

Veel spamfilters zijn gebouwd voor het Engels. Spam in andere talen glipt erlangs, en gewone mail in andere talen wordt om het schrift gemarkeerd. Spam Scanner is gebouwd om allebei te voorkomen.


## De woorden lezen

Woorden worden gevonden met `Intl.Segmenter`, de Unicode-regels voor woordgrenzen met woordenboeken voor Chinees, Japans, Thai, Lao, Khmer en Birmaans. Een Chinese zin wordt woorden zoals 恭喜, 获得 en 大奖, niet één lange string die nooit terugkomt.

Vermommingen worden voor het tellen ongedaan gemaakt: onzichtbare tekens in woorden, Cyrillische of Griekse letters in Latijnse woorden (`pаypal`), cijfers in plaats van letters (`v1agra`), en wiskundige of omcirkelde letters (𝐅𝐑𝐄𝐄). Elke vermomming is ook een aanwijzing op zich.


## Niet markeren wat het niet kent

Openbare spamdatasets bevatten veel meer anderstalige spam dan anderstalige ham, zodat een naïeve classifier leert dat Arabische of Koreaanse tekst op zich spam is. Spam Scanner gebruikt de taal nooit als aanwijzing, weegt elk woord tegen de spam- en hamaantallen van de eigen taal, en blijft „onzeker” naar verhouding van hoe weinig ham het in een taal heeft gezien.

In een test op sms-berichten in 21 talen die het meegeleverde model nooit had gezien, bracht dit de fout-positieven in het Chinees, Arabisch, Koreaans, Japans, Hindi, Bengaals, Urdu, Turks, Oekraïens en Zweeds terug naar nul.


## Spam vangen in elke taal

* **Controles die geen woorden lezen:** lookalike-domeinen, misleidende links, uitvoerbare bestanden, macro's, SPF, DKIM, DMARC en blocklists.
* **Een taalmodel** voor onzekere berichten. Open modellen zoals Qwen 3.5 en Gemma 4 lezen 140 tot 200 talen; de end-to-endtests controleren spam en ham in het Chinees, Arabisch, Koreaans, Hindi en Thai met een echt model.
* **Je eigen mail.** Een paar honderd berichten van elk soort in een taal geven een model dat op je mail is getraind daar volledige zekerheid.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Om alleen bepaalde talen te accepteren, voegt `--allow-language en,de` punten toe aan mail die met zekerheid in een andere taal is herkend.

[Talen in detail](../../docs/languages.md)
