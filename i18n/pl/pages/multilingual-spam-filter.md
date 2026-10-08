<!-- source: 0ad167ddd34e -->

<!--
label: Wielojęzyczny filtr antyspamowy
title: Wielojęzyczny filtr antyspamowy: chiński, arabski, rosyjski i inne
description: Jak Spam Scanner filtruje spam w każdym języku: podział na słowa według Unicode, odwracanie maskowania i brak oznaczeń za język, o którym model wie mało.
keywords: wielojęzyczny filtr antyspamowy, filtr spamu chiński, filtr spamu arabski, filtr spamu rosyjski, filtr spamu japoński, wykrywanie spamu Unicode, spam homoglify
-->

# Wielojęzyczny filtr antyspamowy

Wiele filtrów antyspamowych zbudowano z myślą o angielskim. Spam w innych językach przechodzi przez nie, a zwykła poczta w innych językach jest oznaczana z powodu pisma. Spam Scanner zbudowano tak, aby unikać jednego i drugiego.


## Czytanie słów

Słowa są wyznaczane przez `Intl.Segmenter`, czyli reguły granic słów Unicode ze słownikami dla chińskiego, japońskiego, tajskiego, laotańskiego, khmerskiego i birmańskiego. Chińskie zdanie staje się słowami takimi jak 恭喜, 获得 i 大奖, a nie jednym długim ciągiem, który nigdy się nie powtarza.

Maskowanie jest odwracane przed liczeniem: niewidoczne znaki wewnątrz słów, litery cyrylicy lub greckie wewnątrz słów łacińskich (`pаypal`), cyfry zamiast liter (`v1agra`) oraz litery matematyczne lub w ramkach (𝐅𝐑𝐄𝐄). Każdy rodzaj maskowania jest też osobną wskazówką.


## Bez oznaczania tego, czego nie zna

Publiczne zbiory spamu zawierają znacznie więcej obcojęzycznego spamu niż obcojęzycznego hamu, więc naiwny klasyfikator uczy się, że sam tekst po arabsku czy koreańsku to spam. Spam Scanner nigdy nie używa języka jako wskazówki, waży każde słowo względem liczników spamu i hamu w jego własnym języku i pozostaje „niepewny” proporcjonalnie do tego, jak mało hamu widział w danym języku.

W teście na wiadomościach SMS w 21 językach, których dołączony model nigdy nie widział, sprowadziło to jego fałszywe alarmy po chińsku, arabsku, koreańsku, japońsku, w hindi, po bengalsku, w urdu, po turecku, ukraińsku i szwedzku do zera.


## Wyłapywanie spamu w każdym języku

* **Kontrole, które nie czytają słów:** podobne domeny, mylące linki, pliki wykonywalne, makra, SPF, DKIM, DMARC i czarne listy.
* **Model językowy** dla niepewnych wiadomości. Otwarte modele, takie jak Qwen 3.5 i Gemma 4, czytają od 140 do 200 języków; testy end-to-end sprawdzają spam i ham po chińsku, arabsku, koreańsku, w hindi i po tajsku na prawdziwym modelu.
* **Twoja własna poczta.** Kilkaset wiadomości każdego rodzaju w danym języku daje modelowi wytrenowanemu na twojej poczcie pełną pewność w tym języku.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Aby akceptować tylko niektóre języki, `--allow-language en,de` dodaje punkty poczcie, która z pewnością została rozpoznana jako napisana w innym języku.

[Języki szczegółowo](../../docs/languages.md)
