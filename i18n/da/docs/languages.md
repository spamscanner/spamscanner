<!-- source: 5d22e36f3f16 -->

# Sprog

Spam kommer på alle sprog, og det samme gør almindelig post. Spam Scanner læser begge og er forsigtig med sprog, den kender lidt til: et spamfilter, der markerer hver arabisk eller kinesisk besked, er værre end intet filter.


## Alle skriftsystemer læses

* **Ord.** Teksten opdeles med `Intl.Segmenter`, som følger Unicode-reglerne for ordgrænser og bruger ordbøger til kinesisk, japansk, thai, lao, khmer og burmesisk, skriftsystemer, der skrives uden mellemrum. Lange tekster deles først i stykker, fordi segmenteren i Node.js 18 bliver langsom på meget lange strenge.
* **Normalisering.** Unicode NFKC gør bogstaver i fuld bredde og de fleste stiliserede bogstaver (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) til almindelige. Teksten gøres til små bogstaver efter Unicode-reglerne.
* **Forklædninger.** Usynlige tegn inde i ord (`free` med et mellemrum med nul bredde mellem to bogstaver, eller `v1agra` med dem omkring 1-tallet) fjernes og tælles, men ikke dem mellem cifre, som afsendere sætter i tal, så telefoner ikke laver dem om til links, og heller ikke et mellemrum med nul bredde mellem bogstaver i thai, lao, khmer, burmesisk eller tibetansk, som skrivere af de skriftsystemer sætter, hvor et ord slutter. Joinerne (U+200C, U+200D), som persisk, indiske skriftsystemer og emoji har brug for, tæller kun mellem latinske bogstaver. Bløde bindestreger og de retningsmarkeringer, indlejringer og isoleringer, som hebraisk og arabisk tekst har brug for, fjernes uden at blive talt; de tilsidesættelser, der viser bogstaver i en anden rækkefølge (U+202D, U+202E), tæller i enhver tekst. Ord, der blander alfabeter, som `pаypal` med et kyrillisk а, oversættes til det alfabet, de fleste af deres bogstaver hører til, og tælles; en russisk kasusendelse efter et varemærkes navn og en apostrof (`iPhone'ы`) blander intet. Tal brugt som bogstaver (`v1agra`) foldes. Hver forklædning er en feature i sig selv, og tre eller flere usynlige tegn eller to eller flere blandede ord lægger også point til.


## Sproget genkendes

Hver beskeds sprog genkendes ud fra skriftsystemet og, for skriftsystemer, som mange sprog deler, ud fra bogstaverne:

* Hangul er koreansk; hiragana og katakana betyder japansk; thai, græsk, hebraisk, armensk, georgisk, bengali, tamil og andre skriftsystemer, der bruges af ét sprog, angiver det direkte.
* Kyrilliske bogstaver, der kun findes i ét sprog, afgør valget mellem ukrainsk (і, ї, є, ґ), hviderussisk (ў), serbisk (ђ, ћ, џ), makedonsk (ѓ, ќ, ѕ) og russisk (ы, э, ё) i de ord, der ikke er navne (ord med stort begyndelsesbogstav og resten små andre steder end i starten af en sætning eller en linje, ikke ord skrevet med store bogstaver, hvis bogstaver kun tæller i en tekst, der er for kort til den statistiske detektor: en bulgarsk tekst, der nævner "господин Рыскулов", er bulgarsk), medmindre teksten også har bogstaver fra kasakhisk, usbekisk, kirgisisk, tadsjikisk, tatarisk, basjkirsk eller mongolsk (ә, ө, ү, ұ, қ, ғ, ң, һ, ҳ, ҷ og andre), hvis alfabeter deler nogle af de bogstaver: så afgør den statistiske detektor, og når den svarer med et slavisk sprog (en russisk eller bulgarsk tekst med et kasakhisk navn eller ord i), afgør ordene uden de bogstaver, bortset fra navne, som ovenfor.
* Tekst i skriftsystemer, som flere sprog deler (latinsk, kyrillisk, arabisk, devanagari og andre), går, når den er lang nok til at bedømme, til [franc](https://github.com/wooorm/franc), begrænset til sprog, der er almindelige i e-mail, så korte beskeder ikke mærkes med sjældne sprog.

Sproget rapporteres som `result.language`, og `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) lægger 3 point til post, der med sikkerhed er genkendt som et hvilket som helst andet sprog.


## Sprog, modellen kender lidt til

En klassifikator lærer af eksempler. Offentlige spamdatasæt indeholder langt mere fremmedsproget spam end fremmedsproget ham, så en naiv klassifikator lærer, at kinesisk eller arabisk tekst i sig selv betyder spam. Spam Scanner retter op på det på tre måder:

1. **Sproget er aldrig et bevis.** Det genkendte sprog og skriftsystem bruges ikke som spor.
2. **Ord vejes inden for deres sprog.** Et ords spamsandsynlighed beregnes ud fra antallet af spam- og ham-beskeder, som klassifikatoren har set på beskedens sprog, ikke på alle sprog. Et dagligdags portugisisk ord i en model, der mest har set portugisisk spam, forbliver neutralt.
3. **Sikkerheden følger dækningen.** Resultatet trækkes mod »usikker« i forhold til, hvor mange beskeder af hver slags klassifikatoren har set på det sprog: fuld sikkerhed kræver 1.000 af hver (eller 2 % af den mindste klasse, for små personlige modeller). Et sprog uden ham i træningsdataene får altid »usikker«.

Den medfølgende model har aldrig set [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), SMS-beskeder maskinoversat til 21 sprog. Før disse regler markerede den 5,7 % af den ham som spam, heriblandt 55 % af den portugisiske og 41 % af den franske. Med dem 0,18 %: ingen på kinesisk, arabisk, koreansk, japansk, hindi, portugisisk, fransk eller 13 andre sprog og 0,27 % på engelsk.


## Spam fanges på de sprog

»Usikker« er sikkert, men det fanger ikke spam. Tre ting gør:

* **De andre tjek** afhænger ikke af sproget: forvekslelige domæner, vildledende links, programfiler, makroer, godkendelse, blokeringslister, reglerne.
* **En sprogmodel.** Moderne åbne modeller læser 100 til 200 sprog, og Spam Scanner spørger en, hver gang klassifikatoren er usikker. End-to-end-testene tjekker, at `qwen3.5:4b` fanger spam og lukker ham igennem på kinesisk, arabisk, koreansk, hindi og thai. [Sprogmodeller](llm.md)
* **Træning på din post.** I en model, der er trænet på din egen post, giver et par hundrede beskeder af hver slags på et sprog klassifikatoren fuld sikkerhed på det sprog. [Træning](training.md) og [et valgfrit datasæt](training.md#more-languages), der tilføjer 21 sprog.
