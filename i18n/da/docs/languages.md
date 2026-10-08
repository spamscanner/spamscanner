<!-- source: 9537a0e62eb0 -->

# Sprog

Spam kommer på alle sprog, og det samme gør almindelig post. Spam Scanner læser begge og er forsigtig med sprog, den kender lidt til: et spamfilter, der markerer hver arabisk eller kinesisk besked, er værre end intet filter.


## Alle skriftsystemer læses

* **Ord.** Teksten opdeles med `Intl.Segmenter`, som følger Unicode-reglerne for ordgrænser og bruger ordbøger til kinesisk, japansk, thai, lao, khmer og burmesisk, skriftsystemer, der skrives uden mellemrum. Lange tekster deles først i stykker, fordi segmenteren i Node.js 18 bliver langsom på meget lange strenge.
* **Normalisering.** Unicode NFKC gør bogstaver i fuld bredde og de fleste stiliserede bogstaver (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) til almindelige. Teksten gøres til små bogstaver efter Unicode-reglerne.
* **Forklædninger.** Usynlige tegn inde i ord (`free` med et mellemrum med nul bredde mellem to bogstaver, bløde bindestreger) fjernes og tælles. Ord, der blander alfabeter, som `pаypal` med et kyrillisk а, oversættes tilbage til ét alfabet og tælles. Tal brugt som bogstaver (`v1agra`) foldes. Hver forklædning er en feature i sig selv, og tre eller flere usynlige tegn eller to eller flere blandede ord lægger også point til.


## Sproget genkendes

Hver beskeds sprog genkendes ud fra skriftsystemet og, for skriftsystemer, som mange sprog deler, ud fra bogstaverne:

* Hangul er koreansk; hiragana og katakana betyder japansk; thai, græsk, hebraisk, armensk, georgisk, bengali, tamil og andre skriftsystemer, der bruges af ét sprog, angiver det direkte.
* Kyrilliske bogstaver, der kun findes i ét sprog, afgør valget mellem ukrainsk (і, ї, є, ґ), hviderussisk (ў), serbisk (ђ, ћ, џ), makedonsk (ѓ, ќ, ѕ) og russisk (ы, э, ё).
* Tekst i skriftsystemer, som flere sprog deler (latinsk, kyrillisk, arabisk, devanagari og andre), går, når den er lang nok til at bedømme, til [franc](https://github.com/wooorm/franc), begrænset til sprog, der er almindelige i e-mail, så korte beskeder ikke mærkes med sjældne sprog.

Sproget rapporteres som `result.language`, og `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) lægger 3 point til post, der med sikkerhed er genkendt som et hvilket som helst andet sprog.


## Sprog, modellen kender lidt til

En klassifikator lærer af eksempler. Offentlige spamdatasæt indeholder langt mere fremmedsproget spam end fremmedsproget ham, så en naiv klassifikator lærer, at kinesisk eller arabisk tekst i sig selv betyder spam. Spam Scanner retter op på det på tre måder:

1. **Sproget er aldrig et bevis.** Det genkendte sprog og skriftsystem bruges ikke som spor.
2. **Ord vejes inden for deres sprog.** Et ords spamsandsynlighed beregnes ud fra antallet af spam- og ham-beskeder, som klassifikatoren har set på beskedens sprog, ikke på alle sprog. Et dagligdags portugisisk ord i en model, der mest har set portugisisk spam, forbliver neutralt.
3. **Sikkerheden følger dækningen.** Resultatet trækkes mod »usikker« i forhold til, hvor mange beskeder af hver slags klassifikatoren har set på det sprog: fuld sikkerhed kræver 1.000 af hver (eller 2 % af den mindste klasse, for små personlige modeller). Et sprog uden ham i træningsdataene får altid »usikker«.

Den medfølgende model har aldrig set [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), SMS-beskeder maskinoversat til 21 sprog. Før disse regler markerede den 5,7 % af den ham som spam, heriblandt 55 % af den portugisiske og 41 % af den franske. Med dem 0,18 %: ingen på kinesisk, arabisk, koreansk, japansk, hindi, portugisisk, fransk eller 20 andre sprog og 0,27 % på engelsk.


## Spam fanges på de sprog

»Usikker« er sikkert, men det fanger ikke spam. Tre ting gør:

* **De andre tjek** afhænger ikke af sproget: forvekslelige domæner, vildledende links, programfiler, makroer, godkendelse, blokeringslister, reglerne.
* **En sprogmodel.** Moderne åbne modeller læser 100 til 200 sprog, og Spam Scanner spørger en, hver gang klassifikatoren er usikker. End-to-end-testene tjekker, at `qwen3.5:4b` fanger spam og lukker ham igennem på kinesisk, arabisk, koreansk, hindi og thai. [Sprogmodeller](llm.md)
* **Træning på din post.** I en model, der er trænet på din egen post, giver et par hundrede beskeder af hver slags på et sprog klassifikatoren fuld sikkerhed på det sprog. [Træning](training.md) og [et valgfrit datasæt](training.md#more-languages), der tilføjer 21 sprog.
