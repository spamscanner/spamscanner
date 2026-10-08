<!-- source: 9537a0e62eb0 -->

# Språk

Spam kommer på alla språk, och det gör vanlig e-post också. Spam Scanner läser båda, och det är försiktigt med språk som det kan lite om: ett spamfilter som flaggar varje arabiskt eller kinesiskt meddelande är sämre än inget alls.


## Att läsa alla skriftsystem

* **Ord.** Texten delas upp med `Intl.Segmenter`, som följer Unicode-reglerna för ordgränser och använder ordlistor för kinesiska, japanska, thailändska, laotiska, khmer och burmesiska, skriftsystem som skrivs utan mellanslag. Långa texter delas först upp i bitar, eftersom segmenteraren i Node.js 18 blir långsam på mycket långa strängar.
* **Normalisering.** Unicode NFKC gör om fullbreddsbokstäver och de flesta stiliserade bokstäver (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) till vanliga. Texten görs om till gemener enligt Unicode-reglerna.
* **Förklädnader.** Osynliga tecken inuti ord (`free` med ett nollbreddsmellanslag mellan två bokstäver, mjuka bindestreck) tas bort och räknas. Ord som blandar alfabet, som `pаypal` med ett kyrilliskt а, förs tillbaka till ett alfabet och räknas. Siffror som används som bokstäver (`v1agra`) viks ihop. Varje förklädnad är en egenskap i sig, och tre eller fler osynliga tecken, eller två eller fler blandade ord, ger också poäng.


## Att identifiera språket

Språket i varje meddelande identifieras från dess skriftsystem och, för skriftsystem som delas av många språk, från dess bokstäver:

* Hangul är koreanska; hiragana och katakana betyder japanska; thailändska, grekiska, hebreiska, armeniska, georgiska, bengaliska, tamilska och andra skriftsystem som används av ett enda språk anger det direkt.
* Kyrilliska bokstäver som bara finns i ett språk avgör mellan ukrainska (і, ї, є, ґ), belarusiska (ў), serbiska (ђ, ћ, џ), makedonska (ѓ, ќ, ѕ) och ryska (ы, э, ё).
* Text i skriftsystem som delas av flera språk (latinskt, kyrilliskt, arabiskt, devanagari med flera) går, när den är tillräckligt lång för att bedöma, till [franc](https://github.com/wooorm/franc), begränsat till språk som är vanliga i e-post så att korta meddelanden inte märks med ovanliga språk.

Språket rapporteras som `result.language`, och `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) lägger till 3 poäng på e-post som med säkerhet identifierats som något annat språk.


## Språk som modellen kan lite om

En klassificerare lär sig av exempel. Offentliga dataset med spam innehåller mycket mer spam än ham på andra språk än engelska, så en naiv klassificerare lär sig att kinesisk eller arabisk text i sig betyder spam. Spam Scanner kompenserar för detta på tre sätt:

1. **Språket är aldrig ett belägg.** Det identifierade språket och skriftsystemet används inte som ledtrådar.
2. **Ord vägs inom sitt språk.** Ett ords spamsannolikhet beräknas mot antalet spam- och hammeddelanden som klassificeraren har sett på meddelandets språk, inte på alla språk. Ett vardagligt portugisiskt ord i en modell som mest sett portugisisk spam förblir neutralt.
3. **Konfidensen följer täckningen.** Resultatet dras mot ”osäker” i proportion till hur många meddelanden av varje slag klassificeraren har sett på det språket: full konfidens kräver 1 000 av varje (eller 2 % av den mindre klassen, för små personliga modeller). Ett språk utan ham i träningsdatan får alltid ”osäker”.

Den medföljande modellen har aldrig sett [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), sms som maskinöversatts till 21 språk. Före dessa regler markerade den 5,7 % av den hammen som spam, däribland 55 % av den portugisiska och 41 % av den franska. Med dem 0,18 %: ingen på kinesiska, arabiska, koreanska, japanska, hindi, portugisiska, franska eller 20 andra språk, och 0,27 % på engelska.


## Att fånga spam på de språken

Osäker är säkert, men det fångar inte spam. Tre saker gör det:

* **De andra kontrollerna** beror inte på språket: förväxlingsbara domäner, vilseledande länkar, körbara filer, makron, autentisering, blocklistor, reglerna.
* **En språkmodell.** Moderna öppna modeller läser 100 till 200 språk, och Spam Scanner frågar en så snart klassificeraren är osäker. End-to-end-testerna kontrollerar att `qwen3.5:4b` fångar spam och släpper igenom ham på kinesiska, arabiska, koreanska, hindi och thailändska. [Språkmodeller](llm.md)
* **Träning på din e-post.** I en modell som tränats på din egen e-post ger några hundra meddelanden av varje slag på ett språk klassificeraren full konfidens där. [Träning](training.md), och [ett valfritt dataset](training.md#more-languages) som lägger till 21 språk.
