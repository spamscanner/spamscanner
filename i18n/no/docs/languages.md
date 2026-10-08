<!-- source: 9537a0e62eb0 -->

# Språk

Spam kommer på alle språk, og det gjør vanlig e-post også. Spam Scanner leser begge deler og er forsiktig med språk det vet lite om: et spamfilter som flagger hver arabiske eller kinesiske melding, er verre enn ingen filter.


## Å lese alle skriftsystemer

* **Ord.** Teksten deles med `Intl.Segmenter`, som følger Unicode-reglene for ordgrenser og bruker ordbøker for kinesisk, japansk, thai, lao, khmer og burmesisk, skriftsystemer som skrives uten mellomrom. Lange tekster deles først opp i biter, fordi segmenteringen i Node.js 18 blir treg på svært lange strenger.
* **Normalisering.** Unicode NFKC gjør bokstaver i full bredde og de fleste stiliserte bokstaver (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) om til vanlige bokstaver. Teksten gjøres om til små bokstaver etter Unicode-reglene.
* **Forkledninger.** Usynlige tegn inne i ord (`free` med et mellomrom med null bredde mellom to bokstaver, myke bindestreker) fjernes og telles. Ord som blander alfabeter, som `pаypal` med en kyrillisk а, føres tilbake til ett alfabet og telles. Sifre brukt som bokstaver (`v1agra`) gjøres om. Hver forkledning er en egen egenskap, og tre eller flere usynlige tegn, eller to eller flere blandede ord, gir også poeng.


## Å gjenkjenne språket

Språket i hver melding gjenkjennes ut fra skriftsystemet og, for skriftsystemer som deles av mange språk, ut fra bokstavene:

* Hangul er koreansk; hiragana og katakana betyr japansk; thai, gresk, hebraisk, armensk, georgisk, bengali, tamil og andre skriftsystemer som brukes av ett språk, angir språket direkte.
* Kyrilliske bokstaver som bare finnes i ett språk, avgjør mellom ukrainsk (і, ї, є, ґ), hviterussisk (ў), serbisk (ђ, ћ, џ), makedonsk (ѓ, ќ, ѕ) og russisk (ы, э, ё).
* Tekst i skriftsystemer som deles av flere språk (latinsk, kyrillisk, arabisk, devanagari og andre), sendes til [franc](https://github.com/wooorm/franc) når den er lang nok til å vurderes, begrenset til språk som er vanlige i e-post, slik at korte meldinger ikke merkes med sjeldne språk.

Språket rapporteres som `result.language`, og `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) gir 3 poeng til e-post som med sikkerhet er gjenkjent som et hvilket som helst annet språk.


## Språk modellen vet lite om

En klassifiserer lærer av eksempler. Offentlige spamdatasett inneholder langt mer spam enn ham på andre språk enn engelsk, så en naiv klassifiserer lærer at kinesisk eller arabisk tekst i seg selv betyr spam. Spam Scanner korrigerer for dette på tre måter:

1. **Språket er aldri bevis.** Det gjenkjente språket og skriftsystemet brukes ikke som indisier.
2. **Ord vektes innenfor sitt eget språk.** Spamsannsynligheten for et ord beregnes mot antall spam- og ham-meldinger klassifisereren har sett på meldingens språk, ikke på alle språk. Et vanlig portugisisk ord i en modell som hovedsakelig har sett portugisisk spam, forblir nøytralt.
3. **Tilliten følger dekningen.** Resultatet trekkes mot «usikker» i forhold til hvor mange meldinger av hver type klassifisereren har sett på det språket: full tillit krever 1 000 av hver (eller 2 % av den minste klassen, for små personlige modeller). Et språk uten ham i treningsdataene får alltid «usikker».

Den medfølgende modellen har aldri sett [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), SMS-meldinger maskinoversatt til 21 språk. Før disse reglene merket den 5,7 % av hammen der som spam, inkludert 55 % av den portugisiske og 41 % av den franske. Med reglene: 0,18 %, ingen på kinesisk, arabisk, koreansk, japansk, hindi, portugisisk, fransk eller 20 andre språk, og 0,27 % på engelsk.


## Å fange spam på disse språkene

Usikker er trygt, men fanger ikke spam. Tre ting gjør det:

* **De andre sjekkene** avhenger ikke av språket: forvekslingsdomener, villedende lenker, kjørbare filer, makroer, autentisering, blokkeringslister, reglene.
* **En språkmodell.** Moderne åpne modeller leser 100 til 200 språk, og Spam Scanner spør en hver gang klassifisereren er usikker. Ende-til-ende-testene sjekker at `qwen3.5:4b` fanger spam og slipper gjennom ham på kinesisk, arabisk, koreansk, hindi og thai. [Språkmodeller](llm.md)
* **Trening på din e-post.** I en modell trent på din egen e-post gir noen hundre meldinger av hver type på et språk klassifisereren full tillit der. [Trening](training.md), og [et valgfritt datasett](training.md#more-languages) som legger til 21 språk.
