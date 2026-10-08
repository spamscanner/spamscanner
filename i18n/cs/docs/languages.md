<!-- source: 9537a0e62eb0 -->

# Jazyky

Spam přichází v každém jazyce a běžná pošta také. Spam Scanner čte obojí a je opatrný u jazyků, o kterých ví málo: spamový filtr, který označí každou arabskou nebo čínskou zprávu, je horší než žádný.


## Čtení každého písma

* **Slova.** Text se dělí pomocí `Intl.Segmenter`, který se řídí pravidly Unicode pro hranice slov a používá slovníky pro čínštinu, japonštinu, thajštinu, laoštinu, khmerštinu a barmštinu, tedy písma psaná bez mezer. Dlouhé texty se nejprve rozdělí na části, protože segmentátor v Node.js 18 se na velmi dlouhých řetězcích zpomaluje.
* **Normalizace.** Unicode NFKC převede písmena plné šířky a většinu stylizovaných písmen (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) na obyčejná. Text se převádí na malá písmena podle pravidel Unicode.
* **Maskování.** Neviditelné znaky uvnitř slov (`free` s mezerou nulové šířky mezi dvěma písmeny, měkké spojovníky) se odstraní a spočítají. Slova, která míchají abecedy, například `pаypal` s cyrilickým а, se převedou zpět na jednu abecedu a spočítají. Číslice použité místo písmen (`v1agra`) se nahradí. Každý druh maskování je samostatný příznak a tři nebo více neviditelných znaků, nebo dvě či více smíšených slov, také přidávají body.


## Rozpoznání jazyka

Jazyk každé zprávy se rozpozná podle písma a u písem, která sdílí mnoho jazyků, podle písmen:

* Hangul je korejština; hiragana a katakana znamenají japonštinu; thajské písmo, řecké písmo, hebrejské písmo, arménské písmo, gruzínské písmo, bengálské písmo, tamilské písmo a další písma, která používá jediný jazyk, ho určují přímo.
* Cyrilická písmena, která se vyskytují jen v jednom jazyce, rozhodnou mezi ukrajinštinou (і, ї, є, ґ), běloruštinou (ў), srbštinou (ђ, ћ, џ), makedonštinou (ѓ, ќ, ѕ) a ruštinou (ы, э, ё).
* Text v písmech, která sdílí více jazyků (latinka, cyrilice, arabské písmo, dévanágarí a další), jde, pokud je dost dlouhý na posouzení, do [franc](https://github.com/wooorm/franc), omezeného na jazyky běžné v e-mailu, aby krátké zprávy nedostaly štítek vzácného jazyka.

Jazyk se uvádí v `result.language` a `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) přidá 3 body poště, která je s jistotou rozpoznaná v jakémkoli jiném jazyce.


## Jazyky, o kterých model ví málo

Klasifikátor se učí z příkladů. Veřejné datové sady spamu obsahují mnohem víc cizojazyčného spamu než cizojazyčného hamu, takže naivní klasifikátor se naučí, že čínský nebo arabský text sám o sobě znamená spam. Spam Scanner to vyrovnává třemi způsoby:

1. **Jazyk nikdy není důkazem.** Rozpoznaný jazyk a písmo se jako indicie nepoužívají.
2. **Slova se váží v rámci svého jazyka.** Pravděpodobnost spamu pro slovo se počítá vůči počtu spamových a hamových zpráv, které klasifikátor viděl v jazyce zprávy, ne ve všech jazycích. Běžné portugalské slovo zůstane v modelu, který viděl hlavně portugalský spam, neutrální.
3. **Důvěra sleduje pokrytí.** Výsledek se táhne k „nejisté“ úměrně tomu, kolik zpráv každého druhu klasifikátor v daném jazyce viděl: plná důvěra vyžaduje 1 000 od každého (nebo 2 % menší třídy u malých osobních modelů). Jazyk bez hamu v trénovacích datech dostane vždy „nejisté“.

Přibalený model nikdy neviděl [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), zprávy SMS strojově přeložené do 21 jazyků. Před zavedením těchto pravidel označil 5,7 % tamního hamu jako spam, včetně 55 % portugalského a 41 % francouzského. S nimi 0,18 %: žádný v čínštině, arabštině, korejštině, japonštině, hindštině, portugalštině, francouzštině ani 20 dalších jazycích a 0,27 % v angličtině.


## Zachycení spamu v těchto jazycích

Nejisté je bezpečné, ale spam to nezachytí. Zachytí ho tři věci:

* **Ostatní kontroly** nezávisí na jazyce: podobně vypadající domény, klamavé odkazy, spustitelné soubory, makra, ověření, blocklisty, pravidla.
* **Jazykový model.** Moderní otevřené modely čtou 100 až 200 jazyků a Spam Scanner se jednoho zeptá, kdykoli si klasifikátor není jistý. Testy end-to-end ověřují, že `qwen3.5:4b` zachytí spam a propustí ham v čínštině, arabštině, korejštině, hindštině a thajštině. [Jazykové modely](llm.md)
* **Trénování na vaší poště.** V modelu natrénovaném na vaší vlastní poště stačí několik set zpráv každého druhu v jednom jazyce, aby měl klasifikátor v tomto jazyce plnou důvěru. [Trénování](training.md) a [volitelná datová sada](training.md#more-languages), která přidává 21 jazyků.
