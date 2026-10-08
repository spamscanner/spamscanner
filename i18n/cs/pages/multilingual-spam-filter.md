<!-- source: 0ad167ddd34e -->

<!--
label: Vícejazyčný spamový filtr
title: Vícejazyčný spamový filtr pro čínštinu, arabštinu, ruštinu a další
description: Jak Spam Scanner filtruje spam v každém jazyce: dělení na slova podle Unicode, odstranění maskování a nikdy neoznačí jazyk, který model málo zná.
keywords: vícejazyčný spamový filtr, spamový filtr čeština, čínský spam, arabský spam, ruský spam, japonský spam, detekce spamu Unicode, homoglyfy spam
-->

# Vícejazyčný spamový filtr

Mnoho spamových filtrů vzniklo pro angličtinu. Spam v jiných jazycích jimi proklouzne a běžná pošta v jiných jazycích se označí kvůli svému písmu. Spam Scanner je postavený tak, aby se vyhnul obojímu.


## Čtení slov

Slova se hledají pomocí `Intl.Segmenter`, tedy pravidel Unicode pro hranice slov se slovníky pro čínštinu, japonštinu, thajštinu, laoštinu, khmerštinu a barmštinu. Z čínské věty se stanou slova jako 恭喜, 获得 a 大奖, ne jeden dlouhý řetězec, který se nikdy neopakuje.

Maskování se před počítáním odstraní: neviditelné znaky uvnitř slov, cyrilická nebo řecká písmena uvnitř latinkových slov (`pаypal`), číslice místo písmen (`v1agra`) a matematická nebo zakroužkovaná písmena (𝐅𝐑𝐄𝐄). Každý druh maskování je zároveň samostatnou indicií.


## Neoznačovat to, co nezná

Veřejné datové sady spamu obsahují mnohem víc cizojazyčného spamu než cizojazyčného hamu, takže naivní klasifikátor se naučí, že arabský nebo korejský text sám o sobě je spam. Spam Scanner jazyk nikdy nepoužívá jako indicii, každé slovo váží vůči počtům spamu a hamu v jeho vlastním jazyce a zůstává „nejistý“ úměrně tomu, jak málo hamu v daném jazyce viděl.

V testu na zprávách SMS ve 21 jazycích, které přibalený model nikdy neviděl, to snížilo jeho falešně pozitivní výsledky v čínštině, arabštině, korejštině, japonštině, hindštině, bengálštině, urdštině, turečtině, ukrajinštině a švédštině na nulu.


## Zachycení spamu v každém jazyce

* **Kontroly, které nečtou slova:** podobně vypadající domény, klamavé odkazy, spustitelné soubory, makra, SPF, DKIM, DMARC a blocklisty.
* **Jazykový model** pro nejisté zprávy. Otevřené modely jako Qwen 3.5 a Gemma 4 čtou 140 až 200 jazyků; testy end-to-end se skutečným modelem ověřují spam a ham v čínštině, arabštině, korejštině, hindštině a thajštině.
* **Vaše vlastní pošta.** Několik set zpráv každého druhu v jednom jazyce dá modelu natrénovanému na vaší poště v tomto jazyce plnou důvěru.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Chcete-li přijímat jen některé jazyky, `--allow-language en,de` přidá body poště, která je s jistotou rozpoznaná v jakémkoli jiném.

[Jazyky podrobně](../../docs/languages.md)
