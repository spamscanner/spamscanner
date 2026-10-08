<!-- source: 0ad167ddd34e -->

<!--
label: Flerspråkigt spamfilter
title: Flerspråkigt spamfilter för kinesiska, arabiska, ryska med flera
description: Så filtrerar Spam Scanner spam på alla språk: Unicode-ordsegmentering, återställda förklädnader och ingen flaggning av språk som modellen kan lite om.
keywords: flerspråkigt spamfilter, kinesiskt spamfilter, arabiskt spamfilter, ryskt spamfilter, japanskt spamfilter, Unicode spamdetektering, homoglyf spam
-->

# Flerspråkigt spamfilter

Många spamfilter byggdes för engelska. Spam på andra språk slinker förbi dem, och vanlig e-post på andra språk flaggas på grund av sitt skriftsystem. Spam Scanner är byggt för att undvika båda.


## Att läsa orden

Ord hittas med `Intl.Segmenter`, Unicode-reglerna för ordgränser med ordlistor för kinesiska, japanska, thailändska, laotiska, khmer och burmesiska. En kinesisk mening blir ord som 恭喜, 获得 och 大奖, inte en lång sträng som aldrig upprepas.

Förklädnader återställs innan orden räknas: osynliga tecken inuti ord, kyrilliska eller grekiska bokstäver i latinska ord (`pаypal`), siffror i stället för bokstäver (`v1agra`) och matematiska eller inringade bokstäver (𝐅𝐑𝐄𝐄). Varje förklädnad är också en ledtråd i sig.


## Att inte flagga det okända

Offentliga dataset med spam innehåller mycket mer spam än ham på andra språk än engelska, så en naiv klassificerare lär sig att arabisk eller koreansk text i sig är spam. Spam Scanner använder aldrig språket som ledtråd, väger varje ord mot spam- och hamräkningen för dess eget språk och förblir ”osäker” i proportion till hur lite ham den har sett på ett språk.

I ett test på sms på 21 språk som den medföljande modellen aldrig sett sänkte detta de falska positiva till noll på kinesiska, arabiska, koreanska, japanska, hindi, bengali, urdu, turkiska, ukrainska och svenska.


## Att fånga spam på alla språk

* **Kontroller som inte läser ord:** förväxlingsbara domäner, vilseledande länkar, körbara filer, makron, SPF, DKIM, DMARC och blocklistor.
* **En språkmodell** för osäkra meddelanden. Öppna modeller som Qwen 3.5 och Gemma 4 läser 140 till 200 språk; end-to-end-testerna kontrollerar spam och ham på kinesiska, arabiska, koreanska, hindi och thailändska med en riktig modell.
* **Din egen e-post.** Några hundra meddelanden av varje slag på ett språk ger en modell som tränats på din e-post full konfidens där.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

För att bara acceptera vissa språk lägger `--allow-language en,de` till poäng på e-post som med säkerhet identifierats som något annat språk.

[Språk i detalj](../../docs/languages.md)
