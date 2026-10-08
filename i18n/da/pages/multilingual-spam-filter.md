<!-- source: 0ad167ddd34e -->

<!--
label: Flersproget spamfilter
title: Flersproget spamfilter til kinesisk, arabisk, russisk og mere
description: Sådan filtrerer Spam Scanner spam på alle sprog: Unicode-orddeling, forklædninger omgøres, og et sprog, modellen kender lidt til, markeres aldrig.
keywords: flersproget spamfilter, kinesisk spamfilter, arabisk spamfilter, russisk spamfilter, japansk spamfilter, Unicode spamdetektion, homoglyf spam
-->

# Flersproget spamfilter

Mange spamfiltre er bygget til engelsk. Spam på andre sprog smutter forbi dem, og almindelig post på andre sprog markeres på grund af skriftsystemet. Spam Scanner er bygget til at undgå begge dele.


## Ordene læses

Ord findes med `Intl.Segmenter`, Unicode-reglerne for ordgrænser med ordbøger til kinesisk, japansk, thai, lao, khmer og burmesisk. En kinesisk sætning bliver til ord som 恭喜, 获得 og 大奖 og ikke én lang streng, der aldrig gentages.

Forklædninger omgøres før optællingen: usynlige tegn inde i ord, kyrilliske eller græske bogstaver i latinske ord (`pаypal`), tal i stedet for bogstaver (`v1agra`) og matematiske eller indrammede bogstaver (𝐅𝐑𝐄𝐄). Hver forklædning er også et spor i sig selv.


## Det, den ikke kender, markeres ikke

Offentlige spamdatasæt indeholder langt mere spam på fremmede sprog end ham på fremmede sprog, så en naiv klassifikator lærer, at arabisk eller koreansk tekst i sig selv er spam. Spam Scanner bruger aldrig sproget som spor, vejer hvert ord mod spam- og ham-tallene for ordets eget sprog og forbliver »usikker« i forhold til, hvor lidt ham den har set på et sprog.

I en test på SMS-beskeder på 21 sprog, som den medfølgende model aldrig havde set, bragte det de falske positiver på kinesisk, arabisk, koreansk, japansk, hindi, bengali, urdu, tyrkisk, ukrainsk og svensk ned på nul.


## Spam fanges på alle sprog

* **Tjek, der ikke læser ord:** forvekslelige domæner, vildledende links, programfiler, makroer, SPF, DKIM, DMARC og blokeringslister.
* **En sprogmodel** til usikre beskeder. Åbne modeller som Qwen 3.5 og Gemma 4 læser 140 til 200 sprog; end-to-end-testene tjekker spam og ham på kinesisk, arabisk, koreansk, hindi og thai med en rigtig model.
* **Din egen post.** Et par hundrede beskeder af hver slags på et sprog giver en model, der er trænet på din post, fuld sikkerhed på det sprog.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

For kun at acceptere nogle sprog lægger `--allow-language en,de` point til post, der med sikkerhed er genkendt som et hvilket som helst andet sprog.

[Sprog i detaljer](../../docs/languages.md)
