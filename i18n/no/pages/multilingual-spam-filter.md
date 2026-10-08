<!-- source: 0ad167ddd34e -->

<!--
label: Flerspråklig spamfilter
title: Flerspråklig spamfilter for kinesisk, arabisk, russisk og mer
description: Slik filtrerer Spam Scanner spam på alle språk: Unicode-ordsegmentering, forkledninger gjort om, og aldri flagging av språk modellen kjenner lite.
keywords: flerspråklig spamfilter, spamfilter kinesisk, spamfilter arabisk, spamfilter russisk, spamfilter japansk, Unicode spamdeteksjon, homoglyf spam
-->

# Flerspråklig spamfilter

Mange spamfiltre ble laget for engelsk. Spam på andre språk slipper forbi dem, og vanlig e-post på andre språk blir flagget på grunn av skriftsystemet. Spam Scanner er laget for å unngå begge deler.


## Å lese ordene

Ord finnes med `Intl.Segmenter`, Unicode-reglene for ordgrenser med ordbøker for kinesisk, japansk, thai, lao, khmer og burmesisk. En kinesisk setning blir til ord som 恭喜, 获得 og 大奖, ikke én lang streng som aldri gjentas.

Forkledninger gjøres om før opptellingen: usynlige tegn inne i ord, kyrilliske eller greske bokstaver inne i latinske ord (`pаypal`), sifre i stedet for bokstaver (`v1agra`) og matematiske eller innrammede bokstaver (𝐅𝐑𝐄𝐄). Hver forkledning er også et eget indisium.


## Ikke flagge det den ikke kjenner

Offentlige spamdatasett inneholder langt mer spam enn ham på andre språk enn engelsk, så en naiv klassifiserer lærer at arabisk eller koreansk tekst i seg selv er spam. Spam Scanner bruker aldri språket som indisium, vekter hvert ord mot spam- og ham-tellingene for dets eget språk, og forblir «usikker» i forhold til hvor lite ham den har sett på et språk.

I en test på SMS-meldinger på 21 språk som den medfølgende modellen aldri hadde sett, brakte dette de falske positivene på kinesisk, arabisk, koreansk, japansk, hindi, bengali, urdu, tyrkisk, ukrainsk og svensk ned til null.


## Å fange spam på alle språk

* **Sjekker som ikke leser ord:** forvekslingsdomener, villedende lenker, kjørbare filer, makroer, SPF, DKIM, DMARC og blokkeringslister.
* **En språkmodell** for usikre meldinger. Åpne modeller som Qwen 3.5 og Gemma 4 leser 140 til 200 språk; ende-til-ende-testene sjekker spam og ham på kinesisk, arabisk, koreansk, hindi og thai med en ekte modell.
* **Din egen e-post.** Noen hundre meldinger av hver type på et språk gir en modell trent på e-posten din full tillit der.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

For å godta bare enkelte språk gir `--allow-language en,de` poeng til e-post som med sikkerhet er gjenkjent som et hvilket som helst annet språk.

[Språk i detalj](../../docs/languages.md)
