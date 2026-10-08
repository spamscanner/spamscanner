<!-- source: 361732724f0e -->

<!--
label: Ofte stillede spørgsmål
title: Ofte stillede spørgsmål
description: Svar om Spam Scanner: hvor præcis den er, hvilke sprog den understøtter, hvad den sender over netværket, sprogmodeller, SpamAssassin og Forward Email.
keywords: Spam Scanner FAQ, spørgsmål om spamfilter, spamfilter præcision, spamfilter privatliv, spamfilter dansk
-->

# Ofte stillede spørgsmål


## Hvad er Spam Scanner?

Et spamfilter til Node.js, kommandolinjen og mailservere. Det læser en rå e-mailbesked og afgør, om den er spam, phishing eller svindel eller indeholder malware, med en score og en liste over de test, der afgjorde det. Det kører som et bibliotek, en milter til Postfix og Sendmail, en SpamAssassin-kompatibel spamd-server, et Postfix-indholdsfilter, et HTTP API eller en TCP-server.


## Er det gratis?

Dets [licens](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), Business Source License 1.1, tillader al brug undtagen at tilbyde spamdetektion som en tjeneste til andre og angiver den dato, hvor den skifter til Apache License 2.0.


## Hvor præcist er det?

På engelske beskeder, der var holdt ude af træningsdataene, markerede den medfølgende klassifikator alene ingen ham som spam og fangede 97 % af spammen; de fulde tal for hvert sprog står i [træningsvejledningen](../../docs/training.md#the-bundled-model). Links, vedhæftede filer, godkendelse, blokeringslister og en sprogmodel lægger sig oven i det. Din egen post er den rigtige test: `spamscanner eval` måler enhver model på enhver mærket post.


## Hvilke sprog understøtter det?

Dem alle. Det opdeler ord efter Unicode-reglerne, også kinesisk, japansk og thai, som ikke har mellemrum. Hvor den medfølgende model har set lidt post på et sprog, forbliver den usikker i stedet for at markere beskeden, og en sprogmodel eller din egen træning afgør sagen. [Sprog](../../docs/languages.md)


## Sender det min post nogen steder hen?

Nej. Som standard slår det værtsnavnene i links op på Cloudflares filtrerende DNS-resolvere, og intet andet forlader maskinen. Godkendelse, blokeringslister, sprogmodeller og omdømmetjenester er slået fra, indtil de konfigureres, og personoplysninger fjernes, før post sendes til en hostet sprogmodel. [Sikkerhed og privatliv](../../docs/security.md)


## Har jeg brug for en sprogmodel?

Nej. Den er en second opinion til tvivlstilfælde. Uden en afgøres de beskeder alene af deres score.


## Hvilken sprogmodel skal jeg bruge?

`qwen3.5:4b` via Ollama på en CPU eller `qwen3.5:9b` med en GPU. Begge er Apache-licenserede og læser 201 sprog. Spam Scanner aflæser sandsynligheden for hver dom fra ét trin i modellen, hvilket på en CPU med to kerner tog omkring 11 sekunder pr. besked i stedet for 31 for et skrevet svar, med samme præcision. Til en hostet tjeneste svarer beslutningsmodellerne Cloudflare Clef og TypeSafe Jev på under et sekund; Anthropic, OpenAI, Google og andre virker også. [Målinger](../../docs/llm.md#measured) og [anbefalede modeller](../../docs/llm.md#recommended-open-models)


## Kan det erstatte SpamAssassin?

I de fleste opsætninger, ja: det taler spamds protokol, så spamc, Exim og Haraka virker uændret, og det skriver de samme `X-Spam-*`-headere. Det kører ikke SpamAssassins regelfiler. [Alternativ til SpamAssassin](/spamassassin-alternative/)


## Vil det afvise legitim post?

Afvisning af post er slået fra som standard: milteren markerer kun. Med `--reject` afvises kun beskeder med en score på 15 eller mere, med en midlertidig 451-fejl, så afsendere prøver igen, og en fejl kan rettes ved at ændre en indstilling. Indholdsfilteret afviser aldrig under SMTP-sessionen.


## Hvordan træner jeg det på min post?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json` og derefter `--model model.json`. Mbox-filer, Maildirs, mapper med `.eml`-filer og datasæt i CSV eller JSON Lines virker alle. [Træning](../../docs/training.md)


## Virker det uden Node.js?

Ja: selvstændige binærfiler til Linux, macOS og Windows indeholder Node.js og modellen. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Hvem laver det?

[Forward Email](https://forwardemail.net), til sine egne mailservere.
