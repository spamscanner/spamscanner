<!-- source: c93fa1a3f9c7 -->

<!--
label: Vanlige spørsmål
title: Vanlige spørsmål
description: Svar om Spam Scanner: hvor nøyaktig det er, hvilke språk det støtter, hva det sender over nettet, språkmodeller, SpamAssassin og Forward Email.
keywords: Spam Scanner spørsmål, spørsmål om spamfilter, nøyaktighet spamfilter, personvern spamfilter, Spam Scanner FAQ
-->

# Vanlige spørsmål


## Hva er Spam Scanner?

Et spamfilter for Node.js, kommandolinjen og e-postservere. Det leser en rå e-postmelding og avgjør om den er spam, phishing eller svindel, eller om den inneholder skadevare, med en poengsum og listen over testene som avgjorde det. Det kjører som et bibliotek, en milter for Postfix og Sendmail, en SpamAssassin-kompatibel spamd-server, et innholdsfilter for Postfix, et HTTP API eller en TCP-server.


## Er det gratis?

[Lisensen](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), Business Source License 1.1, tillater all bruk unntatt å tilby spamdeteksjon som en tjeneste til andre, og angir datoen da den går over til Apache License 2.0.


## Hvor nøyaktig er det?

På tilbakeholdte engelske meldinger fra treningsdataene merket den medfølgende klassifisereren alene ingen ham som spam og fanget 97 % av spammen; de fullstendige tallene per språk finnes i [veiledningen for trening](../../docs/training.md#the-bundled-model). Lenker, vedlegg, autentisering, blokkeringslister og en språkmodell kommer i tillegg. Din egen e-post er den virkelige testen: `spamscanner eval` måler enhver modell på enhver merket e-post.


## Hvilke språk støtter det?

Alle. Det segmenterer ord med Unicode-reglene, også kinesisk, japansk og thai, som ikke har mellomrom. Der den medfølgende modellen har sett lite e-post på et språk, forblir den usikker i stedet for å flagge meldingen, og en språkmodell eller din egen trening avgjør. [Språk](../../docs/languages.md)


## Sender det e-posten min noe sted?

Nei. Som standard slår det opp vertsnavnene i lenker på Cloudflares filtrerende DNS-resolvere, og ingenting annet forlater maskinen. Autentisering, blokkeringslister, språkmodeller og omdømmetjenester er av inntil de konfigureres, og personopplysninger fjernes før e-post sendes til en driftet språkmodell. [Sikkerhet og personvern](../../docs/security.md)


## Trenger jeg en språkmodell?

Nei. Den er en ekstra vurdering for vanskelige tilfeller. Uten en avgjøres disse meldingene bare av poengsummen.


## Hvilken språkmodell bør jeg bruke?

`qwen3.5:4b` via Ollama på en prosessor, eller `qwen3.5:9b` med en GPU. Begge har Apache-lisens og leser 201 språk. Driftede modeller fra Anthropic, OpenAI, Google og andre virker også. [Anbefalte modeller](../../docs/llm.md#recommended-open-models)


## Kan det erstatte SpamAssassin?

For de fleste oppsett, ja: det snakker spamd-protokollen, så spamc, Exim og Haraka virker uendret, og det skriver de samme `X-Spam-*`-hodene. Det kjører ikke SpamAssassins regelfiler. [Alternativ til SpamAssassin](/spamassassin-alternative/)


## Vil det avvise legitim e-post?

Avvisning av e-post er av som standard: milteren bare merker. Med `--reject` avvises bare meldinger med 15 poeng eller mer, med en midlertidig 451-feil, så avsendere prøver igjen og en feil kan rettes ved å endre en innstilling. Innholdsfilteret avviser aldri under SMTP-økten.


## Hvordan trener jeg det på e-posten min?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, og deretter `--model model.json`. Mbox-filer, Maildir-mapper, mapper med `.eml`-filer og datasett i CSV eller JSON Lines virker alle. [Trening](../../docs/training.md)


## Virker det uten Node.js?

Ja: frittstående binærfiler for Linux, macOS og Windows inneholder Node.js og modellen. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Hvem lager det?

[Forward Email](https://forwardemail.net), for selskapets egne e-postservere.
