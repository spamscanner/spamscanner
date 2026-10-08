<!-- source: c93fa1a3f9c7 -->

<!--
label: Vanliga frågor
title: Vanliga frågor
description: Svar om Spam Scanner: hur träffsäkert det är, vilka språk det stöder, vad det skickar över nätverket, språkmodeller, SpamAssassin och Forward Email.
keywords: Spam Scanner vanliga frågor, frågor om spamfilter, spamfilter träffsäkerhet, spamfilter integritet
-->

# Vanliga frågor


## Vad är Spam Scanner?

Ett spamfilter för Node.js, kommandoraden och e-postservrar. Det läser ett rått e-postmeddelande och avgör om det är spam, nätfiske, ett bedrägeri eller innehåller skadlig kod, med en poäng och en lista över de tester som avgjorde det. Det körs som ett bibliotek, en milter för Postfix och Sendmail, en SpamAssassin-kompatibel spamd-server, ett innehållsfilter för Postfix, ett HTTP-API eller en TCP-server.


## Är det gratis?

Dess [licens](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), Business Source License 1.1, tillåter all användning utom att erbjuda spamdetektering som en tjänst åt andra, och anger det datum då den övergår till Apache License 2.0.


## Hur träffsäkert är det?

På undanhållna engelska meddelanden ur träningsdatan markerade den medföljande klassificeraren ensam ingen ham som spam och fångade 97 % av spammen; de fullständiga siffrorna per språk finns i [träningsguiden](../../docs/training.md#the-bundled-model). Länkar, bilagor, autentisering, blocklistor och en språkmodell bidrar ytterligare. Din egen e-post är det verkliga testet: `spamscanner eval` mäter vilken modell som helst på vilken märkt e-post som helst.


## Vilka språk stöds?

Alla. Det segmenterar ord med Unicode-reglerna, även kinesiska, japanska och thailändska, som saknar mellanslag. Där den medföljande modellen har sett lite e-post på ett språk förblir den osäker i stället för att flagga meddelandet, och en språkmodell eller din egen träning avgör. [Språk](../../docs/languages.md)


## Skickar det min e-post någonstans?

Nej. Som standard slår det upp värdnamnen i länkar hos Cloudflares filtrerande DNS-resolvrar, och ingenting annat lämnar datorn. Autentisering, blocklistor, språkmodeller och ryktestjänster är avstängda tills de konfigureras, och personuppgifter tas bort innan e-post skickas till en molnbaserad språkmodell. [Säkerhet och integritet](../../docs/security.md)


## Behöver jag en språkmodell?

Nej. Den är en andra åsikt för gränsfall. Utan en avgörs de meddelandena enbart av sin poäng.


## Vilken språkmodell ska jag använda?

`qwen3.5:4b` via Ollama på en processor, eller `qwen3.5:9b` med en GPU. Båda är Apache-licensierade och läser 201 språk. Molnbaserade modeller från Anthropic, OpenAI, Google och andra fungerar också. [Rekommenderade modeller](../../docs/llm.md#recommended-open-models)


## Kan det ersätta SpamAssassin?

För de flesta installationer, ja: det talar spamds protokoll, så spamc, Exim och Haraka fungerar oförändrade, och det skriver samma `X-Spam-*`-huvuden. Det kör inte SpamAssassins regelfiler. [Alternativ till SpamAssassin](/spamassassin-alternative/)


## Kommer det att avvisa legitim e-post?

Att neka e-post är avstängt som standard: miltern märker bara. Med `--reject` nekas bara meddelanden med 15 poäng eller mer, med ett tillfälligt 451-fel, så avsändarna försöker igen och ett misstag kan rättas genom att ändra en inställning. Innehållsfiltret nekar aldrig under SMTP-sessionen.


## Hur tränar jag det på min e-post?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, och sedan `--model model.json`. Mbox-filer, Maildir-kataloger, mappar med `.eml`-filer och dataset i CSV eller JSON Lines fungerar alla. [Träning](../../docs/training.md)


## Fungerar det utan Node.js?

Ja: fristående binärfiler för Linux, macOS och Windows innehåller Node.js och modellen. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Vem gör det?

[Forward Email](https://forwardemail.net), för sina egna e-postservrar.
