<!-- source: 361732724f0e -->

<!--
label: Veelgestelde vragen
title: Veelgestelde vragen
description: Antwoorden over Spam Scanner: nauwkeurigheid, ondersteunde talen, wat het over het netwerk verstuurt, taalmodellen, SpamAssassin en Forward Email.
keywords: Spam Scanner veelgestelde vragen, Spam Scanner FAQ, vragen over spamfilter, nauwkeurigheid spamfilter, privacy spamfilter
-->

# Veelgestelde vragen


## Wat is Spam Scanner?

Een spamfilter voor Node.js, de opdrachtregel en mailservers. Het leest een ruw e-mailbericht en beslist of het spam, phishing of oplichting is of malware bevat, met een score en de lijst met tests die de doorslag gaven. Het draait als bibliotheek, als milter voor Postfix en Sendmail, als spamd-server die compatibel is met SpamAssassin, als contentfilter voor Postfix, als HTTP API of als TCP-server.


## Is het gratis?

De [licentie](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), de Business Source License 1.1, staat elk gebruik toe behalve spamdetectie als dienst aan anderen aanbieden, en noemt de datum waarop hij overgaat in de Apache License 2.0.


## Hoe nauwkeurig is het?

Op achtergehouden Engelse berichten uit de trainingsdata markeerde de meegeleverde classifier op zichzelf geen enkele ham als spam en ving hij 97% van de spam; de volledige cijfers per taal staan in de [handleiding over training](../../docs/training.md#the-bundled-model). Links, bijlagen, authenticatie, blocklists en een taalmodel komen daar nog bij. Je eigen mail is de echte test: `spamscanner eval` meet elk model op elke gelabelde mail.


## Welke talen ondersteunt het?

Allemaal. Het segmenteert woorden met de Unicode-regels, ook in het Chinees, Japans en Thai, die geen spaties hebben. Waar het meegeleverde model weinig mail in een taal heeft gezien, blijft het onzeker in plaats van die mail te markeren, en dan beslissen een taalmodel of je eigen training. [Talen](../../docs/languages.md)


## Stuurt het mijn mail ergens heen?

Nee. Standaard zoekt het de hostnamen van links op bij de filterende DNS-resolvers van Cloudflare, en verder verlaat niets de machine. Authenticatie, blocklists, taalmodellen en reputatiediensten staan uit tot je ze instelt, en persoonsgegevens worden verwijderd voordat mail naar een gehost taalmodel gaat. [Beveiliging en privacy](../../docs/security.md)


## Heb ik een taalmodel nodig?

Nee. Het is een tweede mening voor twijfelgevallen. Zonder model worden die berichten alleen op hun score beslist.


## Welk taalmodel moet ik gebruiken?

`qwen3.5:4b` via Ollama op een CPU, of `qwen3.5:9b` met een GPU. Beide hebben een Apache-licentie en lezen 201 talen. Spam Scanner leest de kans op elk oordeel af uit één stap van het model; op een CPU met twee cores kostte dat ongeveer 11 seconden per bericht in plaats van 31 voor een geschreven antwoord, met dezelfde nauwkeurigheid. Voor een gehoste dienst antwoorden de beslismodellen Cloudflare Clef en TypeSafe Jev in minder dan een seconde; Anthropic, OpenAI, Google en andere werken ook. [Metingen](../../docs/llm.md#measured) en [aanbevolen modellen](../../docs/llm.md#recommended-open-models)


## Kan het SpamAssassin vervangen?

Voor de meeste configuraties wel: het spreekt het protocol van spamd, zodat spamc, Exim en Haraka ongewijzigd werken, en het schrijft dezelfde `X-Spam-*`-headers. Het voert de regelbestanden van SpamAssassin niet uit. [Alternatief voor SpamAssassin](/spamassassin-alternative/)


## Weigert het legitieme mail?

Mail weigeren staat standaard uit: de milter markeert alleen. Met `--reject` worden alleen berichten met een score van 15 of meer geweigerd, met een tijdelijke 451-fout, zodat afzenders het opnieuw proberen en een fout te herstellen is door een instelling aan te passen. Het contentfilter weigert nooit tijdens de SMTP-sessie.


## Hoe train ik het op mijn mail?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, en daarna `--model model.json`. Mbox-bestanden, Maildirs, mappen met `.eml`-bestanden en datasets in CSV of JSON Lines werken allemaal. [Training](../../docs/training.md)


## Werkt het zonder Node.js?

Ja: standalone binaries voor Linux, macOS en Windows bevatten Node.js en het model. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Wie maakt het?

[Forward Email](https://forwardemail.net), voor de eigen mailservers.
