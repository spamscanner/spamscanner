<!-- source: 599bd320e55a -->

<!--
label: Om
title: Om Spam Scanner, lisensen og personvern
description: Hvem som lager Spam Scanner, hvordan du melder en feil eller et sikkerhetshull, lisensen, og hva dette nettstedet samler inn: ingen informasjonskapsler og ingen analyse.
keywords: om Spam Scanner, Forward Email, lisens Spam Scanner, BUSL-1.1, kontakt Spam Scanner, personvern Spam Scanner
-->

# Om Spam Scanner

Spam Scanner er et spamfilter for e-post fra [Forward Email](https://forwardemail.net), den personvernfokuserte e-posttjenesten, som bygde det for sine egne e-postservere. Kildekoden, sakene og utgivelsene ligger på [GitHub](https://github.com/spamscanner/spamscanner), og pakken ligger på [npm](https://www.npmjs.com/package/spamscanner).


## Hvem som lager det

Teamet bak Forward Email skriver og vedlikeholder Spam Scanner. Forward Email lagrer ingen logger over meldingsinnhold og kunne derfor ikke sende e-post til en ekstern filtreringstjeneste: filteret måtte kjøre på egne servere og forklare hver avgjørelse uten at et menneske leser e-posten. [Hvordan Forward Email bruker det](../../docs/forward-email.md)

Forward Email er også åpen kildekode, på [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Grunnleggeren var en av de første ansatte i DuckDuckGo.


## Kontakt

* **Spørsmål, feil og ønsker om funksjoner:** opprett en sak på [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Sikkerhetshull:** meld dem fortrolig via [GitHubs rapportering av sårbarheter](https://github.com/spamscanner/spamscanner/security/advisories/new), ikke i offentlige saker. Den samme adressen står i [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Andre lisenser:** kontakt [Forward Email](https://forwardemail.net).


## Lisensvilkår

Spam Scanners [lisens](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) er Business Source License 1.1, med Apache License 2.0 som Change License. Change Date-en som lisensen oppgir, er passert, og fra den datoen gir lisensen deg rettigheter etter Apache License 2.0.


## Personvern

Dette nettstedet setter ingen informasjonskapsler og laster ingen analyse, sporere, annonser, skrifttyper eller skript fra andre nettsteder. Alle filer kommer fra spamscanner.net.

* Temaet, språket du velger og Mastodon-serveren du deler til, lagres i nettleserens lokale lagring og sendes ingen steder.
* Videoen lastes først når du spiller den av.
* Delingslenkene er vanlige lenker, så ingenting fra disse nettverkene lastes før du følger en.
* Nettstedet driftes på GitHub Pages, og GitHub logger IP-adressen til hver besøkende av sikkerhetshensyn. Se [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) og [GitHubs personvernerklæring](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Hva programvaren sender

Spam Scanner sender ingen telemetri og ser ikke etter oppdateringer. Som standard slår det opp vertsnavnene i en meldings lenker hos Cloudflares filtrerende DNS-resolvere, og ingenting annet forlater maskinen. De andre nettverkskontrollene er av til du slår dem på. [Sikkerhet og personvern](../../docs/security.md)


## Utgivelser

GitHub Actions bygger de frittstående binærfilene fra det offentlige repositoriet. Hver utgivelse lister hashene deres i en `SHA256SUMS`-fil, som installasjonsskriptet kontrollerer, og hver binærfil har en signert attestasjon av byggets opprinnelse. Utgivelser og notatene deres ligger på [GitHub](https://github.com/spamscanner/spamscanner/releases).
