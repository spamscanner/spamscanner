<!-- source: 599bd320e55a -->

<!--
label: Om
title: Om Spam Scanner, licensen og privatliv
description: Hvem der laver Spam Scanner, hvordan du rapporterer en fejl eller en sårbarhed, dens licens, og hvad denne hjemmeside indsamler: ingen cookies og ingen analyse.
keywords: om Spam Scanner, Forward Email, licens Spam Scanner, BUSL-1.1, kontakt Spam Scanner, privatliv Spam Scanner
-->

# Om Spam Scanner

Spam Scanner er et spamfilter til mail fra [Forward Email](https://forwardemail.net), den privatlivsfokuserede maildienst, som byggede det til sine egne mailservere. Kildekoden, sagerne og udgivelserne ligger på [GitHub](https://github.com/spamscanner/spamscanner), og pakken ligger på [npm](https://www.npmjs.com/package/spamscanner).


## Hvem der laver det

Holdet bag Forward Email skriver og vedligeholder Spam Scanner. Forward Email gemmer ingen logs over beskedindhold og kunne derfor ikke sende mail til en ekstern filtreringstjeneste: filtret skulle køre på de egne servere og forklare hver beslutning, uden at et menneske læser mailen. [Hvordan Forward Email bruger det](../../docs/forward-email.md)

Forward Email er også open source, på [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Grundlæggeren var en af de første ansatte hos DuckDuckGo.


## Kontakt

* **Spørgsmål, fejl og ønsker til funktioner:** opret en sag på [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Sikkerhedshuller:** rapportér dem fortroligt via [GitHubs rapportering af sårbarheder](https://github.com/spamscanner/spamscanner/security/advisories/new), ikke i offentlige sager. Den samme adresse står i [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Andre licenser:** kontakt [Forward Email](https://forwardemail.net).


## Licensvilkår

Spam Scanners [licens](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) er Business Source License 1.1 med Apache License 2.0 som Change License. Den Change Date, licensen angiver, er passeret, og fra den dato giver licensen dig rettigheder under Apache License 2.0.


## Privatliv

Denne hjemmeside sætter ingen cookies og indlæser ingen analyse, sporing, reklamer, skrifttyper eller scripts fra andre websteder. Alle filer kommer fra spamscanner.net.

* Temaet, det sprog, du vælger, og den Mastodon-server, du deler til, gemmes i din browsers lokale lager og sendes ingen steder hen.
* Videoen indlæses først, når du afspiller den.
* Delingslinkene er almindelige links, så intet fra de netværk indlæses, før du følger et.
* Hjemmesiden hostes på GitHub Pages, og GitHub logger hver besøgendes IP-adresse af sikkerhedshensyn. Se [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) og [GitHubs privatlivserklæring](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Hvad softwaren sender

Spam Scanner sender ingen telemetri og søger ikke efter opdateringer. Som standard slår det værtsnavnene i en beskeds links op hos Cloudflares filtrerende DNS-resolvere, og intet andet forlader maskinen. De andre netværkstjek er slået fra, indtil du slår dem til. [Sikkerhed og privatliv](../../docs/security.md)


## Udgivelser

GitHub Actions bygger de selvstændige binære filer fra det offentlige repository. Hver udgivelse angiver deres hashes i en `SHA256SUMS`-fil, som installationsscriptet tjekker, og hver binær fil har en signeret attestering af byggets oprindelse. Udgivelser og deres noter ligger på [GitHub](https://github.com/spamscanner/spamscanner/releases).
