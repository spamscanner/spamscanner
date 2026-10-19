<!-- source: 599bd320e55a -->

<!--
label: Om
title: Om Spam Scanner, dess licens och integritet
description: Vem som gör Spam Scanner, hur du rapporterar en bugg eller sårbarhet, vilken licens den har och vad den här webbplatsen samlar in: inga kakor och ingen analys.
keywords: om Spam Scanner, Forward Email, licens Spam Scanner, BUSL-1.1, kontakt Spam Scanner, integritet Spam Scanner
-->

# Om Spam Scanner

Spam Scanner är ett spamfilter för e-post från [Forward Email](https://forwardemail.net), den integritetsfokuserade e-posttjänsten, som byggde det för sina egna e-postservrar. Källkoden, ärendena och releaserna finns på [GitHub](https://github.com/spamscanner/spamscanner), och paketet finns på [npm](https://www.npmjs.com/package/spamscanner).


## Vem som gör det

Teamet bakom Forward Email skriver och underhåller Spam Scanner. Forward Email sparar inga loggar över meddelandeinnehåll och kunde därför inte skicka e-post till en extern filtreringstjänst: filtret måste köras på de egna servrarna och förklara varje beslut utan att någon läser e-posten. [Hur Forward Email använder det](../../docs/forward-email.md)

Även Forward Email är öppen källkod, på [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Grundaren var en av de första anställda på DuckDuckGo.


## Kontakt

* **Frågor, buggar och önskemål om funktioner:** öppna ett ärende på [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Säkerhetsbrister:** rapportera dem privat via [GitHubs sårbarhetsrapportering](https://github.com/spamscanner/spamscanner/security/advisories/new), inte i offentliga ärenden. Samma adress finns i [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Andra licenser:** kontakta [Forward Email](https://forwardemail.net).


## Licensvillkor

Spam Scanners [licens](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) är Business Source License 1.1, med Apache License 2.0 som Change License. Det Change Date som licensen anger har passerat, och från det datumet ger licensen dig rättigheter enligt Apache License 2.0.


## Integritet

Den här webbplatsen sätter inga kakor och laddar ingen analys, inga spårare, annonser, typsnitt eller skript från andra webbplatser. Alla filer kommer från spamscanner.net.

* Temat, språket du väljer och Mastodon-servern du delar till sparas i webbläsarens lokala lagring och skickas ingenstans.
* Videon laddas först när du spelar den.
* Delningslänkarna är vanliga länkar, så inget från de nätverken laddas förrän du följer en.
* Webbplatsen ligger på GitHub Pages, och GitHub loggar varje besökares IP-adress av säkerhetsskäl. Se [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) och [GitHubs integritetspolicy](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Vad programvaran skickar

Spam Scanner skickar ingen telemetri och letar inte efter uppdateringar. Som standard slår det upp värdnamnen i ett meddelandes länkar hos Cloudflares filtrerande DNS-resolvrar, och inget annat lämnar maskinen. De andra nätverkskontrollerna är avstängda tills du slår på dem. [Säkerhet och integritet](../../docs/security.md)


## Releaser

GitHub Actions bygger de fristående binärfilerna från det offentliga repositoryt. Varje release listar deras hashar i en `SHA256SUMS`-fil, som installationsskriptet kontrollerar, och varje binärfil har en signerad attestering av byggets ursprung. Releaser och deras anteckningar finns på [GitHub](https://github.com/spamscanner/spamscanner/releases).
