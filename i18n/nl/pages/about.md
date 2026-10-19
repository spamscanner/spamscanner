<!-- source: 599bd320e55a -->

<!--
label: Over
title: Over Spam Scanner, de licentie en privacy
description: Wie Spam Scanner maakt, hoe je een bug of kwetsbaarheid meldt, de licentie en wat deze website verzamelt: geen cookies en geen analytics.
keywords: over Spam Scanner, Forward Email, licentie Spam Scanner, BUSL-1.1, contact Spam Scanner, privacy Spam Scanner
-->

# Over Spam Scanner

Spam Scanner is een spamfilter voor e-mail van [Forward Email](https://forwardemail.net), de privacygerichte e-maildienst, die het voor de eigen mailservers heeft gebouwd. De broncode, issues en releases staan op [GitHub](https://github.com/spamscanner/spamscanner), en het pakket staat op [npm](https://www.npmjs.com/package/spamscanner).


## Wie het maakt

Het team van Forward Email schrijft en onderhoudt Spam Scanner. Forward Email bewaart geen logs van berichtinhoud en kon mail dus niet naar een externe filterdienst sturen: het filter moest op de eigen servers draaien en elke beslissing uitleggen zonder dat iemand de mail leest. [Hoe Forward Email het gebruikt](../../docs/forward-email.md)

Ook Forward Email is open source, op [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). De oprichter was een van de eerste werknemers van DuckDuckGo.


## Contact

* **Vragen, bugs en functieverzoeken:** open een issue op [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Beveiligingslekken:** meld ze vertrouwelijk via [de kwetsbaarheidsmelding van GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), niet in openbare issues. Hetzelfde adres staat in [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Andere licenties:** neem contact op met [Forward Email](https://forwardemail.net).


## Licentievoorwaarden

De [licentie](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) van Spam Scanner is de Business Source License 1.1, met de Apache License 2.0 als Change License. De Change Date in de licentie is verstreken, en vanaf die datum geeft de licentie je rechten onder de Apache License 2.0.


## Privacy

Deze website plaatst geen cookies en laadt geen analytics, trackers, advertenties, lettertypen of scripts van andere sites. Elk bestand komt van spamscanner.net.

* Het thema, de taal die je kiest en de Mastodon-server waarnaar je deelt worden in de lokale opslag van je browser bewaard en nergens heen gestuurd.
* De video laadt pas als je hem afspeelt.
* De deellinks zijn gewone links, dus er laadt niets van die netwerken tot je er een volgt.
* De site wordt gehost op GitHub Pages, en GitHub logt om veiligheidsredenen het IP-adres van elke bezoeker. Zie [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) en de [privacyverklaring van GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Wat de software verstuurt

Spam Scanner verstuurt geen telemetrie en zoekt niet naar updates. Standaard zoekt het de hostnamen van links in een bericht op bij de filterende DNS-resolvers van Cloudflare, en verder verlaat niets de machine. De andere netwerkcontroles staan uit tot je ze aanzet. [Beveiliging en privacy](../../docs/security.md)


## Releases

GitHub Actions bouwt de losse binaries uit de openbare repository. Elke release vermeldt hun hashes in een bestand `SHA256SUMS`, dat het installatiescript controleert, en elke binary heeft een ondertekende build-provenance-attestatie. Releases en hun notities staan op [GitHub](https://github.com/spamscanner/spamscanner/releases).
