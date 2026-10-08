<!-- source: 60f00f92b5aa -->

# Sikkerhed og privatliv

Spam Scanner læser post, som er privat, fra afsendere, som kan være fjendtlige. Denne side viser, hvad den sender nogen steder hen, og hvordan den behandler det, den læser.


## Hvad der forlader maskinen

Som standard én ting: **værtsnavnene i links** i en besked slås op på Cloudflares filtrerende resolvere, 1.1.1.2 og 1.0.0.2 (malware og phishing) samt 1.1.1.3 og 1.0.0.3 (også voksenindhold). Det er almindelige DNS-forespørgsler efter navne som `example.com`; ingen del af beskeden eller dens adresser sendes. Slå dem fra med `phishing: {cloudflare: false}` eller `--no-cloudflare`, eller slå kun tjekket for voksenindhold fra med `phishing: {adult: false}`.

Alt andet er slået fra, indtil det konfigureres:

| Tjek                | Sender                                                                     | Til                                                                    |
| ------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `authentication`    | DNS-forespørgsler efter afsenderens SPF-, DKIM-, DMARC- og ARC-poster      | Din resolver eller `dnsServers`                                        |
| `dnsbl`             | Klientens IP-adresse, vendt om, og domæner i links, som DNS-forespørgsler  | Blokeringslisternes navneservere via din resolver eller `dns.servers`  |
| `llm`               | Et resumé af beskeden, med personoplysninger fjernet for eksterne udbydere | Den server til sprogmodellen, du angiver ([privatliv](llm.md#privacy)) |
| `reputation.apiUrl` | Afsenderens IP-adresse, domæne og adresse                                  | Den tjeneste, du angiver                                               |
| `clamav`            | Vedhæftede filer                                                           | Din clamd via dens socket                                              |

Der er ingen telemetri, intet opdateringstjek og ingen download under kørsel. Modellen leveres i pakken.


## Hvad den gemmer

Intet, medmindre den bliver bedt om det. Scanninger logges eller gemmes ikke. `learn()` ændrer klassifikatoren i hukommelsen; den skrives kun til disk af `saveModel()`, `spamscanner learn` eller servernes indstilling `--out`. En modelfil indeholder hashede optællinger af features, ikke ord eller beskedtekst.

Svar fra sprogmodeller caches i hukommelsen med en hash af det, der blev sendt, som nøgle, så gentagne kopier af den samme besked kun spørges om én gang. DNS-svar caches i hukommelsen i ti minutter.


## Fjendtligt input

* Vedhæftede filer identificeres ud fra deres bytes og bliver aldrig kørt eller åbnet af et andet program. ZIP-arkiver læses fra deres centrale katalog med en grænse for antallet af poster; indlejrede arkiver pakkes ikke ud.
* Brødtekst læses op til `maxLength` (100.000 tegn), og serverne accepterer beskeder op til 25 MB.
* Hvert netværkstjek har en tidsgrænse (`timeout`, 10 sekunder som standard). Et tjek, der fejler eller overskrider tidsgrænsen, springes over, og scanningen gøres færdig uden det.
* `X-Spam-*`-headere, der allerede står i en besked, fjernes af milteren, indholdsfilteret og `--headers`, så afsendere ikke kan markere deres egen post som ren.
* Microsofts headere med spamdomme stoles kun på, når beskeden kom direkte fra Microsofts servere, og Received-headere bruges aldrig til at afgøre, hvor en besked kom fra.
* Tekst, der henvender sig til AI-filtre, scores som spam, og sprogmodellen får at vide, at beskeden er data og ikke instruktioner. [Prompt injection](llm.md#prompt-injection)


## Servere

Milter-, HTTP-, TCP- og spamd-serverne lytter på 127.0.0.1, medmindre `--host` siger noget andet. HTTP API'et sammenligner sit token i konstant tid og afviser `/learn` uden et. Ingen af dem taler TLS: for at nå dem over et netværk skal du bruge et privat netværk, en SSH-tunnel eller en reverse proxy med TLS.

Kør dem som en bruger uden privilegier. [systemd-unitten i vejledningen til Postfix](postfix.md#1-run-the-milter) tilføjer den sædvanlige hærdning.


## Rapportering af en sårbarhed

Rapportér sikkerhedsproblemer privat via [GitHubs rapportering af sårbarheder](https://github.com/spamscanner/spamscanner/security/advisories/new), ikke i offentlige issues.
