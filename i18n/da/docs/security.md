<!-- source: 1d7373f991c2 -->

# Sikkerhed og privatliv

Spam Scanner læser post, som er privat, fra afsendere, som kan være fjendtlige. Denne side viser, hvad den sender nogen steder hen, og hvordan den behandler det, den læser.


## Hvad der forlader maskinen

Som standard én ting: **værtsnavnene i links** i en besked slås op på Cloudflares filtrerende resolvere, 1.1.1.2 og 1.0.0.2 (malware og phishing) samt 1.1.1.3 og 1.0.0.3 (også voksenindhold). Det er almindelige DNS-forespørgsler efter navne som `example.com`; ingen del af beskeden eller dens adresser sendes. Slå dem fra med `phishing: {cloudflare: false}` eller `--no-cloudflare`, eller slå kun tjekket for voksenindhold fra med `phishing: {adult: false}`.

Alt andet er slået fra, indtil det konfigureres:

| Tjek                | Sender                                                                                                              | Til                                                                    |
| ------------------- | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `authentication`    | DNS-forespørgsler efter afsenderens SPF-, DKIM-, DMARC- og ARC-poster                                               | Din resolver eller `dnsServers`                                        |
| `dnsbl`             | Klientens IP-adresse, vendt om, og domæner i links, som DNS-forespørgsler                                           | Blokeringslisternes navneservere via din resolver eller `dns.servers`  |
| `llm`               | Et resumé af beskeden, med personoplysninger fjernet for eksterne udbydere                                          | Den server til sprogmodellen, du angiver ([privatliv](llm.md#privacy)) |
| `reputation.apiUrl` | Klientens IP-adresse og verificerede værtsnavn samt From-, kuvertafsender- og Reply-To-adresserne med deres domæner | Den tjeneste, du angiver                                               |
| `clamav`            | Vedhæftede filer                                                                                                    | Din clamd via dens socket                                              |

Der er ingen telemetri, intet opdateringstjek og ingen download under kørsel. Modellen leveres i pakken.


## Hvad den gemmer

Intet, medmindre den bliver bedt om det. Scanninger logges eller gemmes ikke. `learn()` ændrer klassifikatoren i hukommelsen; den skrives kun til disk af `saveModel()`, `spamscanner learn` eller servernes indstilling `--out`. En modelfil indeholder hashede optællinger af features, ikke ord eller beskedtekst.

Svar fra sprogmodeller caches i hukommelsen med en hash af det, der blev sendt, som nøgle, så gentagne kopier af den samme besked kun spørges om én gang. DNS-svar caches i hukommelsen i ti minutter og en omdømmetjenestes svar i fem (`reputation.cacheTtl`; en mislykket forespørgsel i ét minut).


## Fjendtligt input

* Vedhæftede filer identificeres ud fra deres bytes og bliver aldrig kørt eller åbnet af et andet program. ZIP-arkiver læses fra deres centrale katalog med grænser for antallet af poster (2000) og for bytes i deres navne (1 MiB; et navn over 1 KiB beholder sine første og sidste 512 bytes, og fund viser højst 100 tegn af et), og hver post læses én gang, uanset hvor mange katalogposter der peger på den; intet dekomprimeres, så programmer i indlejrede eller komprimerede arkiver ses ikke. Vedhæftede beskeder (`message/rfc822`, eller vedhæftninger, hvis filnavn ender på `.eml`) åbnes op til tre niveauer dybt, for højst 100 af deres vedhæftninger og i alt 25 MB vedhæftede beskeder; beskedens egne vedhæftninger undersøges altid alle. En besked ud over MIME-parserens grænser (mere end 1000 dele eller en dels header over 1 MB) læses så langt, parseren tillader (dens første dele, med en for stor header skåret ned, så dens afsender stadig tæller), og får `MIME_TOO_COMPLEX`, som ingen kredit opvejer; ClamAV læser den hele. En vedhæftet besked, som parseren fejler på, får den også og får aldrig scanningen til at fejle. Adressefelter læses op til 16 KB hver (2000 adresser, 16 indlejrede grupper) og 64 KB i alt for hver besked, kun afkortet ved slutningen af en hel adresse, da adresseparseren bruger tid, der vokser med kvadratet på antallet af adresser; mailauth læser From og Return-Path lige så begrænset (de andre felter som de er, så en signatur over dem holder), og en header, som det ville tage mere end lineær tid at læse (tusindvis af foldede linjer eller signaturer, der nævner tusindvis af felter), skæres ned. Et afkortet From-felt får DMARC til at fejle og matcher intet på tilladelseslisten. HTML læses af Spam Scanners egen parser, i lineær tid, uanset hvor dybt det er indlejret.
* Brødtekst læses op til `maxLength` (100.000 tegn), og serverne accepterer beskeder op til 25 MB. Links læses op til `phishing.maxLength` (1.000.000 tegn).
* Hvert netværkstjek har en tidsgrænse (`timeout`, 10 sekunder som standard). Et tjek, der fejler eller overskrider tidsgrænsen, springes over, og scanningen gøres færdig uden det. Godkendelse og billedmodellen (de første 10 billeder) bliver hver især færdige inden for den samlet: godkendelse sender ingen DNS-forespørgsel efter den og ikke flere end 300 for én besked (plads til SPF ved grænserne i RFC 7208, med DKIM, ARC, DMARC og BIMI), og tjekker kun de første 8 DKIM-signaturer i en besked (mailauth læser selv højst 50 ARC-sæt). Den `Authentication-Results`-header, som milteren tilføjer, indeholder højst 8 KiB resultater. ClamAV (fire vedhæftninger ad gangen) har sin egen grænse for alle en beskeds vedhæftninger (`clamav.timeout`, 60 sekunder), og vedhæftninger, den ikke kunne scanne, vises i `results.virusScanErrors`. Sprogmodellen har sin egen (`llm.timeout`).
* Tilladelseslisten stoler kun på det, en afsender ikke kan forfalske: klientens adresse og verificerede værtsnavn samt afsenderdomæner, som godkendelsen bekræfter. [Tilladelses- og blokeringsliste](api.md#allowlist-and-denylist)
* `X-Spam-*`-headere, der allerede står i en besked, fjernes af milteren, indholdsfilteret og `--headers`, så afsendere ikke kan markere deres egen post som ren.
* Microsofts headere med spamdomme stoles kun på, når beskeden kom direkte fra Microsofts servere, og Received-headere bruges aldrig til at afgøre, hvor en besked kom fra.
* Tekst, der henvender sig til AI-filtre, scores som spam, og sprogmodellen får at vide, at beskeden er data og ikke instruktioner. [Prompt injection](llm.md#prompt-injection)


## Servere

Milter-, HTTP-, TCP- og spamd-serverne lytter på 127.0.0.1, medmindre `--host` siger noget andet. HTTP API'et sammenligner sit token i konstant tid og afviser `/learn` uden et. Ingen af dem taler TLS: for at nå dem over et netværk skal du bruge et privat netværk, en SSH-tunnel eller en reverse proxy med TLS.

Kør dem som en bruger uden privilegier. [systemd-unitten i vejledningen til Postfix](postfix.md#1-run-the-milter) tilføjer den sædvanlige hærdning.


## Rapportering af en sårbarhed

Rapportér sikkerhedsproblemer privat via [GitHubs rapportering af sårbarheder](https://github.com/spamscanner/spamscanner/security/advisories/new), ikke i offentlige issues.
