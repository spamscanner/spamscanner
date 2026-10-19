<!-- source: 1d7373f991c2 -->

# Sikkerhet og personvern

Spam Scanner leser e-post, som er privat, fra avsendere, som kan være fiendtlige. Denne siden lister opp hva det sender noe sted, og hvordan det behandler det det leser.


## Hva som forlater maskinen

Som standard én ting: **vertsnavnene i lenker** i en melding slås opp på Cloudflares filtrerende resolvere, 1.1.1.2 og 1.0.0.2 (skadevare og phishing) og 1.1.1.3 og 1.0.0.3 (i tillegg voksent innhold). Dette er vanlige DNS-forespørsler etter navn som `example.com`; ingen del av meldingen eller adressene i den sendes. Slå dem av med `phishing: {cloudflare: false}` eller `--no-cloudflare`, eller bare sjekken av voksent innhold med `phishing: {adult: false}`.

Alt annet er av inntil det konfigureres:

| Sjekk               | Sender                                                                                                                | Til                                                                        |
| ------------------- | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `authentication`    | DNS-forespørsler etter avsenderens SPF-, DKIM-, DMARC- og ARC-poster                                                  | Din resolver, eller `dnsServers`                                           |
| `dnsbl`             | Klientens IP-adresse, reversert, og domener i lenker, som DNS-forespørsler                                            | Navneserverne til blokkeringslistene, via din resolver eller `dns.servers` |
| `llm`               | Et sammendrag av meldingen, med personopplysninger fjernet for eksterne leverandører                                  | Serveren for språkmodellen som du angir ([personvern](llm.md#privacy))     |
| `reputation.apiUrl` | Klientens IP-adresse og verifiserte vertsnavn, og From-, konvoluttavsender- og Reply-To-adressene, med domenene deres | Tjenesten du angir                                                         |
| `clamav`            | Vedlegg                                                                                                               | Din clamd, over socketen                                                   |

Det finnes ingen telemetri, ingen oppdateringssjekk og ingen nedlasting under kjøring. Modellen følger med i pakken.


## Hva det beholder

Ingenting, med mindre du ber om det. Skanninger blir ikke logget eller lagret. `learn()` endrer klassifisereren i minnet; den skrives bare til disk av `saveModel()`, `spamscanner learn` eller serverens `--out`-alternativ. En modellfil inneholder hashede tellinger av egenskaper, ikke ord eller meldingstekst.

Svar fra språkmodellen mellomlagres i minnet, med en hash av det som ble sendt som nøkkel, så det spørres bare én gang om gjentatte kopier av den samme meldingen. DNS-svar mellomlagres i minnet i ti minutter, og svar fra en omdømmetjeneste i fem (`reputation.cacheTtl`; en mislykket forespørsel i ett minutt).


## Fiendtlige inndata

* Vedlegg identifiseres ut fra bytene, og blir aldri kjørt eller åpnet av et annet program. ZIP-arkiver leses fra den sentrale katalogen, med grenser for antall oppføringer (2000) og for bytene i navnene deres (1 MiB; et navn over 1 KiB beholder sine første og siste 512 byte, og funn viser høyst 100 tegn av et navn), og hver oppføring leses én gang uansett hvor mange kataloger som peker på den; ingenting pakkes ut, så programmer inne i nøstede eller komprimerte arkiver blir ikke sett. Vedlagte meldinger (`message/rfc822`, eller vedlegg der filnavnet slutter på `.eml`) åpnes opptil tre nivåer dypt, for høyst 100 av vedleggene deres og 25 MB vedlagte meldinger totalt; meldingens egne vedlegg undersøkes alltid alle. En melding som går ut over MIME-parserens grenser (mer enn 1000 deler, eller en dels header over 1 MB), leses så langt parseren tillater (de første delene, med en for stor header kortet ned slik at avsenderen fortsatt teller) og får `MIME_TOO_COMPLEX`, som ingen kreditt oppveier; ClamAV leser den i sin helhet. En vedlagt melding som parseren feiler på, får den også, og får aldri skanningen til å mislykkes. Adressefelt leses opptil 16 KB hver (2000 adresser, 16 nøstede grupper) og 64 KB totalt for hver melding, og kuttes bare på slutten av en hel adresse, fordi adresseparseren bruker tid som vokser med kvadratet av antall adresser; mailauth leser From og Return-Path også slik avgrenset (de andre feltene som de er, så en signatur over dem holder), og en header det ville tatt lengre enn lineær tid å lese (tusenvis av foldede linjer, eller signaturer som nevner tusenvis av felt), kortes ned. Et kuttet From-felt feiler DMARC og gir ingen treff i tillatelseslister. HTML leses av Spam Scanners egen parser, i lineær tid, uansett hvor dypt den er nøstet.
* Brødteksten leses opp til `maxLength` (100 000 tegn), og serverne godtar meldinger på opptil 25 MB. Lenker leses opptil `phishing.maxLength` (1 000 000 tegn).
* Hver nettverkssjekk har en tidsgrense (`timeout`, 10 sekunder som standard). En sjekk som feiler eller får tidsavbrudd, hoppes over, og skanningen fullføres uten den. Autentisering og bildemodellen (de første 10 bildene) blir hver for seg ferdige innenfor den totalt: autentiseringen sender ingen DNS-spørring etter den, og heller ikke flere enn 300 for én melding (plass til SPF ved grensene i RFC 7208, med DKIM, ARC, DMARC og BIMI), og sjekker bare de første 8 DKIM-signaturene i en melding (mailauth selv leser høyst 50 ARC-sett). `Authentication-Results`-headeren som milteren legger til, inneholder høyst 8 KiB med resultater. ClamAV (fire vedlegg om gangen) har sin egen grense for alle vedleggene i en melding (`clamav.timeout`, 60 sekunder), og vedlegg den ikke kunne skanne, står i `results.virusScanErrors`. Språkmodellen har sin egen (`llm.timeout`).
* Tillatelseslisten stoler bare på det en avsender ikke kan forfalske: klientens adresse og verifiserte vertsnavn, og avsenderdomener som autentiseringen bekrefter. [Tillatelses- og blokkeringsliste](api.md#allowlist-and-denylist)
* `X-Spam-*`-hoder som allerede finnes i en melding, fjernes av milteren, innholdsfilteret og `--headers`, så avsendere ikke kan merke sin egen e-post som ren.
* Microsofts hoder med spamvurdering stoles bare på når meldingen kom direkte fra Microsofts servere, og Received-hoder brukes aldri til å avgjøre hvor en melding kom fra.
* Tekst rettet mot KI-filtre får poeng som spam, og språkmodellen får beskjed om at meldingen er data, ikke instruksjoner. [Prompt injection](llm.md#prompt-injection)


## Servere

Serverne for milter, HTTP, TCP og spamd lytter på 127.0.0.1 med mindre `--host` sier noe annet. HTTP API-et sammenligner tokenet sitt på konstant tid og avviser `/learn` uten token. Ingen av dem snakker TLS: for å nå dem over et nettverk bruker du et privat nettverk, en SSH-tunnel eller en omvendt proxy med TLS.

Kjør dem som en bruker uten privilegier. [systemd-enheten i veiledningen for Postfix](postfix.md#1-run-the-milter) legger til den vanlige herdingen.


## Rapportere en sårbarhet

Rapporter sikkerhetsproblemer privat via [GitHubs rapportering av sårbarheter](https://github.com/spamscanner/spamscanner/security/advisories/new), ikke i offentlige issues.
