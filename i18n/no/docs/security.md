<!-- source: 60f00f92b5aa -->

# Sikkerhet og personvern

Spam Scanner leser e-post, som er privat, fra avsendere, som kan være fiendtlige. Denne siden lister opp hva det sender noe sted, og hvordan det behandler det det leser.


## Hva som forlater maskinen

Som standard én ting: **vertsnavnene i lenker** i en melding slås opp på Cloudflares filtrerende resolvere, 1.1.1.2 og 1.0.0.2 (skadevare og phishing) og 1.1.1.3 og 1.0.0.3 (i tillegg voksent innhold). Dette er vanlige DNS-forespørsler etter navn som `example.com`; ingen del av meldingen eller adressene i den sendes. Slå dem av med `phishing: {cloudflare: false}` eller `--no-cloudflare`, eller bare sjekken av voksent innhold med `phishing: {adult: false}`.

Alt annet er av inntil det konfigureres:

| Sjekk               | Sender                                                                               | Til                                                                        |
| ------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| `authentication`    | DNS-forespørsler etter avsenderens SPF-, DKIM-, DMARC- og ARC-poster                 | Din resolver, eller `dnsServers`                                           |
| `dnsbl`             | Klientens IP-adresse, reversert, og domener i lenker, som DNS-forespørsler           | Navneserverne til blokkeringslistene, via din resolver eller `dns.servers` |
| `llm`               | Et sammendrag av meldingen, med personopplysninger fjernet for eksterne leverandører | Serveren for språkmodellen som du angir ([personvern](llm.md#privacy))     |
| `reputation.apiUrl` | Avsenderens IP-adresse, domene og adresse                                            | Tjenesten du angir                                                         |
| `clamav`            | Vedlegg                                                                              | Din clamd, over socketen                                                   |

Det finnes ingen telemetri, ingen oppdateringssjekk og ingen nedlasting under kjøring. Modellen følger med i pakken.


## Hva det beholder

Ingenting, med mindre du ber om det. Skanninger blir ikke logget eller lagret. `learn()` endrer klassifisereren i minnet; den skrives bare til disk av `saveModel()`, `spamscanner learn` eller serverens `--out`-alternativ. En modellfil inneholder hashede tellinger av egenskaper, ikke ord eller meldingstekst.

Svar fra språkmodellen mellomlagres i minnet, med en hash av det som ble sendt som nøkkel, så det spørres bare én gang om gjentatte kopier av den samme meldingen. DNS-svar mellomlagres i minnet i ti minutter.


## Fiendtlige inndata

* Vedlegg identifiseres ut fra bytene, og blir aldri kjørt eller åpnet av et annet program. ZIP-arkiver leses fra den sentrale katalogen, med en grense for antall oppføringer; nøstede arkiver pakkes ikke ut.
* Brødteksten leses opp til `maxLength` (100 000 tegn), og serverne godtar meldinger på opptil 25 MB.
* Hver nettverkssjekk har en tidsgrense (`timeout`, 10 sekunder som standard). En sjekk som feiler eller får tidsavbrudd, hoppes over, og skanningen fullføres uten den.
* `X-Spam-*`-hoder som allerede finnes i en melding, fjernes av milteren, innholdsfilteret og `--headers`, så avsendere ikke kan merke sin egen e-post som ren.
* Microsofts hoder med spamvurdering stoles bare på når meldingen kom direkte fra Microsofts servere, og Received-hoder brukes aldri til å avgjøre hvor en melding kom fra.
* Tekst rettet mot KI-filtre får poeng som spam, og språkmodellen får beskjed om at meldingen er data, ikke instruksjoner. [Prompt injection](llm.md#prompt-injection)


## Servere

Serverne for milter, HTTP, TCP og spamd lytter på 127.0.0.1 med mindre `--host` sier noe annet. HTTP API-et sammenligner tokenet sitt på konstant tid og avviser `/learn` uten token. Ingen av dem snakker TLS: for å nå dem over et nettverk bruker du et privat nettverk, en SSH-tunnel eller en omvendt proxy med TLS.

Kjør dem som en bruker uten privilegier. [systemd-enheten i veiledningen for Postfix](postfix.md#1-run-the-milter) legger til den vanlige herdingen.


## Rapportere en sårbarhet

Rapporter sikkerhetsproblemer privat via [GitHubs rapportering av sårbarheter](https://github.com/spamscanner/spamscanner/security/advisories/new), ikke i offentlige issues.
