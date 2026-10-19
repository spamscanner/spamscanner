<!-- source: 1d7373f991c2 -->

# Säkerhet och integritet

Spam Scanner läser e-post, som är privat, från avsändare, som kan vara fientliga. Den här sidan listar vad det skickar någonstans och hur det behandlar det som det läser.


## Vad som lämnar datorn

Som standard en sak: **värdnamnen i länkar** i ett meddelande slås upp hos Cloudflares filtrerande resolvrar, 1.1.1.2 och 1.0.0.2 (skadlig kod och nätfiske) samt 1.1.1.3 och 1.0.0.3 (även vuxeninnehåll). Det är vanliga DNS-frågor efter namn som `example.com`; ingen del av meddelandet eller dess adresser skickas. Stäng av dem med `phishing: {cloudflare: false}` eller `--no-cloudflare`, eller bara kontrollen av vuxeninnehåll med `phishing: {adult: false}`.

Allt annat är avstängt tills det konfigureras:

| Kontroll            | Skickar                                                                                                               | Till                                                             |
| ------------------- | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `authentication`    | DNS-frågor efter avsändarens SPF-, DKIM-, DMARC- och ARC-poster                                                       | Din resolver, eller `dnsServers`                                 |
| `dnsbl`             | Klientens IP-adress, omvänd, och länkdomäner, som DNS-frågor                                                          | Blocklistornas namnservrar, via din resolver eller `dns.servers` |
| `llm`               | En sammanfattning av meddelandet, med personuppgifter borttagna för externa leverantörer                              | Den språkmodellserver du anger ([integritet](llm.md#privacy))    |
| `reputation.apiUrl` | Klientens IP-adress och verifierade värdnamn, och adresserna i From, kuvertavsändaren och Reply-To, med deras domäner | Den tjänst du anger                                              |
| `clamav`            | Bilagor                                                                                                               | Din clamd, över dess socket                                      |

Det finns ingen telemetri, ingen uppdateringskontroll och ingen nedladdning vid körning. Modellen levereras i paketet.


## Vad det sparar

Ingenting, om du inte ber om det. Skanningar loggas eller lagras inte. `learn()` ändrar klassificeraren i minnet; den skrivs till disk bara av `saveModel()`, `spamscanner learn` eller servrarnas alternativ `--out`. En modellfil innehåller hashade räknare för egenskaper, inte ord eller meddelandetext.

Svar från språkmodellen cachas i minnet, med en hash av det som skickades som nyckel, så upprepade kopior av samma meddelande frågas om en gång. DNS-svar cachas i minnet i tio minuter, och en ryktestjänsts svar i fem (`reputation.cacheTtl`; en misslyckad förfrågan i en minut).


## Fientlig indata

* Bilagor identifieras genom sina byte och körs aldrig eller öppnas av något annat program. ZIP-arkiv läses från sin centrala katalog, med gränser för antalet poster (2000) och för antalet byte i deras namn (1 MiB; ett namn över 1 KiB behåller sina första och sista 512 byte, och fynd visar högst 100 tecken av ett), där varje post läses en gång hur många kataloger som än pekar på den; ingenting packas upp, så program i nästlade eller komprimerade arkiv syns inte. Bifogade meddelanden (`message/rfc822`, eller bilagor vars filnamn slutar på `.eml`) öppnas upp till tre nivåer djupt, för högst 100 av deras bilagor och 25 MB bifogade meddelanden totalt; meddelandets egna bilagor granskas alltid samtliga. Ett meddelande som överskrider MIME-tolkarens gränser (fler än 1000 delar, eller en dels header över 1 MB) läses så långt tolkaren tillåter (dess första delar, med en för stor header nedkortad så att avsändaren fortfarande räknas) och får `MIME_TOO_COMPLEX`, som inget avdrag väger upp; ClamAV läser det i sin helhet. Ett bifogat meddelande som tolkaren misslyckas med får det också, och får aldrig skanningen att misslyckas. Adressfält läses upp till 16 KB vardera (2000 adresser, 16 nästlade grupper) och 64 KB totalt för varje meddelande, avkortade bara vid slutet av en hel adress, eftersom adresstolken tar tid som växer med kvadraten på antalet adresser; mailauth läser From och Return-Path med samma gränser (de andra fälten som de är, så att en signatur över dem håller), och läser en header som det skulle ta mer än linjär tid att läsa (tusentals vikta rader, eller signaturer som anger tusentals fält) nedkortad. Ett avkortat From-fält får DMARC att misslyckas och tillåter ingenting. HTML läses av Spam Scanners egen tolkare, i linjär tid, hur djupt nästlad den än är.
* Brödtext läses upp till `maxLength` (100 000 tecken) och servrarna tar emot meddelanden upp till 25 MB. Länkar läses upp till `phishing.maxLength` (1 000 000 tecken).
* Varje nätverkskontroll har en tidsgräns (`timeout`, 10 sekunder som standard). En kontroll som misslyckas eller överskrider tidsgränsen hoppas över och skanningen slutförs utan den. Autentisering och bildmodellen (de första 10 bilderna) blir var för sig klara inom den totalt: autentiseringen skickar ingen DNS-fråga efter den, och inte fler än 300 för ett meddelande (utrymme för SPF vid gränserna i RFC 7208, med DKIM, ARC, DMARC och BIMI), och kontrollerar bara de första 8 DKIM-signaturerna i ett meddelande (mailauth läser själv högst 50 ARC-uppsättningar). Den `Authentication-Results`-header som miltern lägger till innehåller högst 8 KiB resultat. ClamAV (fyra bilagor åt gången) har en egen gräns för alla ett meddelandes bilagor (`clamav.timeout`, 60 sekunder), och bilagor som den inte kunde skanna listas i `results.virusScanErrors`. Språkmodellen har en egen (`llm.timeout`).
* Tillåtelselistan litar bara på det en avsändare inte kan förfalska: klientens adress och verifierade värdnamn, och avsändardomäner som autentiseringen bekräftar. [Tillåtelse- och spärrlista](api.md#allowlist-and-denylist)
* `X-Spam-*`-huvuden som redan finns i ett meddelande tas bort av miltern, innehållsfiltret och `--headers`, så avsändare kan inte märka sin egen e-post som ren.
* Microsofts huvuden med spamutslag litas bara på när meddelandet kom direkt från Microsofts servrar, och Received-huvuden används aldrig för att avgöra var ett meddelande kom ifrån.
* Text som riktar sig till AI-filter poängsätts som spam, och språkmodellen får veta att meddelandet är data, inte instruktioner. [Promptinjektion](llm.md#prompt-injection)


## Servrar

Servrarna för milter, HTTP, TCP och spamd lyssnar på 127.0.0.1 om inte `--host` anger något annat. HTTP-API:t jämför sin token i konstant tid och nekar `/learn` utan en token. Ingen av dem talar TLS: för att nå dem över ett nätverk, använd ett privat nätverk, en SSH-tunnel eller en omvänd proxy med TLS.

Kör dem som en oprivilegierad användare. [systemd-enheten i Postfix-guiden](postfix.md#1-run-the-milter) lägger till den vanliga härdningen.


## Rapportera en sårbarhet

Rapportera säkerhetsproblem privat via [GitHubs sårbarhetsrapportering](https://github.com/spamscanner/spamscanner/security/advisories/new), inte i offentliga ärenden.
