<!-- source: 60f00f92b5aa -->

# Säkerhet och integritet

Spam Scanner läser e-post, som är privat, från avsändare, som kan vara fientliga. Den här sidan listar vad det skickar någonstans och hur det behandlar det som det läser.


## Vad som lämnar datorn

Som standard en sak: **värdnamnen i länkar** i ett meddelande slås upp hos Cloudflares filtrerande resolvrar, 1.1.1.2 och 1.0.0.2 (skadlig kod och nätfiske) samt 1.1.1.3 och 1.0.0.3 (även vuxeninnehåll). Det är vanliga DNS-frågor efter namn som `example.com`; ingen del av meddelandet eller dess adresser skickas. Stäng av dem med `phishing: {cloudflare: false}` eller `--no-cloudflare`, eller bara kontrollen av vuxeninnehåll med `phishing: {adult: false}`.

Allt annat är avstängt tills det konfigureras:

| Kontroll            | Skickar                                                                                  | Till                                                             |
| ------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `authentication`    | DNS-frågor efter avsändarens SPF-, DKIM-, DMARC- och ARC-poster                          | Din resolver, eller `dnsServers`                                 |
| `dnsbl`             | Klientens IP-adress, omvänd, och länkdomäner, som DNS-frågor                             | Blocklistornas namnservrar, via din resolver eller `dns.servers` |
| `llm`               | En sammanfattning av meddelandet, med personuppgifter borttagna för externa leverantörer | Den språkmodellserver du anger ([integritet](llm.md#privacy))    |
| `reputation.apiUrl` | Avsändarens IP-adress, domän och adress                                                  | Den tjänst du anger                                              |
| `clamav`            | Bilagor                                                                                  | Din clamd, över dess socket                                      |

Det finns ingen telemetri, ingen uppdateringskontroll och ingen nedladdning vid körning. Modellen levereras i paketet.


## Vad det sparar

Ingenting, om du inte ber om det. Skanningar loggas eller lagras inte. `learn()` ändrar klassificeraren i minnet; den skrivs till disk bara av `saveModel()`, `spamscanner learn` eller servrarnas alternativ `--out`. En modellfil innehåller hashade räknare för egenskaper, inte ord eller meddelandetext.

Svar från språkmodellen cachas i minnet, med en hash av det som skickades som nyckel, så upprepade kopior av samma meddelande frågas om en gång. DNS-svar cachas i minnet i tio minuter.


## Fientlig indata

* Bilagor identifieras genom sina byte och körs aldrig eller öppnas av något annat program. ZIP-arkiv läses från sin centrala katalog, med en gräns för antalet poster; nästlade arkiv packas inte upp.
* Brödtext läses upp till `maxLength` (100 000 tecken) och servrarna tar emot meddelanden upp till 25 MB.
* Varje nätverkskontroll har en tidsgräns (`timeout`, 10 sekunder som standard). En kontroll som misslyckas eller överskrider tidsgränsen hoppas över och skanningen slutförs utan den.
* `X-Spam-*`-huvuden som redan finns i ett meddelande tas bort av miltern, innehållsfiltret och `--headers`, så avsändare kan inte märka sin egen e-post som ren.
* Microsofts huvuden med spamutslag litas bara på när meddelandet kom direkt från Microsofts servrar, och Received-huvuden används aldrig för att avgöra var ett meddelande kom ifrån.
* Text som riktar sig till AI-filter poängsätts som spam, och språkmodellen får veta att meddelandet är data, inte instruktioner. [Promptinjektion](llm.md#prompt-injection)


## Servrar

Servrarna för milter, HTTP, TCP och spamd lyssnar på 127.0.0.1 om inte `--host` anger något annat. HTTP-API:t jämför sin token i konstant tid och nekar `/learn` utan en token. Ingen av dem talar TLS: för att nå dem över ett nätverk, använd ett privat nätverk, en SSH-tunnel eller en omvänd proxy med TLS.

Kör dem som en oprivilegierad användare. [systemd-enheten i Postfix-guiden](postfix.md#1-run-the-milter) lägger till den vanliga härdningen.


## Rapportera en sårbarhet

Rapportera säkerhetsproblem privat via [GitHubs sårbarhetsrapportering](https://github.com/spamscanner/spamscanner/security/advisories/new), inte i offentliga ärenden.
