<!-- source: df3e980c3ef1 -->

# Beveiliging en privacy

Spam Scanner leest mail, die privé is, van afzenders die vijandig kunnen zijn. Deze pagina noemt wat het ergens heen stuurt en hoe het omgaat met wat het leest.


## Wat de machine verlaat

Standaard één ding: de **hostnamen van links** in een bericht worden opgezocht op de filterende resolvers van Cloudflare, 1.1.1.2 en 1.0.0.2 (malware en phishing) en 1.1.1.3 en 1.0.0.3 (ook content voor volwassenen). Dit zijn gewone DNS-queries voor namen zoals `example.com`; er wordt geen deel van het bericht of van de adressen verstuurd. Zet ze uit met `phishing: {cloudflare: false}` of `--no-cloudflare`, of alleen de controle op content voor volwassenen met `phishing: {adult: false}`.

Al het andere staat uit tot je het instelt:

| Controle            | Verstuurt                                                                                                                     | Naar                                                               |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `authentication`    | DNS-queries voor de SPF-, DKIM-, DMARC- en ARC-records van de afzender                                                        | Je resolver, of `dnsServers`                                       |
| `dnsbl`             | Het IP-adres van de client, omgekeerd, en linkdomeinen, als DNS-queries                                                       | De nameservers van de blocklists, via je resolver of `dns.servers` |
| `llm`               | Een samenvatting van het bericht, zonder persoonsgegevens bij externe aanbieders                                              | De taalmodelserver die je opgeeft ([privacy](llm.md#privacy))      |
| `reputation.apiUrl` | Het IP-adres en de geverifieerde hostnaam van de client, en de From-, envelopafzender- en Reply-To-adressen, met hun domeinen | De dienst die je opgeeft                                           |
| `clamav`            | Bijlagen                                                                                                                      | Je clamd, via de socket                                            |

Er is geen telemetrie, geen updatecontrole en geen download tijdens het draaien. Het model zit in het pakket.


## Wat het bewaart

Niets, tenzij je erom vraagt. Scans worden niet gelogd of opgeslagen. `learn()` wijzigt de classifier in het geheugen; hij wordt alleen naar schijf geschreven door `saveModel()`, `spamscanner learn` of de optie `--out` van de servers. Een modelbestand bevat gehashte aantallen kenmerken, geen woorden of berichttekst.

Antwoorden van het taalmodel worden in het geheugen gecachet, met een hash van wat er werd verstuurd als sleutel, zodat herhaalde kopieën van hetzelfde bericht maar één keer worden voorgelegd. DNS-antwoorden worden tien minuten in het geheugen gecachet, en de antwoorden van een reputatiedienst vijf (`reputation.cacheTtl`; een mislukt verzoek één minuut).


## Vijandige invoer

* Bijlagen worden herkend aan hun bytes en nooit uitgevoerd of door een ander programma geopend. ZIP-archieven worden gelezen vanuit hun centrale directory, met een limiet op het aantal items; geneste archieven worden niet uitgepakt. Bijgevoegde berichten (`message/rfc822`, of bijlagen waarvan de bestandsnaam eindigt op `.eml`) worden tot drie niveaus diep geopend, voor hoogstens 100 van hun bijlagen en in totaal 25 MB aan bijgevoegde berichten; de eigen bijlagen van het bericht worden altijd allemaal gecontroleerd. Een bericht dat buiten de limieten van de MIME-parser valt (meer dan 1000 delen, of een header van een deel boven 1 MB), wordt gelezen voor zover de parser toelaat (de eerste delen, met een te grote header ingekort zodat de afzender nog meetelt) en krijgt `MIME_TOO_COMPLEX`, wat geen enkele aftrek compenseert; ClamAV leest het in zijn geheel. Een bijgevoegd bericht waarop de parser faalt, krijgt het ook en laat de scan nooit mislukken. HTML wordt gelezen door de eigen parser van Spam Scanner, in lineaire tijd, hoe diep het ook genest is.
* Bodytekst wordt gelezen tot `maxLength` (100.000 tekens) en de servers accepteren berichten tot 25 MB. Links worden gelezen tot `phishing.maxLength` (1.000.000 tekens).
* Elke netwerkcontrole heeft een time-out (`timeout`, standaard 10 seconden). Een controle die mislukt of een time-out krijgt, wordt overgeslagen en de scan rondt zonder die controle af. Authenticatie en het beeldmodel (de eerste 10 afbeeldingen) zijn elk in hun geheel binnen die tijd klaar. ClamAV (vier bijlagen tegelijk) heeft een eigen limiet voor alle bijlagen van een bericht samen (`clamav.timeout`, 60 seconden), en bijlagen die het niet kon scannen staan in `results.virusScanErrors`. Het taalmodel heeft een eigen limiet (`llm.timeout`).
* De toestaanlijst vertrouwt alleen wat een afzender niet kan vervalsen: het adres en de geverifieerde hostnaam van de client, en afzenderdomeinen die de authenticatie bevestigt. [Toestaan- en blokkeerlijst](api.md#allowlist-and-denylist)
* `X-Spam-*`-headers die al in een bericht staan, worden verwijderd door de milter, het contentfilter en `--headers`, zodat afzenders hun eigen mail niet als schoon kunnen markeren.
* De spamoordeelheaders van Microsoft worden alleen vertrouwd als het bericht rechtstreeks van de servers van Microsoft kwam, en Received-headers worden nooit gebruikt om te bepalen waar een bericht vandaan kwam.
* Tekst die zich tot AI-filters richt, wordt als spam gescoord, en het taalmodel krijgt te horen dat het bericht data is, geen instructies. [Prompt injection](llm.md#prompt-injection)


## Servers

De milter-, HTTP-, TCP- en spamd-servers luisteren op 127.0.0.1, tenzij `--host` iets anders zegt. De HTTP API vergelijkt zijn token in constante tijd en weigert `/learn` zonder token. Geen ervan spreekt TLS: om ze over een netwerk te bereiken, gebruik je een privénetwerk, een SSH-tunnel of een reverse proxy met TLS.

Draai ze als gebruiker zonder rechten. De [systemd-unit in de Postfix-handleiding](postfix.md#1-run-the-milter) voegt de gebruikelijke hardening toe.


## Een kwetsbaarheid melden

Meld beveiligingsproblemen privé via [de kwetsbaarheidsmeldingen van GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), niet in openbare issues.
