<!-- source: 988243aec4f3 -->

<!--
label: Zelf gehost spamfilter
title: Zelf gehost spamfilter voor je eigen mailserver
description: Een spamfilter op je eigen server. Spam Scanner houdt de mail op de machine, levert het model mee in het pakket, verstuurt geen telemetrie en werkt met Postfix of Exim.
keywords: zelf gehost spamfilter, on-premises spamfilter, privé spamfilter, lokaal spamfilter, spamfilter voor mailserver, spamfilter zonder cloud
-->

# Zelf gehost spamfilter

Spam Scanner draait op je eigen server en houdt de mail daar. Het model van de classifier zit in het pakket, er is geen telemetrie of updatecontrole, en standaard verstuurt het alleen een DNS-query voor de hostnaam van elke link.


## Wat de server verlaat

Standaard alleen de hostnamen van links in een bericht. Die worden als gewone DNS-query's opgezocht bij de filterende resolvers van Cloudflare (1.1.1.2 en 1.1.1.3), en geen enkel deel van het bericht of de adressen wordt verstuurd. `--no-cloudflare` zet ook dat uit.

Elke andere controle die het netwerk gebruikt staat uit tot je hem aanzet:

| Controle              | Aanzetten met        | Wat het verstuurt                                                    |
| --------------------- | -------------------- | -------------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | DNS-query's naar de records van de afzender                          |
| DNS-blocklists        | `--dnsbl`, `--uribl` | Het IP-adres van de client en de domeinen van links, als DNS-query's |
| ClamAV                | `--clamav`           | Bijlagen, naar je eigen clamd                                        |
| Een taalmodel         | `--llm`              | Een samenvatting van het bericht, naar de server die je opgeeft      |

Scans worden niet gelogd of bewaard. [Beveiliging en privacy](../../docs/security.md)


## Installeren op een server

```sh
npm install --global spamscanner
```

Of de losse binary, met Node.js en het model ingebouwd:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Het installatiescript controleert de binary met het bestand `SHA256SUMS` van de release voordat het hem installeert, en elke binary heeft een ondertekende build-provenance-attestatie die `gh attestation verify` controleert. Er zijn binaries voor Linux (x64 en arm64), macOS en Windows. De Linux-binaries hebben glibc nodig, dus installeer op Alpine met npm. [Aan de slag](../../docs/getting-started.md)

Er is geen updatecontrole. Voer om bij te werken de installatieopdracht opnieuw uit: beide opdrachten installeren de nieuwste release.


## Als service draaien

De milter-, HTTP-, TCP- en spamd-servers luisteren op 127.0.0.1, tenzij `--host` iets anders zegt. Draai ze als gebruiker zonder rechten, bijvoorbeeld onder systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

De [volledige unit en de inrichting](../../docs/postfix.md#1-run-the-milter) staan in de Postfix-handleiding. Geen van de servers spreekt TLS; gebruik een privénetwerk, een SSH-tunnel of een reverse proxy met TLS om er vanaf een andere machine bij te komen.


## Je mailserver koppelen

| Mailserver                            | Opdracht                                | Poort |
| ------------------------------------- | --------------------------------------- | ----- |
| Postfix of Sendmail                   | `spamscanner milter`                    | 7831  |
| Postfix, zonder ooit mail te weigeren | `spamscanner filter`, een contentfilter | geen  |
| Exim, Haraka of spamc                 | `spamscanner spamd`                     | 783   |
| Alles wat HTTP spreekt                | `spamscanner http`                      | 7832  |
| Een eenvoudige TCP-client             | `spamscanner server`                    | 7830  |
| Een mailserver geschreven in Node.js  | `import SpamScanner from 'spamscanner'` | geen  |

De servers kunnen de headers `X-Spam-Flag`, `X-Spam-Score` en `X-Spam-Status` aan het bericht toevoegen, en de bibliotheek geeft de score en elke test die afging terug. Handleidingen: [spamfilter voor Postfix](/postfix-spam-filter/), [andere mailservers](../../docs/mail-servers.md) en [de HTTP-API](../../docs/http-api.md).


## Taalmodellen lokaal houden

Een taalmodel is optioneel en leest alleen twijfelgevallen: duidelijke spam en duidelijke ham bereiken het nooit. Met Ollama draait het op dezelfde server, zodat geen bericht die verlaat:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` draait op een CPU. Gebruik je een gehoste aanbieder, dan worden persoonsgegevens uit het bericht verwijderd voordat het wordt verstuurd. [Taalmodellen](../../docs/llm.md)


## Trainen op je eigen mail

Het meegeleverde model is getraind op openbare datasets. Een model dat is getraind op de mail die je server ontvangt doet het beter, en het blijft op die server:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Een modelbestand bevat gehashte tellingen van kenmerken, geen woorden of berichttekst. [Training](../../docs/training.md)


## Vereisten

Node.js 18 of nieuwer op Linux, macOS of Windows, of niets met een losse binary. ClamAV en Ollama zijn optioneel en draaien als eigen services.
