<!-- source: 988243aec4f3 -->

<!--
label: Selvdriftet spamfilter
title: Selvdriftet spamfilter for din egen e-postserver
description: Et spamfilter på din egen server. Spam Scanner holder e-posten på maskinen, har modellen med i pakken, sender ingen telemetri og passer med Postfix eller Exim.
keywords: selvdriftet spamfilter, selvhostet spamfilter, privat spamfilter, lokalt spamfilter, spamfilter for e-postserver, spamfilter uten sky
-->

# Selvdriftet spamfilter

Spam Scanner kjører på din egen server og holder e-posten der. Klassifikatorens modell ligger i pakken, det finnes ingen telemetri eller oppdateringssjekk, og som standard sender det bare et DNS-oppslag for vertsnavnet i hver lenke.


## Hva som forlater serveren

Som standard bare vertsnavnene i lenkene i en melding. De slås opp hos Cloudflares filtrerende resolvere (1.1.1.2 og 1.1.1.3) som vanlige DNS-spørringer, og ingen del av meldingen eller adressene sendes. `--no-cloudflare` slår også dette av.

Alle andre kontroller som bruker nettverket er av til du slår dem på:

| Kontroll              | Slå på med           | Hva den sender                                               |
| --------------------- | -------------------- | ------------------------------------------------------------ |
| SPF, DKIM, DMARC, ARC | `--auth`             | DNS-spørringer etter avsenderens poster                      |
| DNS-blokkeringslister | `--dnsbl`, `--uribl` | Klientens IP-adresse og lenkenes domener, som DNS-spørringer |
| ClamAV                | `--clamav`           | Vedlegg, til din egen clamd                                  |
| En språkmodell        | `--llm`              | Et sammendrag av meldingen, til serveren du oppgir           |

Skanninger logges ikke og lagres ikke. [Sikkerhet og personvern](../../docs/security.md)


## Installer på en server

```sh
npm install --global spamscanner
```

Eller den frittstående binærfilen, med Node.js og modellen innebygd:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Installasjonsskriptet kontrollerer binærfilen mot utgivelsens `SHA256SUMS`-fil før den installeres, og hver binærfil har en signert attestasjon av byggets opprinnelse som `gh attestation verify` kontrollerer. Det finnes binærfiler for Linux (x64 og arm64), macOS og Windows. Linux-filene krever glibc, så installer med npm på Alpine. [Kom i gang](../../docs/getting-started.md)

Det finnes ingen oppdateringssjekk. For å oppdatere kjører du installasjonskommandoen på nytt: begge kommandoene installerer den nyeste utgivelsen.


## Kjør det som tjeneste

Milter-, HTTP-, TCP- og spamd-serverne lytter på 127.0.0.1 med mindre `--host` sier noe annet. Kjør dem som en bruker uten rettigheter, for eksempel under systemd:

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

Den [fullstendige enheten og oppsettet](../../docs/postfix.md#1-run-the-milter) står i Postfix-veiledningen. Ingen av serverne snakker TLS; for å nå en fra en annen maskin bruker du et privat nettverk, en SSH-tunnel eller en omvendt proxy med TLS.


## Koble til e-postserveren din

| E-postserver                            | Kommando                                | Port  |
| --------------------------------------- | --------------------------------------- | ----- |
| Postfix eller Sendmail                  | `spamscanner milter`                    | 7831  |
| Postfix, uten noen gang å avvise e-post | `spamscanner filter`, et innholdsfilter | ingen |
| Exim, Haraka eller spamc                | `spamscanner spamd`                     | 783   |
| Alt som snakker HTTP                    | `spamscanner http`                      | 7832  |
| En enkel TCP-klient                     | `spamscanner server`                    | 7830  |
| En e-postserver skrevet i Node.js       | `import SpamScanner from 'spamscanner'` | ingen |

Serverne kan legge til hodene `X-Spam-Flag`, `X-Spam-Score` og `X-Spam-Status` i meldingen, og biblioteket returnerer poengsummen og hver test som slo til. Veiledninger: [spamfilter for Postfix](/postfix-spam-filter/), [andre e-postservere](../../docs/mail-servers.md) og [HTTP-API-et](../../docs/http-api.md).


## Hold språkmodellene lokale

En språkmodell er valgfri og leser bare tvilstilfeller: tydelig spam og tydelig ham når den aldri. Med Ollama kjører den på samme server, så ingen melding forlater den:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` kjører på en CPU. Med en ekstern leverandør fjernes personopplysninger fra meldingen før den sendes. [Språkmodeller](../../docs/llm.md)


## Tren det på din egen e-post

Den medfølgende modellen er trent på offentlige datasett. En modell som er trent på e-posten serveren din mottar, gjør det bedre, og den blir på serveren:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

En modellfil inneholder hashede tellinger av kjennetegn, ikke ord eller meldingstekst. [Trening](../../docs/training.md)


## Krav

Node.js 18 eller nyere på Linux, macOS eller Windows, eller ingenting med en frittstående binærfil. ClamAV og Ollama er valgfrie og kjører som egne tjenester.
