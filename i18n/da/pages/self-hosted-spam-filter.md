<!-- source: 988243aec4f3 -->

<!--
label: Selvhostet spamfilter
title: Selvhostet spamfilter til din egen mailserver
description: Et spamfilter på din egen server. Spam Scanner holder mailen på maskinen, har modellen med i pakken, sender ingen telemetri og passer til Postfix eller Exim.
keywords: selvhostet spamfilter, on-premises spamfilter, privat spamfilter, lokalt spamfilter, spamfilter til mailserver, spamfilter uden cloud
-->

# Selvhostet spamfilter

Spam Scanner kører på din egen server og holder mailen der. Klassifikatorens model ligger i pakken, der er ingen telemetri eller opdateringstjek, og som standard sender det kun et DNS-opslag for værtsnavnet i hvert link.


## Hvad der forlader serveren

Som standard kun værtsnavnene i en beskeds links. De slås op hos Cloudflares filtrerende resolvere (1.1.1.2 og 1.1.1.3) som almindelige DNS-forespørgsler, og ingen del af beskeden eller dens adresser sendes. `--no-cloudflare` slår også det fra.

Alle andre tjek, der bruger netværket, er slået fra, indtil du slår dem til:

| Tjek                  | Slå til med          | Hvad det sender                                                 |
| --------------------- | -------------------- | --------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | DNS-forespørgsler efter afsenderens poster                      |
| DNS-blokeringslister  | `--dnsbl`, `--uribl` | Klientens IP-adresse og linkenes domæner, som DNS-forespørgsler |
| ClamAV                | `--clamav`           | Vedhæftede filer, til din egen clamd                            |
| En sprogmodel         | `--llm`              | Et resumé af beskeden, til den server, du angiver               |

Scanninger logges og gemmes ikke. [Sikkerhed og privatliv](../../docs/security.md)


## Installér på en server

```sh
npm install --global spamscanner
```

Eller den selvstændige binære fil, med Node.js og modellen indbygget:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Installationsscriptet tjekker den binære fil mod udgivelsens `SHA256SUMS`-fil, før den installeres, og hver binær fil har en signeret attestering af byggets oprindelse, som `gh attestation verify` tjekker. Der er binære filer til Linux (x64 og arm64), macOS og Windows. Linux-filerne kræver glibc, så installér med npm på Alpine. [Kom i gang](../../docs/getting-started.md)

Der er intet opdateringstjek. For at opdatere skal du køre installationskommandoen igen: begge kommandoer installerer den nyeste udgivelse.


## Kør det som tjeneste

Milter-, HTTP-, TCP- og spamd-serverne lytter på 127.0.0.1, medmindre `--host` siger andet. Kør dem som en bruger uden rettigheder, for eksempel under systemd:

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

Den [fulde enhed og dens opsætning](../../docs/postfix.md#1-run-the-milter) står i Postfix-guiden. Ingen af serverne taler TLS; for at nå en fra en anden maskine skal du bruge et privat netværk, en SSH-tunnel eller en reverse proxy med TLS.


## Forbind din mailserver

| Mailserver                              | Kommando                                | Port  |
| --------------------------------------- | --------------------------------------- | ----- |
| Postfix eller Sendmail                  | `spamscanner milter`                    | 7831  |
| Postfix, uden nogensinde at afvise mail | `spamscanner filter`, et indholdsfilter | ingen |
| Exim, Haraka eller spamc                | `spamscanner spamd`                     | 783   |
| Alt, der taler HTTP                     | `spamscanner http`                      | 7832  |
| En enkel TCP-klient                     | `spamscanner server`                    | 7830  |
| En mailserver skrevet i Node.js         | `import SpamScanner from 'spamscanner'` | ingen |

Serverne kan tilføje headerne `X-Spam-Flag`, `X-Spam-Score` og `X-Spam-Status` til beskeden, og biblioteket returnerer scoren og hver test, der slog til. Guider: [spamfilter til Postfix](/postfix-spam-filter/), [andre mailservere](../../docs/mail-servers.md) og [HTTP-API'et](../../docs/http-api.md).


## Hold sprogmodellerne lokale

En sprogmodel er valgfri og læser kun tvivlstilfælde: tydelig spam og tydelig ham når den aldrig. Med Ollama kører den på samme server, så ingen besked forlader den:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` kører på en CPU. Med en hostet udbyder fjernes personoplysninger fra beskeden, før den sendes. [Sprogmodeller](../../docs/llm.md)


## Træn det på din egen mail

Den medfølgende model er trænet på offentlige datasæt. En model, der er trænet på den mail, din server modtager, klarer sig bedre, og den bliver på serveren:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

En modelfil indeholder hashede optællinger af kendetegn, ikke ord eller beskedtekst. [Træning](../../docs/training.md)


## Krav

Node.js 18 eller nyere på Linux, macOS eller Windows, eller intet med en selvstændig binær fil. ClamAV og Ollama er valgfrie og kører som egne tjenester.
