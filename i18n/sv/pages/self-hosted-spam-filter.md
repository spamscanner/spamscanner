<!-- source: 988243aec4f3 -->

<!--
label: Egen-hostat spamfilter
title: Egen-hostat spamfilter för din egen e-postserver
description: Ett spamfilter på din egen server. Spam Scanner behåller e-posten på maskinen, har modellen i paketet, skickar ingen telemetri och fungerar med Postfix eller Exim.
keywords: egen-hostat spamfilter, lokalt installerat spamfilter, privat spamfilter, lokalt spamfilter, spamfilter för e-postserver, spamfilter utan moln
-->

# Egen-hostat spamfilter

Spam Scanner körs på din egen server och behåller e-posten där. Klassificerarens modell finns i paketet, det finns ingen telemetri eller uppdateringskontroll, och som standard skickar det bara en DNS-fråga för värdnamnet i varje länk.


## Vad som lämnar servern

Som standard bara värdnamnen i länkarna i ett meddelande. De slås upp hos Cloudflares filtrerande resolvrar (1.1.1.2 och 1.1.1.3) som vanliga DNS-frågor, och ingen del av meddelandet eller dess adresser skickas. `--no-cloudflare` stänger av även detta.

Alla andra kontroller som använder nätverket är avstängda tills du slår på dem:

| Kontroll              | Slå på med           | Vad den skickar                                           |
| --------------------- | -------------------- | --------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | DNS-frågor om avsändarens poster                          |
| DNS-blocklistor       | `--dnsbl`, `--uribl` | Klientens IP-adress och länkarnas domäner, som DNS-frågor |
| ClamAV                | `--clamav`           | Bilagor, till din egen clamd                              |
| En språkmodell        | `--llm`              | En sammanfattning av meddelandet, till servern du anger   |

Skanningar loggas inte och sparas inte. [Säkerhet och integritet](../../docs/security.md)


## Installera på en server

```sh
npm install --global spamscanner
```

Eller den fristående binärfilen, med Node.js och modellen inbyggda:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Installationsskriptet kontrollerar binärfilen mot releasens `SHA256SUMS`-fil innan den installeras, och varje binärfil har en signerad attestering av byggets ursprung som `gh attestation verify` kontrollerar. Binärfilerna finns för Linux (x64 och arm64), macOS och Windows. Linux-binärfilerna kräver glibc, så installera med npm på Alpine. [Kom igång](../../docs/getting-started.md)

Det finns ingen uppdateringskontroll. Kör installationskommandot igen för att uppdatera: båda kommandona installerar den senaste releasen.


## Kör det som tjänst

Milter-, HTTP-, TCP- och spamd-servrarna lyssnar på 127.0.0.1 om inte `--host` säger något annat. Kör dem som en användare utan behörigheter, till exempel under systemd:

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

Den [fullständiga enheten och dess installation](../../docs/postfix.md#1-run-the-milter) finns i Postfix-guiden. Ingen av servrarna talar TLS; för att nå en från en annan maskin, använd ett privat nätverk, en SSH-tunnel eller en omvänd proxy med TLS.


## Koppla din e-postserver

| E-postserver                             | Kommando                                  | Port  |
| ---------------------------------------- | ----------------------------------------- | ----- |
| Postfix eller Sendmail                   | `spamscanner milter`                      | 7831  |
| Postfix, utan att någonsin avvisa e-post | `spamscanner filter`, ett innehållsfilter | ingen |
| Exim, Haraka eller spamc                 | `spamscanner spamd`                       | 783   |
| Allt som talar HTTP                      | `spamscanner http`                        | 7832  |
| En enkel TCP-klient                      | `spamscanner server`                      | 7830  |
| En e-postserver skriven i Node.js        | `import SpamScanner from 'spamscanner'`   | ingen |

Servrarna kan lägga till rubrikerna `X-Spam-Flag`, `X-Spam-Score` och `X-Spam-Status` i meddelandet, och biblioteket returnerar poängen och varje test som slog till. Guider: [spamfilter för Postfix](/postfix-spam-filter/), [andra e-postservrar](../../docs/mail-servers.md) och [HTTP-API:t](../../docs/http-api.md).


## Håll språkmodellerna lokala

En språkmodell är valfri och läser bara gränsfall: tydlig spam och tydlig ham når den aldrig. Med Ollama körs den på samma server, så inget meddelande lämnar den:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` körs på en CPU. Med en hostad leverantör tas personuppgifter bort ur meddelandet innan det skickas. [Språkmodeller](../../docs/llm.md)


## Träna det på din egen e-post

Den medföljande modellen är tränad på offentliga dataset. En modell som tränats på den e-post din server tar emot fungerar bättre, och den stannar på servern:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

En modellfil innehåller hashade antal av egenskaper, inte ord eller meddelandetext. [Träning](../../docs/training.md)


## Krav

Node.js 18 eller senare på Linux, macOS eller Windows, eller ingenting med en fristående binärfil. ClamAV och Ollama är valfria och körs som egna tjänster.
