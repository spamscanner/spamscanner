<!-- source: c061da9312ad -->

# Kommandolinje

```text
spamscanner <command> [options]
```

| Kommando                                   | Hvad den gør                                                                |
| ------------------------------------------ | --------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Scan en besked fra en fil eller standardinput                               |
| `filter -f <sender> -- <recipients...>`    | Postfix-indholdsfilter: scan standardinput, tilføj headere, send den videre |
| `milter`                                   | Milter til Postfix og Sendmail, port 7831                                   |
| `http`                                     | HTTP API, port 7832                                                         |
| `server`                                   | Almindelig TCP-server, port 7830                                            |
| `spamd`                                    | SpamAssassin-kompatibel spamd-server, port 783                              |
| `train`                                    | Træn en model fra mbox-filer, Maildirs, mapper eller datasæt                |
| `eval`                                     | Mål en model på mærket post                                                 |
| `learn spam\|ham [file\|-] --model <file>` | Lær en model én besked                                                      |
| `llm-test`                                 | Tjek indstillingerne for sprogmodellen med tre eksempelbeskeder             |
| `models`                                   | Vis anbefalede åbne modeller                                                |
| `version`, `help`                          |                                                                             |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Indstilling                | Betydning                                                 |
| -------------------------- | --------------------------------------------------------- |
| `--json`                   | Udskriv hele resultatet som JSON                          |
| `--headers`                | Udskriv beskeden med `X-Spam-*`-headere tilføjet          |
| `--subject-tag <tag>`      | Sæt også et præfiks foran emnet på spam                   |
| `--verbose`                | Vis alle test og klassifikatorens stærkeste spor          |
| `--threshold <n>`          | Score, hvor post er spam (standard 5)                     |
| `--reject-threshold <n>`   | Score, hvor post afvises (standard 15)                    |
| `--model <file>`           | En modelfil i stedet for den medfølgende                  |
| `--no-classifier`          | Brug ikke klassifikatoren                                 |
| `--config <file>`          | En JSON-fil med [biblioteksindstillinger](api.md#options) |
| `--allow-language <codes>` | Accepterede sprog, for eksempel `en,de,fr`                |

Afslutningskoder: 0 ham, 1 spam, 2 fejl.

### SMTP-session

| Indstilling         | Betydning                                      |
| ------------------- | ---------------------------------------------- |
| `--ip <address>`    | IP-adressen på den klient, der sendte beskeden |
| `--hostname <name>` | Klientens verificerede reverse DNS-navn        |
| `--helo <name>`     | Det navn, den angav i HELO eller EHLO          |
| `--from <address>`  | Afsender i konvolutten (MAIL FROM)             |
| `--to <address>`    | Modtager i konvolutten; gentag for flere       |

### Tjek

| Indstilling           | Betydning                                                                       |
| --------------------- | ------------------------------------------------------------------------------- |
| `--auth`              | Tjek SPF, DKIM, DMARC og ARC (kræver `--ip`)                                    |
| `--dnsbl <zone>`      | IP-blokeringsliste, for eksempel `zen.spamhaus.org`; kan gentages               |
| `--uribl <zone>`      | Domæneblokeringsliste for links, for eksempel `dbl.spamhaus.org`; kan gentages  |
| `--dns-server <ip>`   | Navneserver til DNS-tjek; kan gentages                                          |
| `--no-cloudflare`     | Spørg ikke Cloudflares filtrerende resolvere om links                           |
| `--clamav [socket]`   | Scan vedhæftede filer med clamd, på dens standardsocket eller den angivne       |
| `--allowlist <value>` | Acceptér altid denne IP-adresse, dette domæne eller denne adresse; kan gentages |
| `--denylist <value>`  | Afvis altid denne IP-adresse, dette domæne eller denne adresse; kan gentages    |

### Sprogmodel

| Indstilling                                                | Betydning                                                                                                                                      |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` og andre ([liste](llm.md#providers))                                                      |
| `--llm-model <name>`                                       | Model, for eksempel `qwen3.5:4b` eller `claude-haiku-4-5`                                                                                      |
| `--llm-method <method>`                                    | `decision` (en sandsynlighed for hver dom i ét trin; standard, hvor det er muligt) eller `generate` ([metoder](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | Cloudflare-konto-ID til `clef` og `clef-flash`                                                                                                 |
| `--llm-url <url>`                                          | Basis-URL, for eksempel `http://10.0.0.5:11434`                                                                                                |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Ændr én del af udbyderens URL                                                                                                                  |
| `--llm-api-key <key>`                                      | API-nøgle; se også miljøvariablerne nedenfor                                                                                                   |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` eller `none`                                                                               |
| `--llm-auth-header <name>`                                 | Header til nøglen, med `--llm-auth header`                                                                                                     |
| `--llm-username`, `--llm-password`                         | Til `--llm-auth basic`                                                                                                                         |
| `--llm-header "Name: value"`                               | Ekstra header i forespørgslen; kan gentages                                                                                                    |
| `--llm-mode <mode>`                                        | `auto` (kun tvivlstilfælde, standard) eller `always`                                                                                           |
| `--llm-timeout <ms>`                                       | Standard 30000                                                                                                                                 |
| `--llm-policy <text>`                                      | Ekstra regler for modellen, for eksempel »Vi sender aldrig fakturaer«                                                                          |
| `--llm-redact`, `--no-llm-redact`                          | Fjern personoplysninger først; slået til som standard for eksterne udbydere                                                                    |


## filter

Et [Postfix-indholdsfilter](postfix.md#content-filter). Det læser en besked fra standardinput, tilføjer `X-Spam-*`-headere og sender den videre til sendmail med samme konvolut.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Indstilling           | Betydning                                                              |
| --------------------- | ---------------------------------------------------------------------- |
| `--sendmail <path>`   | Standard `/usr/sbin/sendmail`                                          |
| `--subject-tag <tag>` | Sæt et præfiks foran emnet på spam                                     |
| `--reject`            | Send post ved afvisningsgrænsen retur i stedet for at sende den videre |
| `--discard`           | Kassér post ved afvisningsgrænsen i stedet for at sende den videre     |

Afslutningskoderne følger sendmails konventioner, som Postfix læser: 0 leveret (eller kasseret), 64 ingen modtagere angivet, 69 afvist som spam (Postfix sender den retur), 75 enhver fejl, så Postfix beholder beskeden og prøver igen senere.


## milter, http, server og spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Port 783 er den port, SpamAssassin-klienter bruger som standard. Porte under 1024 kræver root eller kapabiliteten `CAP_NET_BIND_SERVICE`; brug en anden port, for eksempel `--port 7833`, og fortæl klienten det.

| Indstilling           | Betydning                                                            |
| --------------------- | -------------------------------------------------------------------- |
| `--port <n>`          | TCP-port                                                             |
| `--host <ip>`         | Adresse, der lyttes på (standard 127.0.0.1)                          |
| `--socket <path>`     | Lyt i stedet på en Unix-socket                                       |
| `--reject`            | Milter: afvis post ved afvisningsgrænsen                             |
| `--reject-code <n>`   | Milter: 451, prøv igen senere (standard), eller 550                  |
| `--quarantine`        | Milter: hold spam tilbage i mailserverens karantæne                  |
| `--name <hostname>`   | Milter: denne servers navn i Authentication-Results                  |
| `--token <secret>`    | HTTP: kræv `Authorization: Bearer <secret>`; nødvendigt for `/learn` |
| `--allow-tell`        | spamd: acceptér TELL-forespørgsler (`spamc -L spam`) til indlæring   |
| `--out <file>`        | HTTP og spamd: gem det indlærte i denne modelfil                     |
| `--subject-tag <tag>` | Milter og spamd: sæt et præfiks foran emnet på spam                  |
| `--verbose`           | Milter: log hver scanning. TCP-server: svar med én tekstlinje        |

Scanningsindstillingerne ovenfor gælder også for serverne. [Milteren](postfix.md#milter), [HTTP API'et, TCP-serveren og spamd](http-api.md).


## train, eval og learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Indstilling                                     | Betydning                                                                   |
| ----------------------------------------------- | --------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: en mbox-fil, en Maildir eller en mappe med `.eml`-filer; kan gentages |
| `--ham <path>`                                  | Ham, på samme måde; kan gentages                                            |
| `--dataset <file>`                              | En CSV- eller JSON Lines-fil med kolonner til tekst og etiket; kan gentages |
| `--text-column <name>`, `--label-column <name>` | Kolonnenavne, når de ikke genkendes automatisk                              |
| `--out <file>`                                  | Hvor modellen skrives (standard `spamscanner-model.json`)                   |
| `--merge`                                       | Start fra den medfølgende model (eller `--model`) i stedet for en tom model |

`learn` opdaterer modelfilen på stedet og opretter den ud fra den medfølgende model første gang. [Træning](training.md)


## llm-test og models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` sender én almindelig besked og to svindelbeskeder, på engelsk og italiensk, til modellen, udskriver dens domme, den tid hver tog, den anvendte metode og hardwaren og afslutter kun med 0, hvis alle tre er rigtige.


## Konfigurationsfil

`--config file.json` (eller miljøvariablen `SPAMSCANNER_CONFIG`) indlæser [biblioteksindstillinger](api.md#options). Indstillinger på kommandolinjen tilsidesætter filen.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Miljøvariabler

| Variabel                                                                                                                                                                                                                                                                                                                    | Betydning                                         |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                        | Konfigurationsfil                                 |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                         | Modelfil, der bruges i stedet for den medfølgende |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                         | Token til HTTP API'et                             |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                   | API-nøgle til enhver udbyder af sprogmodeller     |
| `CLOUDFLARE_API_TOKEN` og `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Hver udbyders egen nøgle                          |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                   | Fejlsøgningslogning                               |
