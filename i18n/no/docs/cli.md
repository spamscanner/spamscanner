<!-- source: c061da9312ad -->

# Kommandolinje

```text
spamscanner <command> [options]
```

| Kommando                                   | Hva den gjør                                                                          |
| ------------------------------------------ | ------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Skanner en melding fra en fil eller standard inndata                                  |
| `filter -f <sender> -- <recipients...>`    | Innholdsfilter for Postfix: skanner standard inndata, legger til hoder, sender videre |
| `milter`                                   | Milter for Postfix og Sendmail, port 7831                                             |
| `http`                                     | HTTP API, port 7832                                                                   |
| `server`                                   | Enkel TCP-server, port 7830                                                           |
| `spamd`                                    | SpamAssassin-kompatibel spamd-server, port 783                                        |
| `train`                                    | Trener en modell fra mbox-filer, Maildir-mapper, mapper eller datasett                |
| `eval`                                     | Måler en modell på merket e-post                                                      |
| `learn spam\|ham [file\|-] --model <file>` | Lærer en modell opp på én melding                                                     |
| `llm-test`                                 | Sjekker innstillingene for språkmodellen med tre eksempelmeldinger                    |
| `models`                                   | Lister opp anbefalte åpne modeller                                                    |
| `version`, `help`                          |                                                                                       |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Alternativ                 | Betydning                                               |
| -------------------------- | ------------------------------------------------------- |
| `--json`                   | Skriv ut hele resultatet som JSON                       |
| `--headers`                | Skriv ut meldingen med `X-Spam-*`-hoder lagt til        |
| `--subject-tag <tag>`      | Sett i tillegg et prefiks foran emnet på spam           |
| `--verbose`                | Vis alle tester og klassifisererens sterkeste indisier  |
| `--threshold <n>`          | Poengsum der e-post er spam (standard 5)                |
| `--reject-threshold <n>`   | Poengsum der e-post avvises (standard 15)               |
| `--model <file>`           | En modellfil i stedet for den medfølgende               |
| `--no-classifier`          | Ikke bruk klassifisereren                               |
| `--config <file>`          | En JSON-fil med [bibliotekalternativer](api.md#options) |
| `--allow-language <codes>` | Godtatte språk, for eksempel `en,de,fr`                 |

Avslutningskoder: 0 ham, 1 spam, 2 feil.

### SMTP-økt

| Alternativ          | Betydning                                     |
| ------------------- | --------------------------------------------- |
| `--ip <address>`    | IP-adressen til klienten som sendte meldingen |
| `--hostname <name>` | Klientens verifiserte navn fra omvendt DNS    |
| `--helo <name>`     | Navnet den oppga i HELO eller EHLO            |
| `--from <address>`  | Konvoluttavsender (MAIL FROM)                 |
| `--to <address>`    | Konvoluttmottaker; gjenta for flere           |

### Sjekker

| Alternativ            | Betydning                                                                       |
| --------------------- | ------------------------------------------------------------------------------- |
| `--auth`              | Sjekk SPF, DKIM, DMARC og ARC (krever `--ip`)                                   |
| `--dnsbl <zone>`      | IP-blokkeringsliste, for eksempel `zen.spamhaus.org`; kan gjentas               |
| `--uribl <zone>`      | Domeneblokkeringsliste for lenker, for eksempel `dbl.spamhaus.org`; kan gjentas |
| `--dns-server <ip>`   | Navneserver for DNS-sjekker; kan gjentas                                        |
| `--no-cloudflare`     | Ikke spør Cloudflares filtrerende resolvere om lenker                           |
| `--clamav [socket]`   | Skann vedlegg med clamd, på standard-socketen eller den som oppgis              |
| `--allowlist <value>` | Godta alltid denne IP-adressen, dette domenet eller denne adressen; kan gjentas |
| `--denylist <value>`  | Avvis alltid denne IP-adressen, dette domenet eller denne adressen; kan gjentas |

### Språkmodell

| Alternativ                                                 | Betydning                                                                                                                                                  |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` og andre ([liste](llm.md#providers))                                                                  |
| `--llm-model <name>`                                       | Modell, for eksempel `qwen3.5:4b` eller `claude-haiku-4-5`                                                                                                 |
| `--llm-method <method>`                                    | `decision` (en sannsynlighet for hver vurdering, i ett steg; standard der det er tilgjengelig) eller `generate` ([metoder](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | Cloudflare-konto-ID, for `clef` og `clef-flash`                                                                                                            |
| `--llm-url <url>`                                          | Basis-URL, for eksempel `http://10.0.0.5:11434`                                                                                                            |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Endre én del av leverandørens URL                                                                                                                          |
| `--llm-api-key <key>`                                      | API-nøkkel; se også miljøvariablene nedenfor                                                                                                               |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` eller `none`                                                                                           |
| `--llm-auth-header <name>`                                 | Hode for nøkkelen, med `--llm-auth header`                                                                                                                 |
| `--llm-username`, `--llm-password`                         | For `--llm-auth basic`                                                                                                                                     |
| `--llm-header "Name: value"`                               | Ekstra hode i forespørselen; kan gjentas                                                                                                                   |
| `--llm-mode <mode>`                                        | `auto` (bare vanskelige tilfeller, standard) eller `always`                                                                                                |
| `--llm-timeout <ms>`                                       | Standard 30000                                                                                                                                             |
| `--llm-policy <text>`                                      | Ekstra regler for modellen, for eksempel «Vi sender aldri fakturaer»                                                                                       |
| `--llm-redact`, `--no-llm-redact`                          | Fjern personopplysninger først; på som standard for eksterne leverandører                                                                                  |


## filter

Et [innholdsfilter for Postfix](postfix.md#content-filter). Det leser en melding fra standard inndata, legger til `X-Spam-*`-hoder og sender den til sendmail med den samme konvolutten.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Alternativ            | Betydning                                                               |
| --------------------- | ----------------------------------------------------------------------- |
| `--sendmail <path>`   | Standard `/usr/sbin/sendmail`                                           |
| `--subject-tag <tag>` | Sett et prefiks foran emnet på spam                                     |
| `--reject`            | Returner e-post ved avvisningsterskelen i stedet for å sende den videre |
| `--discard`           | Forkast e-post ved avvisningsterskelen i stedet for å sende den videre  |

Avslutningskodene følger konvensjonene til sendmail, som Postfix leser: 0 levert (eller forkastet), 64 ingen mottakere oppgitt, 69 avvist som spam (Postfix returnerer den), 75 enhver feil, slik at Postfix beholder meldingen og prøver igjen senere.


## milter, http, server og spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Port 783 er porten SpamAssassin-klienter bruker som standard. Porter under 1024 krever root eller egenskapen `CAP_NET_BIND_SERVICE`; bruk en annen port, for eksempel `--port 7833`, og oppgi den til klienten.

| Alternativ            | Betydning                                                           |
| --------------------- | ------------------------------------------------------------------- |
| `--port <n>`          | TCP-port                                                            |
| `--host <ip>`         | Adressen det skal lyttes på (standard 127.0.0.1)                    |
| `--socket <path>`     | Lytt på en Unix-socket i stedet                                     |
| `--reject`            | Milter: avvis e-post ved avvisningsterskelen                        |
| `--reject-code <n>`   | Milter: 451, prøv igjen senere (standard), eller 550                |
| `--quarantine`        | Milter: hold spam tilbake i e-postserverens karantene               |
| `--name <hostname>`   | Milter: navnet på denne serveren i Authentication-Results           |
| `--token <secret>`    | HTTP: krev `Authorization: Bearer <secret>`; nødvendig for `/learn` |
| `--allow-tell`        | spamd: godta TELL-forespørsler (`spamc -L spam`) for å lære         |
| `--out <file>`        | HTTP og spamd: lagre det som læres, i denne modellfilen             |
| `--subject-tag <tag>` | Milter og spamd: sett et prefiks foran emnet på spam                |
| `--verbose`           | Milter: logg hver skanning. TCP-server: svar med én tekstlinje      |

Skannealternativene ovenfor gjelder også for serverne. [Milteren](postfix.md#milter), [HTTP API-et, TCP-serveren og spamd](http-api.md).


## train, eval og learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Alternativ                                      | Betydning                                                                       |
| ----------------------------------------------- | ------------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: en mbox-fil, en Maildir eller en mappe med `.eml`-filer; kan gjentas      |
| `--ham <path>`                                  | Ham, på samme måte; kan gjentas                                                 |
| `--dataset <file>`                              | En CSV- eller JSON Lines-fil med kolonner for tekst og etikett; kan gjentas     |
| `--text-column <name>`, `--label-column <name>` | Kolonnenavn, når de ikke oppdages automatisk                                    |
| `--out <file>`                                  | Hvor modellen skal skrives (standard `spamscanner-model.json`)                  |
| `--merge`                                       | Start fra den medfølgende modellen (eller `--model`) i stedet for en tom modell |

`learn` oppdaterer modellfilen på stedet og oppretter den fra den medfølgende modellen første gang. [Trening](training.md)


## llm-test og models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` sender én vanlig melding og to svindelforsøk, på engelsk og italiensk, til modellen, skriver ut vurderingene, tiden hver av dem tok, metoden som ble brukt og maskinvaren, og avslutter med 0 bare hvis alle tre er riktige.


## Konfigurasjonsfil

`--config file.json` (eller miljøvariabelen `SPAMSCANNER_CONFIG`) laster inn [bibliotekalternativer](api.md#options). Alternativer på kommandolinjen overstyrer filen.

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
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                        | Konfigurasjonsfil                                 |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                         | Modellfil som brukes i stedet for den medfølgende |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                         | Token for HTTP API-et                             |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                   | API-nøkkel for enhver leverandør av språkmodeller |
| `CLOUDFLARE_API_TOKEN` og `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Hver leverandørs egen nøkkel                      |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                   | Feilsøkingslogging                                |
