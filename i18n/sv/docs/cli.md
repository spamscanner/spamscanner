<!-- source: c061da9312ad -->

# Kommandorad

```text
spamscanner <command> [options]
```

| Kommando                                   | Vad det gör                                                                           |
| ------------------------------------------ | ------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Skannar ett meddelande från en fil eller standard in                                  |
| `filter -f <sender> -- <recipients...>`    | Innehållsfilter för Postfix: skannar standard in, lägger till huvuden, skickar vidare |
| `milter`                                   | Milter för Postfix och Sendmail, port 7831                                            |
| `http`                                     | HTTP-API, port 7832                                                                   |
| `server`                                   | Enkel TCP-server, port 7830                                                           |
| `spamd`                                    | SpamAssassin-kompatibel spamd-server, port 783                                        |
| `train`                                    | Tränar en modell från mbox-filer, Maildir-kataloger, mappar eller dataset             |
| `eval`                                     | Mäter en modell på märkt e-post                                                       |
| `learn spam\|ham [file\|-] --model <file>` | Lär en modell ett meddelande                                                          |
| `llm-test`                                 | Kontrollerar inställningarna för språkmodellen med tre exempelmeddelanden             |
| `models`                                   | Listar rekommenderade öppna modeller                                                  |
| `version`, `help`                          |                                                                                       |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Alternativ                 | Betydelse                                                 |
| -------------------------- | --------------------------------------------------------- |
| `--json`                   | Skriv ut hela resultatet som JSON                         |
| `--headers`                | Skriv ut meddelandet med `X-Spam-*`-huvuden tillagda      |
| `--subject-tag <tag>`      | Lägg även till ett prefix i ämnesraden på spam            |
| `--verbose`                | Visa alla tester och klassificerarens starkaste ledtrådar |
| `--threshold <n>`          | Poäng där e-post är spam (standard 5)                     |
| `--reject-threshold <n>`   | Poäng där e-post avvisas (standard 15)                    |
| `--model <file>`           | En modellfil i stället för den medföljande                |
| `--no-classifier`          | Använd inte klassificeraren                               |
| `--config <file>`          | En JSON-fil med [bibliotekets alternativ](api.md#options) |
| `--allow-language <codes>` | Accepterade språk, till exempel `en,de,fr`                |

Slutkoder: 0 ham, 1 spam, 2 fel.

### SMTP-session

| Alternativ          | Betydelse                                         |
| ------------------- | ------------------------------------------------- |
| `--ip <address>`    | IP-adressen för klienten som skickade meddelandet |
| `--hostname <name>` | Klientens verifierade namn i omvänd DNS           |
| `--helo <name>`     | Namnet som den angav i HELO eller EHLO            |
| `--from <address>`  | Kuvertets avsändare (MAIL FROM)                   |
| `--to <address>`    | Kuvertets mottagare; upprepa för flera            |

### Kontroller

| Alternativ            | Betydelse                                                                 |
| --------------------- | ------------------------------------------------------------------------- |
| `--auth`              | Kontrollera SPF, DKIM, DMARC och ARC (kräver `--ip`)                      |
| `--dnsbl <zone>`      | IP-blocklista, till exempel `zen.spamhaus.org`; kan upprepas              |
| `--uribl <zone>`      | Domänblocklista för länkar, till exempel `dbl.spamhaus.org`; kan upprepas |
| `--dns-server <ip>`   | Namnserver för DNS-kontroller; kan upprepas                               |
| `--no-cloudflare`     | Fråga inte Cloudflares filtrerande resolvrar om länkar                    |
| `--clamav [socket]`   | Skanna bilagor med clamd, på dess standardsocket eller den angivna        |
| `--allowlist <value>` | Acceptera alltid denna IP-adress, domän eller adress; kan upprepas        |
| `--denylist <value>`  | Avvisa alltid denna IP-adress, domän eller adress; kan upprepas           |

### Språkmodell

| Alternativ                                                 | Betydelse                                                                                                                                    |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` med flera ([lista](llm.md#providers))                                                   |
| `--llm-model <name>`                                       | Modell, till exempel `qwen3.5:4b` eller `claude-haiku-4-5`                                                                                   |
| `--llm-method <method>`                                    | `decision` (en sannolikhet för varje utslag, i ett steg; standard där det finns) eller `generate` ([metoder](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | Cloudflare-konto-ID, för `clef` och `clef-flash`                                                                                             |
| `--llm-url <url>`                                          | Bas-URL, till exempel `http://10.0.0.5:11434`                                                                                                |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Ändra en del av leverantörens URL                                                                                                            |
| `--llm-api-key <key>`                                      | API-nyckel; se även miljövariablerna nedan                                                                                                   |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` eller `none`                                                                             |
| `--llm-auth-header <name>`                                 | Huvud för nyckeln, med `--llm-auth header`                                                                                                   |
| `--llm-username`, `--llm-password`                         | För `--llm-auth basic`                                                                                                                       |
| `--llm-header "Name: value"`                               | Extra huvud i förfrågan; kan upprepas                                                                                                        |
| `--llm-mode <mode>`                                        | `auto` (bara gränsfall, standard) eller `always`                                                                                             |
| `--llm-timeout <ms>`                                       | Standard 30000                                                                                                                               |
| `--llm-policy <text>`                                      | Extra regler för modellen, till exempel ”Vi skickar aldrig fakturor”                                                                         |
| `--llm-redact`, `--no-llm-redact`                          | Ta bort personuppgifter först; påslaget som standard för externa leverantörer                                                                |


## filter

Ett [innehållsfilter för Postfix](postfix.md#content-filter). Det läser ett meddelande från standard in, lägger till `X-Spam-*`-huvuden och skickar det till sendmail med samma kuvert.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Alternativ            | Betydelse                                                                   |
| --------------------- | --------------------------------------------------------------------------- |
| `--sendmail <path>`   | Standard `/usr/sbin/sendmail`                                               |
| `--subject-tag <tag>` | Lägg till ett prefix i ämnesraden på spam                                   |
| `--reject`            | Studsa e-post som når gränsen för avvisning i stället för att skicka vidare |
| `--discard`           | Släng e-post som når gränsen för avvisning i stället för att skicka vidare  |

Slutkoderna följer sendmails konventioner, som Postfix läser: 0 levererat (eller slängt), 64 inga mottagare angivna, 69 avvisat som spam (Postfix studsar det), 75 alla fel, så att Postfix behåller meddelandet och försöker igen senare.


## milter, http, server och spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Port 783 är den port som SpamAssassin-klienter använder som standard. Portar under 1024 kräver root eller förmågan `CAP_NET_BIND_SERVICE`; använd en annan port, till exempel `--port 7833`, och ange den för klienten.

| Alternativ            | Betydelse                                                           |
| --------------------- | ------------------------------------------------------------------- |
| `--port <n>`          | TCP-port                                                            |
| `--host <ip>`         | Adress att lyssna på (standard 127.0.0.1)                           |
| `--socket <path>`     | Lyssna i stället på en Unix-socket                                  |
| `--reject`            | Milter: neka e-post som når gränsen för avvisning                   |
| `--reject-code <n>`   | Milter: 451, försök igen senare (standard), eller 550               |
| `--quarantine`        | Milter: håll kvar spam i e-postserverns karantän                    |
| `--name <hostname>`   | Milter: den här serverns namn i Authentication-Results              |
| `--token <secret>`    | HTTP: kräv `Authorization: Bearer <secret>`; krävs för `/learn`     |
| `--allow-tell`        | spamd: acceptera TELL-förfrågningar (`spamc -L spam`) för inlärning |
| `--out <file>`        | HTTP och spamd: spara det som lärs in till den här modellfilen      |
| `--subject-tag <tag>` | Milter och spamd: lägg till ett prefix i ämnesraden på spam         |
| `--verbose`           | Milter: logga varje skanning. TCP-server: svara med en textrad      |

Skanningsalternativen ovan gäller även för servrarna. [Miltern](postfix.md#milter), [HTTP-API:t, TCP-servern och spamd](http-api.md).


## train, eval och learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Alternativ                                      | Betydelse                                                                  |
| ----------------------------------------------- | -------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: en mbox-fil, en Maildir eller en mapp med `.eml`-filer; kan upprepas |
| `--ham <path>`                                  | Ham, på samma sätt; kan upprepas                                           |
| `--dataset <file>`                              | En CSV- eller JSON Lines-fil med text- och etikettkolumner; kan upprepas   |
| `--text-column <name>`, `--label-column <name>` | Kolumnnamn, när de inte identifieras automatiskt                           |
| `--out <file>`                                  | Var modellen ska skrivas (standard `spamscanner-model.json`)               |
| `--merge`                                       | Börja från den medföljande modellen (eller `--model`) i stället för en tom |

`learn` uppdaterar modellfilen på plats och skapar den från den medföljande modellen första gången. [Träning](training.md)


## llm-test och models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` skickar ett vanligt meddelande och två bedrägerier, på engelska och italienska, till modellen, skriver ut dess utslag, tiden varje tog, metoden som användes och hårdvaran, och avslutas med 0 bara om alla tre är rätt.


## Konfigurationsfil

`--config file.json` (eller miljövariabeln `SPAMSCANNER_CONFIG`) läser in [bibliotekets alternativ](api.md#options). Alternativ på kommandoraden har företräde framför filen.

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


## Miljövariabler

| Variabel                                                                                                                                                                                                                                                                                                                     | Betydelse                                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                         | Konfigurationsfil                                   |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                          | Modellfil som används i stället för den medföljande |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                          | Token för HTTP-API:t                                |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                    | API-nyckel för alla leverantörer av språkmodeller   |
| `CLOUDFLARE_API_TOKEN` och `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Varje leverantörs egen nyckel                       |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                    | Felsökningsloggning                                 |
