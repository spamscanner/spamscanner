<!-- source: a59bc5927d86 -->

# Opdrachtregel

```text
spamscanner <command> [options]
```

| Opdracht                                   | Wat het doet                                                                         |
| ------------------------------------------ | ------------------------------------------------------------------------------------ |
| `scan [file\|-]`                           | Scant een bericht uit een bestand of van standaardinvoer                             |
| `filter -f <sender> -- <recipients...>`    | Contentfilter voor Postfix: scant standaardinvoer, voegt headers toe, geeft het door |
| `milter`                                   | Milter voor Postfix en Sendmail, poort 7831                                          |
| `http`                                     | HTTP API, poort 7832                                                                 |
| `server`                                   | Eenvoudige TCP-server, poort 7830                                                    |
| `spamd`                                    | Met SpamAssassin compatibele spamd-server, poort 783                                 |
| `train`                                    | Traint een model met mbox-bestanden, Maildirs, mappen of datasets                    |
| `eval`                                     | Meet een model op gelabelde mail                                                     |
| `learn spam\|ham [file\|-] --model <file>` | Leert een model één bericht                                                          |
| `llm-test`                                 | Controleert de instellingen van het taalmodel met drie voorbeeldberichten            |
| `models`                                   | Toont aanbevolen open modellen                                                       |
| `version`, `help`                          |                                                                                      |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Optie                      | Betekenis                                                     |
| -------------------------- | ------------------------------------------------------------- |
| `--json`                   | Toont het volledige resultaat als JSON                        |
| `--headers`                | Toont het bericht met toegevoegde `X-Spam-*`-headers          |
| `--subject-tag <tag>`      | Zet ook een voorvoegsel voor het onderwerp van spam           |
| `--verbose`                | Toont elke test en de sterkste aanwijzingen van de classifier |
| `--threshold <n>`          | Score waarbij mail spam is (standaard 5)                      |
| `--reject-threshold <n>`   | Score waarbij mail wordt geweigerd (standaard 15)             |
| `--model <file>`           | Een modelbestand in plaats van het meegeleverde model         |
| `--no-classifier`          | Gebruikt de classifier niet                                   |
| `--config <file>`          | Een JSON-bestand met [bibliotheekopties](api.md#options)      |
| `--allow-language <codes>` | Geaccepteerde talen, bijvoorbeeld `en,de,fr`                  |

Exitcodes: 0 ham, 1 spam, 2 fout.

### SMTP-sessie

| Optie               | Betekenis                                         |
| ------------------- | ------------------------------------------------- |
| `--ip <address>`    | IP-adres van de client die het bericht verstuurde |
| `--hostname <name>` | De geverifieerde reverse-DNS-naam van de client   |
| `--helo <name>`     | De naam die de client in HELO of EHLO opgaf       |
| `--from <address>`  | Envelope-afzender (MAIL FROM)                     |
| `--to <address>`    | Envelope-ontvanger; herhaal voor meerdere         |

### Controles

| Optie                 | Betekenis                                                                |
| --------------------- | ------------------------------------------------------------------------ |
| `--auth`              | Controleert SPF, DKIM, DMARC en ARC (vereist `--ip`)                     |
| `--dnsbl <zone>`      | IP-blocklist, bijvoorbeeld `zen.spamhaus.org`; herhaalbaar               |
| `--uribl <zone>`      | Domeinblocklist voor links, bijvoorbeeld `dbl.spamhaus.org`; herhaalbaar |
| `--dns-server <ip>`   | Nameserver voor DNS-controles; herhaalbaar                               |
| `--no-cloudflare`     | Vraagt de filterende resolvers van Cloudflare niet naar links            |
| `--clamav [socket]`   | Scant bijlagen met clamd, op de standaardsocket of de opgegeven socket   |
| `--allowlist <value>` | Accepteert dit IP-adres, domein of adres altijd; herhaalbaar             |
| `--denylist <value>`  | Weigert dit IP-adres, domein of adres altijd; herhaalbaar                |

### Taalmodel

| Optie                                                      | Betekenis                                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` en andere ([lijst](llm.md#providers)) |
| `--llm-model <name>`                                       | Model, bijvoorbeeld `qwen3.5:4b` of `claude-haiku-4-5`                          |
| `--llm-url <url>`                                          | Basis-URL, bijvoorbeeld `http://10.0.0.5:11434`                                 |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Wijzigt één deel van de URL van de aanbieder                                    |
| `--llm-api-key <key>`                                      | API-sleutel; zie ook de omgevingsvariabelen hieronder                           |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` of `none`                   |
| `--llm-auth-header <name>`                                 | Header voor de sleutel, met `--llm-auth header`                                 |
| `--llm-username`, `--llm-password`                         | Voor `--llm-auth basic`                                                         |
| `--llm-header "Name: value"`                               | Extra request-header; herhaalbaar                                               |
| `--llm-mode <mode>`                                        | `auto` (alleen twijfelgevallen, de standaard) of `always`                       |
| `--llm-timeout <ms>`                                       | Standaard 30000                                                                 |
| `--llm-policy <text>`                                      | Extra regels voor het model, bijvoorbeeld „We never send invoices”              |
| `--llm-redact`, `--no-llm-redact`                          | Verwijdert eerst persoonsgegevens; standaard aan bij externe aanbieders         |


## filter

Een [contentfilter voor Postfix](postfix.md#content-filter). Het leest een bericht van standaardinvoer, voegt `X-Spam-*`-headers toe en geeft het met dezelfde envelope door aan sendmail.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Optie                 | Betekenis                                                             |
| --------------------- | --------------------------------------------------------------------- |
| `--sendmail <path>`   | Standaard `/usr/sbin/sendmail`                                        |
| `--subject-tag <tag>` | Zet een voorvoegsel voor het onderwerp van spam                       |
| `--reject`            | Stuurt mail op de weigerdrempel terug in plaats van hem door te geven |
| `--discard`           | Gooit mail op de weigerdrempel weg in plaats van hem door te geven    |

Exitcodes volgen de conventies van sendmail, die Postfix leest: 0 bezorgd (of weggegooid), 64 geen ontvangers opgegeven, 69 geweigerd als spam (Postfix stuurt het terug), 75 elke andere fout, zodat Postfix het bericht vasthoudt en het later opnieuw probeert.


## milter, http, server en spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Poort 783 is de poort die SpamAssassin-clients standaard gebruiken. Poorten onder 1024 vereisen root of de capability `CAP_NET_BIND_SERVICE`; gebruik een andere poort, zoals `--port 7833`, en geef die aan de client door.

| Optie                 | Betekenis                                                           |
| --------------------- | ------------------------------------------------------------------- |
| `--port <n>`          | TCP-poort                                                           |
| `--host <ip>`         | Adres waarop wordt geluisterd (standaard 127.0.0.1)                 |
| `--socket <path>`     | Luistert in plaats daarvan op een Unix-socket                       |
| `--reject`            | Milter: weigert mail op de weigerdrempel                            |
| `--reject-code <n>`   | Milter: 451, later opnieuw proberen (de standaard), of 550          |
| `--quarantine`        | Milter: houdt spam vast in de quarantaine van de mailserver         |
| `--name <hostname>`   | Milter: de naam van deze server in Authentication-Results           |
| `--token <secret>`    | HTTP: vereist `Authorization: Bearer <secret>`; nodig voor `/learn` |
| `--allow-tell`        | spamd: accepteert TELL-verzoeken (`spamc -L spam`) om te leren      |
| `--out <file>`        | HTTP en spamd: slaat het geleerde op in dit modelbestand            |
| `--subject-tag <tag>` | Milter en spamd: zet een voorvoegsel voor het onderwerp van spam    |
| `--verbose`           | Milter: logt elke scan. TCP-server: antwoordt met één regel tekst   |

De scanopties hierboven gelden ook voor de servers. [De milter](postfix.md#milter), [de HTTP API, de TCP-server en spamd](http-api.md).


## train, eval en learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Optie                                           | Betekenis                                                                        |
| ----------------------------------------------- | -------------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: een mbox-bestand, een Maildir of een map met `.eml`-bestanden; herhaalbaar |
| `--ham <path>`                                  | Ham, idem; herhaalbaar                                                           |
| `--dataset <file>`                              | Een CSV- of JSON Lines-bestand met tekst- en labelkolommen; herhaalbaar          |
| `--text-column <name>`, `--label-column <name>` | Kolomnamen, als ze niet worden herkend                                           |
| `--out <file>`                                  | Waar het model wordt geschreven (standaard `spamscanner-model.json`)             |
| `--merge`                                       | Begint vanaf het meegeleverde model (of `--model`) in plaats van een leeg model  |

`learn` werkt het modelbestand ter plekke bij en maakt het de eerste keer aan vanuit het meegeleverde model. [Training](training.md)


## llm-test en models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` stuurt één gewoon bericht en twee oplichtingsberichten, in het Engels en Italiaans, naar het model, toont de oordelen en eindigt alleen met 0 als alle drie kloppen.


## Configuratiebestand

`--config file.json` (of de omgevingsvariabele `SPAMSCANNER_CONFIG`) laadt [bibliotheekopties](api.md#options). Opties op de opdrachtregel gaan voor het bestand.

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


## Omgevingsvariabelen

| Variabele                                                                                                                                                                                                                                            | Betekenis                                                      |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | Configuratiebestand                                            |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | Modelbestand dat in plaats van het meegeleverde wordt gebruikt |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | Token voor de HTTP API                                         |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | API-sleutel voor elke aanbieder van taalmodellen               |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | De eigen sleutel van elke aanbieder                            |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | Debuglogging                                                   |
