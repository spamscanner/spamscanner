<!-- source: c061da9312ad -->

# Příkazová řádka

```text
spamscanner <command> [options]
```

| Příkaz                                     | Co dělá                                                                                     |
| ------------------------------------------ | ------------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Zkontroluje zprávu ze souboru nebo ze standardního vstupu                                   |
| `filter -f <sender> -- <recipients...>`    | Obsahový filtr pro Postfix: zkontroluje standardní vstup, přidá hlavičky a předá zprávu dál |
| `milter`                                   | Milter pro Postfix a Sendmail, port 7831                                                    |
| `http`                                     | HTTP API, port 7832                                                                         |
| `server`                                   | Prostý TCP server, port 7830                                                                |
| `spamd`                                    | Server spamd kompatibilní se SpamAssassinem, port 783                                       |
| `train`                                    | Natrénuje model ze souborů mbox, adresářů Maildir, složek nebo datových sad                 |
| `eval`                                     | Změří model na označené poště                                                               |
| `learn spam\|ham [file\|-] --model <file>` | Naučí model jednu zprávu                                                                    |
| `llm-test`                                 | Ověří nastavení jazykového modelu na třech ukázkových zprávách                              |
| `models`                                   | Vypíše doporučené otevřené modely                                                           |
| `version`, `help`                          |                                                                                             |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Volba                      | Význam                                                 |
| -------------------------- | ------------------------------------------------------ |
| `--json`                   | Vypíše celý výsledek jako JSON                         |
| `--headers`                | Vypíše zprávu s přidanými hlavičkami `X-Spam-*`        |
| `--subject-tag <tag>`      | Navíc přidá předponu k předmětu spamu                  |
| `--verbose`                | Zobrazí každý test a nejsilnější indicie klasifikátoru |
| `--threshold <n>`          | Skóre, od kterého je pošta spam (výchozí 5)            |
| `--reject-threshold <n>`   | Skóre, od kterého se pošta odmítne (výchozí 15)        |
| `--model <file>`           | Soubor modelu místo přibaleného                        |
| `--no-classifier`          | Nepoužívat klasifikátor                                |
| `--config <file>`          | Soubor JSON s [volbami knihovny](api.md#options)       |
| `--allow-language <codes>` | Přijímané jazyky, například `en,de,fr`                 |

Návratové kódy: 0 ham, 1 spam, 2 chyba.

### Relace SMTP

| Volba               | Význam                                              |
| ------------------- | --------------------------------------------------- |
| `--ip <address>`    | IP adresa klienta, který zprávu poslal              |
| `--hostname <name>` | Ověřené reverzní jméno DNS klienta                  |
| `--helo <name>`     | Jméno, které klient uvedl v HELO nebo EHLO          |
| `--from <address>`  | Odesílatel v obálce (MAIL FROM)                     |
| `--to <address>`    | Příjemce v obálce; pro více příjemců volbu opakujte |

### Kontroly

| Volba                 | Význam                                                                 |
| --------------------- | ---------------------------------------------------------------------- |
| `--auth`              | Kontrolovat SPF, DKIM, DMARC a ARC (vyžaduje `--ip`)                   |
| `--dnsbl <zone>`      | Blocklist IP adres, například `zen.spamhaus.org`; lze opakovat         |
| `--uribl <zone>`      | Blocklist domén v odkazech, například `dbl.spamhaus.org`; lze opakovat |
| `--dns-server <ip>`   | Jmenný server pro kontroly DNS; lze opakovat                           |
| `--no-cloudflare`     | Neptat se filtrovacích resolverů Cloudflare na odkazy                  |
| `--clamav [socket]`   | Kontrolovat přílohy pomocí clamd na jeho výchozím nebo zadaném socketu |
| `--allowlist <value>` | Vždy přijmout tuto IP adresu, doménu nebo adresu; lze opakovat         |
| `--denylist <value>`  | Vždy odmítnout tuto IP adresu, doménu nebo adresu; lze opakovat        |

### Jazykový model

| Volba                                                      | Význam                                                                                                                                              |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` a další ([seznam](llm.md#providers))                                                           |
| `--llm-model <name>`                                       | Model, například `qwen3.5:4b` nebo `claude-haiku-4-5`                                                                                               |
| `--llm-method <method>`                                    | `decision` (pravděpodobnost každého verdiktu v jednom kroku; výchozí, kde je k dispozici) nebo `generate` ([metody](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | ID účtu Cloudflare, pro `clef` a `clef-flash`                                                                                                       |
| `--llm-url <url>`                                          | Základní URL, například `http://10.0.0.5:11434`                                                                                                     |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Změní jednu část URL poskytovatele                                                                                                                  |
| `--llm-api-key <key>`                                      | Klíč API; viz také proměnné prostředí níže                                                                                                          |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` nebo `none`                                                                                     |
| `--llm-auth-header <name>`                                 | Hlavička pro klíč, s `--llm-auth header`                                                                                                            |
| `--llm-username`, `--llm-password`                         | Pro `--llm-auth basic`                                                                                                                              |
| `--llm-header "Name: value"`                               | Další hlavička požadavku; lze opakovat                                                                                                              |
| `--llm-mode <mode>`                                        | `auto` (jen hraniční případy, výchozí) nebo `always`                                                                                                |
| `--llm-timeout <ms>`                                       | Výchozí 30000                                                                                                                                       |
| `--llm-policy <text>`                                      | Další pravidla pro model, například „Faktury nikdy neposíláme“                                                                                      |
| `--llm-redact`, `--no-llm-redact`                          | Nejdřív odstranit osobní údaje; u vzdálených poskytovatelů ve výchozím stavu zapnuto                                                                |


## filter

[Obsahový filtr pro Postfix](postfix.md#content-filter). Přečte zprávu ze standardního vstupu, přidá hlavičky `X-Spam-*` a předá ji programu sendmail se stejnou obálkou.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Volba                 | Význam                                                       |
| --------------------- | ------------------------------------------------------------ |
| `--sendmail <path>`   | Výchozí `/usr/sbin/sendmail`                                 |
| `--subject-tag <tag>` | Přidá předponu k předmětu spamu                              |
| `--reject`            | Poštu na prahu odmítnutí vrátí odesílateli místo předání dál |
| `--discard`           | Poštu na prahu odmítnutí zahodí místo předání dál            |

Návratové kódy se řídí konvencemi programu sendmail, které Postfix čte: 0 doručeno (nebo zahozeno), 64 nezadáni žádní příjemci, 69 odmítnuto jako spam (Postfix zprávu vrátí), 75 jakékoli selhání, takže Postfix zprávu ponechá a zkusí to později znovu.


## milter, http, server a spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Port 783 je port, který klienti SpamAssassinu používají ve výchozím stavu. Porty pod 1024 vyžadují roota nebo oprávnění `CAP_NET_BIND_SERVICE`; použijte jiný port, například `--port 7833`, a nastavte ho v klientovi.

| Volba                 | Význam                                                                        |
| --------------------- | ----------------------------------------------------------------------------- |
| `--port <n>`          | Port TCP                                                                      |
| `--host <ip>`         | Adresa, na které naslouchat (výchozí 127.0.0.1)                               |
| `--socket <path>`     | Naslouchat místo toho na unixovém socketu                                     |
| `--reject`            | Milter: odmítat poštu na prahu odmítnutí                                      |
| `--reject-code <n>`   | Milter: 451, zkuste to později (výchozí), nebo 550                            |
| `--quarantine`        | Milter: zadržet spam v karanténě poštovního serveru                           |
| `--name <hostname>`   | Milter: jméno tohoto serveru v Authentication-Results                         |
| `--token <secret>`    | HTTP: vyžadovat `Authorization: Bearer <secret>`; nutné pro `/learn`          |
| `--allow-tell`        | spamd: přijímat požadavky TELL (`spamc -L spam`) k učení                      |
| `--out <file>`        | HTTP a spamd: ukládat naučené do tohoto souboru modelu                        |
| `--subject-tag <tag>` | Milter a spamd: přidat předponu k předmětu spamu                              |
| `--verbose`           | Milter: zaznamenat každou kontrolu. TCP server: odpovědět jedním řádkem textu |

Výše uvedené volby kontroly platí i pro servery. [Milter](postfix.md#milter), [HTTP API, TCP server a spamd](http-api.md).


## train, eval a learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Volba                                           | Význam                                                                |
| ----------------------------------------------- | --------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: soubor mbox, Maildir nebo složka souborů `.eml`; lze opakovat   |
| `--ham <path>`                                  | Ham, stejně; lze opakovat                                             |
| `--dataset <file>`                              | Soubor CSV nebo JSON Lines se sloupci pro text a štítek; lze opakovat |
| `--text-column <name>`, `--label-column <name>` | Názvy sloupců, pokud se nerozpoznají                                  |
| `--out <file>`                                  | Kam zapsat model (výchozí `spamscanner-model.json`)                   |
| `--merge`                                       | Začít z přibaleného modelu (nebo `--model`) místo prázdného           |

`learn` aktualizuje soubor modelu na místě a napoprvé ho vytvoří z přibaleného modelu. [Trénování](training.md)


## llm-test a models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` pošle modelu jednu běžnou zprávu a dva podvody, v angličtině a italštině, vypíše jeho verdikty, čas každého z nich, použitou metodu a hardware a skončí s kódem 0 jen tehdy, když jsou všechny tři správně.


## Konfigurační soubor

`--config file.json` (nebo proměnná prostředí `SPAMSCANNER_CONFIG`) načte [volby knihovny](api.md#options). Volby z příkazové řádky mají přednost před souborem.

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


## Proměnné prostředí

| Proměnná                                                                                                                                                                                                                                                                                                                   | Význam                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                       | Konfigurační soubor                                     |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                        | Soubor modelu použitý místo přibaleného                 |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                        | Token pro HTTP API                                      |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                  | Klíč API pro jakéhokoli poskytovatele jazykového modelu |
| `CLOUDFLARE_API_TOKEN` a `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Vlastní klíč každého poskytovatele                      |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                  | Ladicí výpisy                                           |
