<!-- source: a59bc5927d86 -->

# Parancssor

```text
spamscanner <command> [options]
```

| Parancs                                    | Mit csinál                                                                              |
| ------------------------------------------ | --------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Levél vizsgálata fájlból vagy a szabványos bemenetről                                   |
| `filter -f <sender> -- <recipients...>`    | Postfix-tartalomszűrő: a szabványos bemenet vizsgálata, fejlécek hozzáadása, továbbadás |
| `milter`                                   | Milter a Postfixhez és a Sendmailhez, 7831-es port                                      |
| `http`                                     | HTTP API, 7832-es port                                                                  |
| `server`                                   | Egyszerű TCP-szerver, 7830-as port                                                      |
| `spamd`                                    | SpamAssassin-kompatibilis spamd szerver, 783-as port                                    |
| `train`                                    | Modell tanítása mbox-fájlokból, Maildirekből, mappákból vagy adatkészletekből           |
| `eval`                                     | Modell mérése címkézett leveleken                                                       |
| `learn spam\|ham [file\|-] --model <file>` | Egy levél megtanítása egy modellnek                                                     |
| `llm-test`                                 | A nyelvimodell-beállítások ellenőrzése három mintalevéllel                              |
| `models`                                   | Az ajánlott nyílt modellek listája                                                      |
| `version`, `help`                          |                                                                                         |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Kapcsoló                   | Jelentés                                                                |
| -------------------------- | ----------------------------------------------------------------------- |
| `--json`                   | A teljes eredmény kiírása JSON-ként                                     |
| `--headers`                | A levél kiírása a hozzáadott `X-Spam-*` fejlécekkel                     |
| `--subject-tag <tag>`      | A spam tárgyának előtaggal való ellátása is                             |
| `--verbose`                | Minden teszt és az osztályozó legerősebb jeleinek megjelenítése         |
| `--threshold <n>`          | Az a pontszám, amelytől a levél spam (alapértelmezés: 5)                |
| `--reject-threshold <n>`   | Az a pontszám, amelytől a levél elutasításra kerül (alapértelmezés: 15) |
| `--model <file>`           | Modellfájl a beépített helyett                                          |
| `--no-classifier`          | Az osztályozó mellőzése                                                 |
| `--config <file>`          | [Könyvtári beállításokat](api.md#options) tartalmazó JSON-fájl          |
| `--allow-language <codes>` | Elfogadott nyelvek, például `en,de,fr`                                  |

Kilépési kódok: 0 ham, 1 spam, 2 hiba.

### SMTP-munkamenet

| Kapcsoló            | Jelentés                                        |
| ------------------- | ----------------------------------------------- |
| `--ip <address>`    | A levelet küldő kliens IP-címe                  |
| `--hostname <name>` | A kliens ellenőrzött fordított DNS-neve         |
| `--helo <name>`     | A HELO vagy EHLO parancsban megadott név        |
| `--from <address>`  | A boríték szerinti feladó (MAIL FROM)           |
| `--to <address>`    | A boríték szerinti címzett; többhöz ismételhető |

### Ellenőrzések

| Kapcsoló              | Jelentés                                                                      |
| --------------------- | ----------------------------------------------------------------------------- |
| `--auth`              | SPF, DKIM, DMARC és ARC ellenőrzése (a `--ip` szükséges hozzá)                |
| `--dnsbl <zone>`      | IP-tiltólista, például `zen.spamhaus.org`; ismételhető                        |
| `--uribl <zone>`      | Domain-tiltólista a hivatkozásokhoz, például `dbl.spamhaus.org`; ismételhető  |
| `--dns-server <ip>`   | Névszerver a DNS-ellenőrzésekhez; ismételhető                                 |
| `--no-cloudflare`     | A Cloudflare szűrő DNS-feloldóinak mellőzése a hivatkozásoknál                |
| `--clamav [socket]`   | Mellékletek vizsgálata clamd-vel, az alapértelmezett vagy a megadott socketen |
| `--allowlist <value>` | Ennek az IP-címnek, domainnek vagy címnek mindig elfogadása; ismételhető      |
| `--denylist <value>`  | Ennek az IP-címnek, domainnek vagy címnek mindig elutasítása; ismételhető     |

### Nyelvi modell

| Kapcsoló                                                   | Jelentés                                                                                       |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` és mások ([lista](llm.md#providers))                 |
| `--llm-model <name>`                                       | Modell, például `qwen3.5:4b` vagy `claude-haiku-4-5`                                           |
| `--llm-url <url>`                                          | Alap-URL, például `http://10.0.0.5:11434`                                                      |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | A szolgáltató URL-jének egy részét módosítja                                                   |
| `--llm-api-key <key>`                                      | API-kulcs; lásd még az alábbi környezeti változókat                                            |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` vagy `none`                                |
| `--llm-auth-header <name>`                                 | A kulcs fejléce, a `--llm-auth header` beállítással                                            |
| `--llm-username`, `--llm-password`                         | A `--llm-auth basic` beállításhoz                                                              |
| `--llm-header "Name: value"`                               | További kérésfejléc; ismételhető                                                               |
| `--llm-mode <mode>`                                        | `auto` (csak a kétes esetek, alapértelmezés) vagy `always`                                     |
| `--llm-timeout <ms>`                                       | Alapértelmezés: 30000                                                                          |
| `--llm-policy <text>`                                      | További szabályok a modellnek, például „Soha nem küldünk számlát”                              |
| `--llm-redact`, `--no-llm-redact`                          | A személyes adatok előzetes eltávolítása; távoli szolgáltatóknál alapértelmezetten bekapcsolva |


## filter

[Postfix-tartalomszűrő](postfix.md#content-filter). Beolvas egy levelet a szabványos bemenetről, hozzáadja az `X-Spam-*` fejléceket, és ugyanazzal a borítékkal átadja a sendmailnek.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Kapcsoló              | Jelentés                                                                |
| --------------------- | ----------------------------------------------------------------------- |
| `--sendmail <path>`   | Alapértelmezés: `/usr/sbin/sendmail`                                    |
| `--subject-tag <tag>` | A spam tárgyának előtaggal való ellátása                                |
| `--reject`            | Az elutasítási küszöböt elérő levél visszapattintása továbbadás helyett |
| `--discard`           | Az elutasítási küszöböt elérő levél eldobása továbbadás helyett         |

A kilépési kódok a sendmail konvencióit követik, amelyeket a Postfix értelmez: 0 kézbesítve (vagy eldobva), 64 nincs megadva címzett, 69 spamként elutasítva (a Postfix visszapattintja), 75 bármilyen hiba, így a Postfix megtartja a levelet, és később újra próbálkozik.


## milter, http, server és spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

A 783-as port az, amelyet a SpamAssassin-kliensek alapértelmezetten használnak. Az 1024 alatti portokhoz root jogosultság vagy a `CAP_NET_BIND_SERVICE` képesség szükséges; ehelyett használható egy másik port, például `--port 7833`, amelyet a kliensnek is meg kell adni.

| Kapcsoló              | Jelentés                                                                      |
| --------------------- | ----------------------------------------------------------------------------- |
| `--port <n>`          | TCP-port                                                                      |
| `--host <ip>`         | A figyelési cím (alapértelmezés: 127.0.0.1)                                   |
| `--socket <path>`     | Figyelés ehelyett Unix-socketen                                               |
| `--reject`            | Milter: az elutasítási küszöböt elérő levelek visszautasítása                 |
| `--reject-code <n>`   | Milter: 451, próbálja később (alapértelmezés), vagy 550                       |
| `--quarantine`        | Milter: a spam visszatartása a levelezőszerver karanténjában                  |
| `--name <hostname>`   | Milter: ennek a szervernek a neve az Authentication-Results fejlécben         |
| `--token <secret>`    | HTTP: `Authorization: Bearer <secret>` megkövetelése; a `/learn` igényli      |
| `--allow-tell`        | spamd: TELL kérések (`spamc -L spam`) elfogadása tanuláshoz                   |
| `--out <file>`        | HTTP és spamd: a tanultak mentése ebbe a modellfájlba                         |
| `--subject-tag <tag>` | Milter és spamd: a spam tárgyának előtaggal való ellátása                     |
| `--verbose`           | Milter: minden vizsgálat naplózása. TCP-szerver: válasz egyetlen szövegsorban |

A fenti vizsgálati kapcsolók a szerverekre is vonatkoznak. [A milter](postfix.md#milter), [a HTTP API, a TCP-szerver és a spamd](http-api.md).


## train, eval és learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Kapcsoló                                        | Jelentés                                                                       |
| ----------------------------------------------- | ------------------------------------------------------------------------------ |
| `--spam <path>`                                 | Spam: mbox-fájl, Maildir vagy `.eml` fájlokat tartalmazó mappa; ismételhető    |
| `--ham <path>`                                  | Ham, ugyanígy; ismételhető                                                     |
| `--dataset <file>`                              | Szöveg- és címkeoszlopot tartalmazó CSV- vagy JSON Lines-fájl; ismételhető     |
| `--text-column <name>`, `--label-column <name>` | Oszlopnevek, ha nem ismeri fel őket                                            |
| `--out <file>`                                  | A modell kimeneti helye (alapértelmezés: `spamscanner-model.json`)             |
| `--merge`                                       | Indulás a beépített modellből (vagy a `--model` modellből) üres modell helyett |

A `learn` helyben frissíti a modellfájlt, első alkalommal a beépített modellből hozza létre. [Tanítás](training.md)


## llm-test és models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

Az `llm-test` egy hétköznapi levelet és két csalást küld a modellnek angolul és olaszul, kiírja az ítéleteit, és csak akkor lép ki 0-s kóddal, ha mindhárom helyes.


## Konfigurációs fájl

A `--config file.json` (vagy a `SPAMSCANNER_CONFIG` környezeti változó) [könyvtári beállításokat](api.md#options) tölt be. A parancssori kapcsolók felülírják a fájlt.

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


## Környezeti változók

| Változó                                                                                                                                                                                                                                              | Jelentés                                      |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | Konfigurációs fájl                            |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | A beépített helyett használt modellfájl       |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | Token a HTTP API-hoz                          |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | API-kulcs bármely nyelvimodell-szolgáltatóhoz |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Az egyes szolgáltatók saját kulcsa            |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | Hibakeresési naplózás                         |
