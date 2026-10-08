<!-- source: a59bc5927d86 -->

# Kommandozeile

```text
spamscanner <command> [options]
```

| Befehl                                     | Was er tut                                                                         |
| ------------------------------------------ | ---------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Eine Nachricht aus einer Datei oder von der Standardeingabe prüfen                 |
| `filter -f <sender> -- <recipients...>`    | Content-Filter für Postfix: Standardeingabe prüfen, Header hinzufügen, weitergeben |
| `milter`                                   | Milter für Postfix und Sendmail, Port 7831                                         |
| `http`                                     | HTTP-API, Port 7832                                                                |
| `server`                                   | Einfacher TCP-Server, Port 7830                                                    |
| `spamd`                                    | SpamAssassin-kompatibler spamd-Server, Port 783                                    |
| `train`                                    | Ein Modell aus mbox-Dateien, Maildirs, Ordnern oder Datensätzen trainieren         |
| `eval`                                     | Ein Modell an gelabelten E-Mails messen                                            |
| `learn spam\|ham [file\|-] --model <file>` | Einem Modell eine einzelne Nachricht beibringen                                    |
| `llm-test`                                 | Sprachmodell-Einstellungen mit drei Beispielnachrichten prüfen                     |
| `models`                                   | Empfohlene offene Modelle auflisten                                                |
| `version`, `help`                          |                                                                                    |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Option                     | Bedeutung                                                       |
| -------------------------- | --------------------------------------------------------------- |
| `--json`                   | Das vollständige Ergebnis als JSON ausgeben                     |
| `--headers`                | Die Nachricht mit hinzugefügten `X-Spam-*`-Headern ausgeben     |
| `--subject-tag <tag>`      | Zusätzlich dem Betreff von Spam ein Präfix voranstellen         |
| `--verbose`                | Alle Tests und die stärksten Hinweise des Klassifikators zeigen |
| `--threshold <n>`          | Score, ab dem eine E-Mail Spam ist (Standard 5)                 |
| `--reject-threshold <n>`   | Score, ab dem eine E-Mail abgewiesen wird (Standard 15)         |
| `--model <file>`           | Eine Modelldatei statt der mitgelieferten                       |
| `--no-classifier`          | Den Klassifikator nicht verwenden                               |
| `--config <file>`          | Eine JSON-Datei mit [Bibliotheksoptionen](api.md#options)       |
| `--allow-language <codes>` | Akzeptierte Sprachen, zum Beispiel `en,de,fr`                   |

Exit-Codes: 0 Ham, 1 Spam, 2 Fehler.

### SMTP-Sitzung

| Option              | Bedeutung                                              |
| ------------------- | ------------------------------------------------------ |
| `--ip <address>`    | IP-Adresse des Clients, der die Nachricht gesendet hat |
| `--hostname <name>` | Der verifizierte Reverse-DNS-Name des Clients          |
| `--helo <name>`     | Der Name, den er bei HELO oder EHLO angegeben hat      |
| `--from <address>`  | Absender im Umschlag (MAIL FROM)                       |
| `--to <address>`    | Empfänger im Umschlag; für mehrere wiederholen         |

### Prüfungen

| Option                | Bedeutung                                                                  |
| --------------------- | -------------------------------------------------------------------------- |
| `--auth`              | SPF, DKIM, DMARC und ARC prüfen (benötigt `--ip`)                          |
| `--dnsbl <zone>`      | IP-Blockliste, zum Beispiel `zen.spamhaus.org`; wiederholbar               |
| `--uribl <zone>`      | Domain-Blockliste für Links, zum Beispiel `dbl.spamhaus.org`; wiederholbar |
| `--dns-server <ip>`   | Nameserver für DNS-Prüfungen; wiederholbar                                 |
| `--no-cloudflare`     | Die filternden Resolver von Cloudflare nicht zu Links befragen             |
| `--clamav [socket]`   | Anhänge mit clamd prüfen, über dessen Standard-Socket oder den angegebenen |
| `--allowlist <value>` | Diese IP-Adresse, Domain oder Adresse immer annehmen; wiederholbar         |
| `--denylist <value>`  | Diese IP-Adresse, Domain oder Adresse immer abweisen; wiederholbar         |

### Sprachmodell

| Option                                                     | Bedeutung                                                                          |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` und weitere ([Liste](llm.md#providers))  |
| `--llm-model <name>`                                       | Modell, zum Beispiel `qwen3.5:4b` oder `claude-haiku-4-5`                          |
| `--llm-url <url>`                                          | Basis-URL, zum Beispiel `http://10.0.0.5:11434`                                    |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Einen Teil der URL des Anbieters ändern                                            |
| `--llm-api-key <key>`                                      | API-Schlüssel; siehe auch die Umgebungsvariablen unten                             |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` oder `none`                    |
| `--llm-auth-header <name>`                                 | Header für den Schlüssel, zusammen mit `--llm-auth header`                         |
| `--llm-username`, `--llm-password`                         | Für `--llm-auth basic`                                                             |
| `--llm-header "Name: value"`                               | Zusätzlicher Request-Header; wiederholbar                                          |
| `--llm-mode <mode>`                                        | `auto` (nur knappe Fälle, der Standard) oder `always`                              |
| `--llm-timeout <ms>`                                       | Standard 30000                                                                     |
| `--llm-policy <text>`                                      | Zusätzliche Regeln für das Modell, zum Beispiel „Wir versenden nie Rechnungen“     |
| `--llm-redact`, `--no-llm-redact`                          | Personenbezogene Daten vorher entfernen; bei entfernten Anbietern standardmäßig an |


## filter

Ein [Content-Filter für Postfix](postfix.md#content-filter). Er liest eine Nachricht von der Standardeingabe, fügt `X-Spam-*`-Header hinzu und übergibt sie mit demselben Umschlag an sendmail.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Option                | Bedeutung                                                                   |
| --------------------- | --------------------------------------------------------------------------- |
| `--sendmail <path>`   | Standard `/usr/sbin/sendmail`                                               |
| `--subject-tag <tag>` | Dem Betreff von Spam ein Präfix voranstellen                                |
| `--reject`            | E-Mails ab dem Ablehnungsschwellenwert zurückweisen statt sie weiterzugeben |
| `--discard`           | E-Mails ab dem Ablehnungsschwellenwert verwerfen statt sie weiterzugeben    |

Die Exit-Codes folgen den Konventionen von sendmail, die Postfix auswertet: 0 zugestellt (oder verworfen), 64 keine Empfänger angegeben, 69 als Spam abgewiesen (Postfix schickt eine Unzustellbarkeitsnachricht), 75 jeder andere Fehler, sodass Postfix die Nachricht behält und es später erneut versucht.


## milter, http, server und spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Port 783 ist der Port, den SpamAssassin-Clients standardmäßig verwenden. Ports unter 1024 benötigen root oder die Capability `CAP_NET_BIND_SERVICE`. Verwenden Sie einen anderen Port, etwa `--port 7833`, und teilen Sie ihn dem Client mit.

| Option                | Bedeutung                                                                      |
| --------------------- | ------------------------------------------------------------------------------ |
| `--port <n>`          | TCP-Port                                                                       |
| `--host <ip>`         | Adresse, auf der gelauscht wird (Standard 127.0.0.1)                           |
| `--socket <path>`     | Stattdessen auf einem Unix-Socket lauschen                                     |
| `--reject`            | Milter: E-Mails ab dem Ablehnungsschwellenwert abweisen                        |
| `--reject-code <n>`   | Milter: 451, später erneut versuchen (der Standard), oder 550                  |
| `--quarantine`        | Milter: Spam in der Quarantäne des Mailservers zurückhalten                    |
| `--name <hostname>`   | Milter: der Name dieses Servers in Authentication-Results                      |
| `--token <secret>`    | HTTP: `Authorization: Bearer <secret>` verlangen; nötig für `/learn`           |
| `--allow-tell`        | spamd: TELL-Anfragen (`spamc -L spam`) zum Lernen annehmen                     |
| `--out <file>`        | HTTP und spamd: Gelerntes in dieser Modelldatei speichern                      |
| `--subject-tag <tag>` | Milter und spamd: dem Betreff von Spam ein Präfix voranstellen                 |
| `--verbose`           | Milter: jede Prüfung protokollieren. TCP-Server: mit einer Textzeile antworten |

Die obigen Scan-Optionen gelten auch für die Server. [Der Milter](postfix.md#milter), [die HTTP-API, der TCP-Server und spamd](http-api.md).


## train, eval und learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Option                                          | Bedeutung                                                                           |
| ----------------------------------------------- | ----------------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: eine mbox-Datei, ein Maildir oder ein Ordner mit `.eml`-Dateien; wiederholbar |
| `--ham <path>`                                  | Ham, ebenso; wiederholbar                                                           |
| `--dataset <file>`                              | Eine CSV- oder JSON-Lines-Datei mit Spalten für Text und Label; wiederholbar        |
| `--text-column <name>`, `--label-column <name>` | Spaltennamen, wenn sie nicht erkannt werden                                         |
| `--out <file>`                                  | Wohin das Modell geschrieben wird (Standard `spamscanner-model.json`)               |
| `--merge`                                       | Mit dem mitgelieferten Modell (oder `--model`) statt einem leeren beginnen          |

`learn` aktualisiert die Modelldatei direkt und legt sie beim ersten Mal aus dem mitgelieferten Modell an. [Training](training.md)


## llm-test und models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` sendet eine gewöhnliche Nachricht und zwei Betrugsnachrichten, auf Englisch und Italienisch, an das Modell, gibt dessen Urteile aus und beendet sich nur dann mit 0, wenn alle drei richtig sind.


## Konfigurationsdatei

`--config file.json` (oder die Umgebungsvariable `SPAMSCANNER_CONFIG`) lädt [Bibliotheksoptionen](api.md#options). Optionen auf der Kommandozeile haben Vorrang vor der Datei.

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


## Umgebungsvariablen

| Variable                                                                                                                                                                                                                                             | Bedeutung                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | Konfigurationsdatei                             |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | Modelldatei, die statt der mitgelieferten dient |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | Token für die HTTP-API                          |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | API-Schlüssel für jeden Sprachmodell-Anbieter   |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Der eigene Schlüssel jedes Anbieters            |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | Debug-Protokollierung                           |
