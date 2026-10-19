<!-- source: ff86d06bdcd0 -->

# Riga di comando

```text
spamscanner <command> [options]
```

| Comando                                    | Cosa fa                                                                                      |
| ------------------------------------------ | -------------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Analizza un messaggio da un file o dallo standard input                                      |
| `filter -f <sender> -- <recipients...>`    | Content filter di Postfix: analizza lo standard input, aggiunge le intestazioni e lo inoltra |
| `milter`                                   | Milter per Postfix e Sendmail, porta 7831                                                    |
| `http`                                     | API HTTP, porta 7832                                                                         |
| `server`                                   | Semplice server TCP, porta 7830                                                              |
| `spamd`                                    | Server spamd compatibile con SpamAssassin, porta 783                                         |
| `train`                                    | Addestra un modello da file mbox, Maildir, cartelle o dataset                                |
| `eval`                                     | Misura un modello su posta etichettata                                                       |
| `learn spam\|ham [file\|-] --model <file>` | Insegna un messaggio a un modello                                                            |
| `llm-test`                                 | Verifica le impostazioni del modello linguistico con tre messaggi di esempio                 |
| `models`                                   | Elenca i modelli aperti consigliati                                                          |
| `version`, `help`                          |                                                                                              |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Opzione                    | Significato                                                  |
| -------------------------- | ------------------------------------------------------------ |
| `--json`                   | Stampa il risultato completo in JSON                         |
| `--headers`                | Stampa il messaggio con le intestazioni `X-Spam-*` aggiunte  |
| `--subject-tag <tag>`      | Aggiunge anche un prefisso all'oggetto dello spam            |
| `--verbose`                | Mostra ogni test e gli indizi più forti del classificatore   |
| `--threshold <n>`          | Punteggio a cui la posta è spam (predefinito 5)              |
| `--reject-threshold <n>`   | Punteggio a cui la posta viene rifiutata (predefinito 15)    |
| `--model <file>`           | Un file di modello al posto di quello incluso                |
| `--no-classifier`          | Non usa il classificatore                                    |
| `--config <file>`          | Un file JSON con le [opzioni della libreria](api.md#options) |
| `--allow-language <codes>` | Lingue accettate, ad esempio `en,de,fr`                      |
| `--max-size <bytes>`       | Messaggio più grande letto (predefinito 26214400, 25 MiB)    |

Codici di uscita: 0 ham, 1 spam, 2 errore.

`scan` e `learn` leggono al massimo `--max-size` byte di un messaggio, da un file o dallo standard input; i server hanno lo stesso limite. Un messaggio più grande è un errore (codice di uscita 2), e il resto non viene letto.

Lo standard output contiene solo il risultato (o il messaggio): tutto ciò che una libreria stampa mentre un comando è in esecuzione, come le note di mailauth sulle lunghezze del corpo DKIM, va sullo standard error.

### Sessione SMTP

| Opzione             | Significato                                                |
| ------------------- | ---------------------------------------------------------- |
| `--ip <address>`    | Indirizzo IP del client che ha inviato il messaggio        |
| `--hostname <name>` | Il nome DNS inverso verificato del client                  |
| `--helo <name>`     | Il nome fornito in HELO o EHLO                             |
| `--from <address>`  | Mittente dell'envelope (MAIL FROM)                         |
| `--to <address>`    | Destinatario dell'envelope; ripetibile per più destinatari |

### Controlli

| Opzione               | Significato                                                                                                                                                 |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--auth`              | Verifica SPF, DKIM, DMARC e ARC (richiede `--ip`)                                                                                                           |
| `--dnsbl <zone>`      | Blocklist di IP, ad esempio `zen.spamhaus.org`; ripetibile                                                                                                  |
| `--uribl <zone>`      | Blocklist di domini per i link, ad esempio `dbl.spamhaus.org`; ripetibile                                                                                   |
| `--dns-server <ip>`   | Name server per i controlli DNS; ripetibile                                                                                                                 |
| `--no-cloudflare`     | Non interroga i resolver con filtraggio di Cloudflare sui link                                                                                              |
| `--clamav[=socket]`   | Analizza gli allegati con clamd, sul suo socket predefinito o su quello indicato                                                                            |
| `--allowlist <value>` | Accetta sempre questo indirizzo IP o nome host del client, o questo dominio o indirizzo quando l'autenticazione conferma il mittente (`--auth`); ripetibile |
| `--denylist <value>`  | Rifiuta sempre questo indirizzo IP, dominio o indirizzo; ripetibile                                                                                         |

### Modello linguistico

| Opzione                                                    | Significato                                                                                                                                                         |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` e altri ([elenco](llm.md#providers))                                                                           |
| `--llm-model <name>`                                       | Modello, ad esempio `qwen3.5:4b` o `claude-haiku-4-5`                                                                                                               |
| `--llm-method <method>`                                    | `decision` (una probabilità per ogni verdetto, in un solo passaggio; il valore predefinito dove disponibile) o `generate` ([metodi](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | ID dell'account Cloudflare, per `clef` e `clef-flash`                                                                                                               |
| `--llm-url <url>`                                          | URL di base, ad esempio `http://10.0.0.5:11434`                                                                                                                     |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Modifica una parte dell'URL del provider                                                                                                                            |
| `--llm-api-key <key>`                                      | Chiave API; vedi anche le variabili d'ambiente più sotto                                                                                                            |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` o `none`                                                                                                        |
| `--llm-auth-header <name>`                                 | Intestazione per la chiave, con `--llm-auth header`                                                                                                                 |
| `--llm-username`, `--llm-password`                         | Per `--llm-auth basic`                                                                                                                                              |
| `--llm-header "Name: value"`                               | Intestazione aggiuntiva della richiesta; ripetibile                                                                                                                 |
| `--llm-mode <mode>`                                        | `auto` (solo casi dubbi, il valore predefinito), `always` o `off`                                                                                                   |
| `--llm-timeout <ms>`                                       | Predefinito 30000                                                                                                                                                   |
| `--llm-policy <text>`                                      | Regole aggiuntive per il modello, ad esempio "Non inviamo mai fatture"                                                                                              |
| `--llm-redact`, `--no-llm-redact`                          | Rimuove prima i dati personali; attivo per impostazione predefinita per i provider remoti                                                                           |


## filter

Un [content filter di Postfix](postfix.md#content-filter). Legge un messaggio dallo standard input, aggiunge le intestazioni `X-Spam-*` e lo passa a sendmail con lo stesso envelope.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Opzione               | Significato                                                                                                    |
| --------------------- | -------------------------------------------------------------------------------------------------------------- |
| `--sendmail <path>`   | Predefinito `/usr/sbin/sendmail`                                                                               |
| `--subject-tag <tag>` | Aggiunge un prefisso all'oggetto dello spam                                                                    |
| `--reject`            | Rimanda al mittente la posta che raggiunge la soglia di rifiuto invece di inoltrarla                           |
| `--discard`           | Scarta la posta che raggiunge la soglia di rifiuto invece di inoltrarla                                        |
| `--on-error <answer>` | Per la posta che non è stato possibile analizzare completamente: `tempfail` (il valore predefinito) o `accept` |
| `--max-size <bytes>`  | Messaggio più grande analizzato (predefinito 26214400, 25 MiB)                                                 |

I codici di uscita seguono le convenzioni di sendmail, che Postfix legge: 0 consegnato (o scartato), 64 nessun destinatario indicato, 69 rifiutato come spam (Postfix lo rimanda al mittente), 75 qualsiasi errore, quindi Postfix conserva il messaggio e riprova più tardi. Anche un messaggio con un allegato che ClamAV non ha potuto analizzare è un errore. Con `--on-error accept`, un messaggio simile, o uno la cui analisi è fallita, viene inoltrato con `X-Spam-Virus-Scan: failed`, e senza le intestazioni `X-Spam-*` aggiunte dal mittente.

Un messaggio più grande di `--max-size` non viene analizzato, né tenuto in memoria per intero. Viene rinviato (75) o, con `--on-error accept`, inoltrato senza analisi man mano che viene letto, contrassegnato e senza le intestazioni `X-Spam-*` del mittente come sopra. Il `message_size_limit` di Postfix (10 MB per impostazione predefinita) mantiene la posta sotto il limite predefinito; se lo alzi oltre 25 MiB, alza anche `--max-size`.


## milter, http, server e spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832    # token in SPAMSCANNER_TOKEN
spamscanner server --port 7830
spamscanner spamd --port 783
```

L'API HTTP legge il proprio token dalla variabile d'ambiente `SPAMSCANNER_TOKEN`. Anche `--token` funziona, ma gli altri utenti della macchina possono vedere le opzioni della riga di comando con `ps`.

La porta 783 è quella usata per impostazione predefinita dai client SpamAssassin. Le porte sotto 1024 richiedono root o la capability `CAP_NET_BIND_SERVICE`; usa un'altra porta, come `--port 7833`, e indicala al client.

| Opzione                 | Significato                                                                                                                                                                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--port <n>`            | Porta TCP                                                                                                                                                                                                                         |
| `--host <ip>`           | Indirizzo su cui restare in ascolto (predefinito 127.0.0.1)                                                                                                                                                                       |
| `--socket <path>`       | Resta invece in ascolto su un socket Unix                                                                                                                                                                                         |
| `--max-size <bytes>`    | Messaggio più grande accettato (predefinito 26214400, 25 MiB). Il milter analizza l'inizio di un corpo più lungo, e risponde come per un'analisi fallita (`--on-error`) quando la busta e le intestazioni da sole sono più grandi |
| `--max-connections <n>` | Connessioni aperte contemporaneamente (predefinito 200); quelle in più vengono chiuse subito. HTTP: anche le richieste gestite contemporaneamente, quelle in più ricevono `503`                                                   |
| `--reject`              | Milter: rifiuta la posta che raggiunge la soglia di rifiuto                                                                                                                                                                       |
| `--reject-code <n>`     | Milter: un codice 4xx, riprova più tardi (451, il valore predefinito), o un codice 5xx come 550                                                                                                                                   |
| `--quarantine`          | Milter: trattiene lo spam nella quarantena del server di posta                                                                                                                                                                    |
| `--on-error <answer>`   | Milter: per la posta che non è stato possibile analizzare completamente, `tempfail` (il valore predefinito) o `accept`                                                                                                            |
| `--name <hostname>`     | Milter: il nome di questo server in Authentication-Results                                                                                                                                                                        |
| `--token <secret>`      | HTTP: richiede `Authorization: Bearer <secret>`; necessario per `/learn`                                                                                                                                                          |
| `--allow-tell`          | spamd: accetta le richieste TELL (`spamc -L spam`) per l'apprendimento                                                                                                                                                            |
| `--out <file>`          | HTTP e spamd: salva ciò che viene appreso in questo file di modello                                                                                                                                                               |
| `--subject-tag <tag>`   | Milter e spamd: aggiunge un prefisso all'oggetto dello spam                                                                                                                                                                       |
| `--verbose`             | Milter: registra ogni analisi. Server TCP: risponde con una riga di testo                                                                                                                                                         |

Le opzioni di analisi descritte sopra valgono anche per i server. [Il milter](postfix.md#milter), [l'API HTTP, il server TCP e spamd](http-api.md).

I client spamd e TCP non inviano l'indirizzo IP del client che ha inviato il messaggio, e i client HTTP lo inviano solo con `?ip=`, quindi `--auth` e `--dnsbl` funzionano solo con il milter e con le richieste HTTP che lo indicano. I server lo segnalano quando partono con queste opzioni.


## train, eval e learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Opzione                                         | Significato                                                               |
| ----------------------------------------------- | ------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: un file mbox, una Maildir o una cartella di file `.eml`; ripetibile |
| `--ham <path>`                                  | Ham, allo stesso modo; ripetibile                                         |
| `--dataset <file>`                              | Un file CSV o JSON Lines con colonne di testo e di etichetta; ripetibile  |
| `--text-column <name>`, `--label-column <name>` | Nomi delle colonne, quando non vengono rilevati                           |
| `--out <file>`                                  | Dove scrivere il modello (predefinito `spamscanner-model.json`)           |
| `--merge`                                       | Parte dal modello incluso (o da `--model`) invece che da un modello vuoto |

`learn` aggiorna il file di modello sul posto, creandolo dal modello incluso la prima volta. [Addestramento](training.md)

Con sia `--model` sia `--out`, `learn` parte dal file di `--model` e scrive il risultato in `--out`.


## llm-test e models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` invia al modello un messaggio normale e due truffe, in inglese e in italiano, stampa i suoi verdetti, il tempo impiegato per ciascuno, il metodo usato e, per un modello su questa macchina, l'hardware, ed esce con 0 solo se tutti e tre sono corretti.


## File di configurazione

`--config file.json` (o la variabile d'ambiente `SPAMSCANNER_CONFIG`) carica le [opzioni della libreria](api.md#options). Le opzioni della riga di comando hanno la precedenza sul file.

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


## Variabili d'ambiente

| Variabile                                                                                                                                                                                                                                                                                                                  | Significato                                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                       | File di configurazione                                   |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                        | File di modello usato al posto di quello incluso         |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                        | Token per l'API HTTP                                     |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                  | Chiave API per qualsiasi provider di modelli linguistici |
| `CLOUDFLARE_API_TOKEN` e `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | La chiave specifica di ciascun provider                  |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                  | Log di debug                                             |
