<!-- source: 988243aec4f3 -->

<!--
label: Filtro antispam self-hosted
title: Filtro antispam self-hosted per il tuo server di posta
description: Un filtro antispam sul tuo server. Spam Scanner tiene la posta sulla macchina, include il modello nel pacchetto, non invia telemetria e si collega a Postfix o Exim.
keywords: filtro antispam self-hosted, filtro antispam on-premise, filtro antispam privato, filtro antispam locale, filtro antispam per server di posta, antispam senza cloud
-->

# Filtro antispam self-hosted

Spam Scanner gira sul tuo server e tiene lì la posta. Il modello del classificatore è incluso nel pacchetto, non ci sono telemetria né controlli degli aggiornamenti e, di default, l'unica cosa che invia è una query DNS per il nome host di ogni link.


## Cosa esce dal server

Di default, solo i nomi host dei link di un messaggio. Vengono cercati sui resolver con filtro di Cloudflare (1.1.1.2 e 1.1.1.3) come normali query DNS, e nessuna parte del messaggio o dei suoi indirizzi viene inviata. `--no-cloudflare` disattiva anche questo.

Ogni altro controllo che usa la rete resta spento finché non lo attivi:

| Controllo              | Si attiva con        | Cosa invia                                                    |
| ---------------------- | -------------------- | ------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC  | `--auth`             | Query DNS sui record del mittente                             |
| Blocklist DNS          | `--dnsbl`, `--uribl` | L'indirizzo IP del client e i domini dei link, come query DNS |
| ClamAV                 | `--clamav`           | Gli allegati, al tuo clamd                                    |
| Un modello linguistico | `--llm`              | Un riassunto del messaggio, al server che indichi             |

Le analisi non vengono registrate né conservate. [Sicurezza e privacy](../../docs/security.md)


## Installare su un server

```sh
npm install --global spamscanner
```

Oppure il binario autonomo, con Node.js e il modello integrati:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Lo script di installazione verifica il binario con il file `SHA256SUMS` della release prima di installarlo, e ogni binario ha un'attestazione di provenienza della build firmata che `gh attestation verify` controlla. Ci sono binari per Linux (x64 e arm64), macOS e Windows. I binari Linux richiedono glibc, quindi su Alpine installa con npm. [Primi passi](../../docs/getting-started.md)

Non c'è controllo degli aggiornamenti. Per aggiornare, esegui di nuovo il comando di installazione: entrambi i comandi installano l'ultima release.


## Eseguirlo come servizio

I server milter, HTTP, TCP e spamd ascoltano su 127.0.0.1 a meno che `--host` non indichi altro. Eseguili con un utente senza privilegi, per esempio con systemd:

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

L'[unità completa e la sua configurazione](../../docs/postfix.md#1-run-the-milter) sono nella guida a Postfix. Nessuno dei server parla TLS: per raggiungerne uno da un'altra macchina usa una rete privata, un tunnel SSH o un reverse proxy con TLS.


## Collegare il tuo server di posta

| Server di posta                       | Comando                                       | Porta   |
| ------------------------------------- | --------------------------------------------- | ------- |
| Postfix o Sendmail                    | `spamscanner milter`                          | 7831    |
| Postfix, senza mai rifiutare posta    | `spamscanner filter`, un filtro dei contenuti | nessuna |
| Exim, Haraka o spamc                  | `spamscanner spamd`                           | 783     |
| Qualsiasi cosa parli HTTP             | `spamscanner http`                            | 7832    |
| Un semplice client TCP                | `spamscanner server`                          | 7830    |
| Un server di posta scritto in Node.js | `import SpamScanner from 'spamscanner'`       | nessuna |

I server possono aggiungere al messaggio le intestazioni `X-Spam-Flag`, `X-Spam-Score` e `X-Spam-Status`, e la libreria restituisce il punteggio e ogni test scattato. Guide: [filtro antispam per Postfix](/postfix-spam-filter/), [altri server di posta](../../docs/mail-servers.md) e [l'API HTTP](../../docs/http-api.md).


## Tenere locali i modelli linguistici

Un modello linguistico è facoltativo e legge solo i casi dubbi: lo spam evidente e il ham evidente non ci arrivano mai. Con Ollama gira sullo stesso server, quindi nessun messaggio ne esce:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` gira su una CPU. Con un provider ospitato, invece, i dati personali vengono rimossi dal messaggio prima dell'invio. [Modelli linguistici](../../docs/llm.md)


## Addestrarlo sulla tua posta

Il modello incluso è addestrato su dataset pubblici. Un modello addestrato sulla posta che riceve il tuo server funziona meglio, e resta su quel server:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Un file di modello contiene conteggi di caratteristiche sottoposte a hash, non parole né testo dei messaggi. [Addestramento](../../docs/training.md)


## Requisiti

Node.js 18 o successivo su Linux, macOS o Windows, o niente con un binario autonomo. ClamAV e Ollama sono facoltativi e girano come servizi a sé.
