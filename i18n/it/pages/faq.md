<!-- source: c93fa1a3f9c7 -->

<!--
label: Domande frequenti
title: Domande frequenti
description: Risposte su Spam Scanner: quanto è preciso, quali lingue supporta, cosa invia in rete, modelli linguistici, SpamAssassin e Forward Email.
keywords: Spam Scanner FAQ, domande filtro antispam, precisione filtro antispam, privacy filtro antispam
-->

# Domande frequenti


## Che cos'è Spam Scanner?

Un filtro antispam per Node.js, la riga di comando e i server di posta. Legge un messaggio email grezzo e decide se è spam, phishing, una truffa o se contiene malware, con un punteggio e l'elenco dei test che hanno deciso. Funziona come libreria, come milter per Postfix e Sendmail, come server spamd compatibile con SpamAssassin, come content filter di Postfix, come API HTTP o come server TCP.


## È gratuito?

La sua [licenza](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), la Business Source License 1.1, consente qualsiasi uso tranne offrire ad altri il rilevamento dello spam come servizio, e indica la data in cui passa alla Apache License 2.0.


## Quanto è preciso?

Sui messaggi in inglese dei suoi dati di addestramento esclusi dall'addestramento, il solo classificatore incluso non ha segnato come spam nessun messaggio ham e ha intercettato il 97% dello spam; i numeri completi per lingua sono nella [guida all'addestramento](../../docs/training.md#the-bundled-model). Link, allegati, autenticazione, blocklist e un modello linguistico si aggiungono a questo. Il vero test è la tua posta: `spamscanner eval` misura qualsiasi modello su qualsiasi posta etichettata.


## Quali lingue supporta?

Tutte. Segmenta le parole con le regole Unicode, anche in cinese, giapponese e thailandese, che non hanno spazi. Dove il modello incluso ha visto poca posta in una lingua, resta incerto invece di segnalarla, e decidono un modello linguistico o il tuo addestramento. [Lingue](../../docs/languages.md)


## Invia la mia posta da qualche parte?

No. Per impostazione predefinita cerca i nomi host dei link sui resolver DNS con filtraggio di Cloudflare, e nient'altro lascia la macchina. Autenticazione, blocklist, modelli linguistici e servizi di reputazione sono disattivati finché non vengono configurati, e i dati personali vengono rimossi prima che la posta vada a un modello linguistico in hosting. [Sicurezza e privacy](../../docs/security.md)


## Mi serve un modello linguistico?

No. È un secondo parere per i casi dubbi. Senza, quei messaggi vengono decisi solo in base al punteggio.


## Quale modello linguistico conviene usare?

`qwen3.5:4b` tramite Ollama su una CPU, oppure `qwen3.5:9b` con una GPU. Entrambi hanno licenza Apache e leggono 201 lingue. Funzionano anche i modelli in hosting di Anthropic, OpenAI, Google e altri. [Modelli consigliati](../../docs/llm.md#recommended-open-models)


## Può sostituire SpamAssassin?

Nella maggior parte delle configurazioni sì: parla il protocollo di spamd, quindi spamc, Exim e Haraka funzionano senza modifiche, e scrive le stesse intestazioni `X-Spam-*`. Non esegue i file di regole di SpamAssassin. [Alternativa a SpamAssassin](/spamassassin-alternative/)


## Rifiuterà posta legittima?

Il rifiuto della posta è disattivato per impostazione predefinita: il milter si limita a marcare. Con `--reject` vengono rifiutati solo i messaggi con punteggio pari o superiore a 15, con un errore temporaneo 451, quindi i mittenti riprovano e un errore si può correggere cambiando un'impostazione. Il content filter non rifiuta mai durante la sessione SMTP.


## Come lo addestro sulla mia posta?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, poi `--model model.json`. Funzionano file mbox, Maildir, cartelle di file `.eml` e dataset CSV o JSON Lines. [Addestramento](../../docs/training.md)


## Funziona senza Node.js?

Sì: i binari autonomi per Linux, macOS e Windows includono Node.js e il modello. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Chi lo sviluppa?

[Forward Email](https://forwardemail.net), per i propri server di posta.
