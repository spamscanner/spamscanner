<!-- source: c56969e779c4 -->

# Documentazione di Spam Scanner

Spam Scanner è un filtro antispam per Node.js e per la riga di comando, con il codice sorgente su GitHub. Legge un messaggio email grezzo e decide se è spam, phishing, una truffa o se contiene malware, in qualsiasi lingua. Funziona come libreria, come strumento da riga di comando, come milter per Postfix o Sendmail, come content filter di Postfix, come server spamd compatibile con SpamAssassin, come API HTTP o come server TCP.

È sviluppato da [Forward Email](https://forwardemail.net) per i propri server di posta.


## Come viene giudicato un messaggio

Ogni controllo aggiunge o toglie punti. Il totale decide l'esito:

| Punteggio   | Azione   | Cosa fa un server di posta          |
| ----------- | -------- | ----------------------------------- |
| Sotto 5     | `accept` | Consegna il messaggio               |
| Da 5 a 14,9 | `tag`    | Lo consegna segnato come spam       |
| 15 e oltre  | `reject` | Lo rifiuta durante la sessione SMTP |

Entrambe le soglie si possono modificare. Ogni risultato elenca i test scattati, con i loro punti e un motivo, quindi una decisione si può sempre spiegare.

I controlli:

* **Un classificatore addestrato** legge le parole del messaggio in qualsiasi sistema di scrittura, la forma dei suoi link, il mittente e gli allegati. Viene distribuito già addestrato su dataset pubblici e impara dalla tua posta. [Come funziona il classificatore](how-it-works.md#the-classifier)
* **I controlli antiphishing** intercettano i domini sosia (`paypa1.com`, `pаypal.com` con una а cirillica), i link il cui testo mostra un indirizzo e la cui destinazione è un altro, e i nomi visualizzati che si spacciano per un marchio. [Phishing](how-it-works.md#phishing)
* **I controlli sugli allegati** trovano eseguibili, eseguibili rinominati come documenti, doppie estensioni, trucchi con i nomi file da destra a sinistra, eseguibili dentro file ZIP, macro di Office e contenuti PDF attivi. ClamAV può analizzare gli allegati alla ricerca di virus. [Allegati](how-it-works.md#attachments)
* **Autenticazione**: SPF, DKIM, DMARC e ARC, quando l'indirizzo IP del client è noto. [Autenticazione](how-it-works.md#authentication)
* **DNS blocklist** per l'indirizzo IP del client e per i domini nei link, e i resolver con filtraggio di Cloudflare per i siti noti di malware e per adulti. [Blocklist](how-it-works.md#blocklists)
* **Regole** per gli schemi che nessun classificatore ha bisogno di imparare: la stringa di test GTUBE, gli oggetti delle sextortion, le truffe con fatture PayPal, l'auto-spoofing e le istruzioni nascoste per i filtri IA. [Regole](scoring.md#rules)
* **Un modello linguistico**, facoltativo, dà un secondo parere sui casi dubbi: un modello locale tramite Ollama o qualsiasi server compatibile con OpenAI, oppure Claude, ChatGPT, Gemini e altri. [Modelli linguistici](llm.md)


## Da dove iniziare

* [Primi passi](getting-started.md): installarlo e analizzare un primo messaggio.
* [Riga di comando](cli.md): ogni comando e opzione.
* [Postfix e Sendmail](postfix.md): filtrare un server di posta con il milter o un content filter.
* [Altri server di posta](mail-servers.md): Exim, Haraka, Dovecot, procmail e qualsiasi cosa possa chiamare un'API HTTP.
* [Addestramento](training.md): insegnargli la tua posta e misurare il risultato.
* [Modelli linguistici](llm.md): provider, modelli aperti consigliati, privacy e prompt injection.
* [Lingue](languages.md): come legge il cinese, l'arabo, il thailandese e ogni altro sistema di scrittura.
* [Forward Email](forward-email.md): come lo usa Forward Email, e l'aggiornamento dalla versione 5 o 6.
* [Riferimento API](api.md) e [test e punteggi](scoring.md).
* [Sicurezza e privacy](security.md): cosa lascia la macchina e come impedirlo.
