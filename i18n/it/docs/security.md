<!-- source: 60f00f92b5aa -->

# Sicurezza e privacy

Spam Scanner legge la posta, che è privata, proveniente da mittenti che possono essere ostili. Questa pagina elenca cosa invia all'esterno e come tratta ciò che legge.


## Cosa lascia la macchina

Per impostazione predefinita, una cosa sola: i **nomi host dei link** in un messaggio vengono cercati sui resolver con filtraggio di Cloudflare, 1.1.1.2 e 1.0.0.2 (malware e phishing) e 1.1.1.3 e 1.0.0.3 (anche contenuti per adulti). Sono normali query DNS per nomi come `example.com`; non viene inviata nessuna parte del messaggio o dei suoi indirizzi. Disattivale con `phishing: {cloudflare: false}` o `--no-cloudflare`, oppure disattiva solo il controllo per adulti con `phishing: {adult: false}`.

Tutto il resto è disattivato finché non viene configurato:

| Controllo           | Invia                                                                          | A                                                                         |
| ------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------- |
| `authentication`    | Query DNS per i record SPF, DKIM, DMARC e ARC del mittente                     | Il tuo resolver, o `dnsServers`                                           |
| `dnsbl`             | L'indirizzo IP del client, invertito, e i domini dei link, come query DNS      | I name server delle blocklist, tramite il tuo resolver o `dns.servers`    |
| `llm`               | Un riassunto del messaggio, con i dati personali rimossi per i provider remoti | Il server del modello linguistico che indichi ([privacy](llm.md#privacy)) |
| `reputation.apiUrl` | L'indirizzo IP, il dominio e l'indirizzo del mittente                          | Il servizio che indichi                                                   |
| `clamav`            | Gli allegati                                                                   | Il tuo clamd, tramite il suo socket                                       |

Non c'è telemetria, nessun controllo degli aggiornamenti e nessun download durante l'esecuzione. Il modello è incluso nel pacchetto.


## Cosa conserva

Niente, se non richiesto. Le analisi non vengono registrate né archiviate. `learn()` modifica il classificatore in memoria; viene scritto su disco solo da `saveModel()`, `spamscanner learn` o dall'opzione `--out` dei server. Un file di modello contiene conteggi di feature sottoposti a hash, non parole né testo dei messaggi.

Le risposte del modello linguistico vengono memorizzate in cache in memoria, indicizzate da un hash di ciò che è stato inviato, quindi le copie ripetute dello stesso messaggio vengono sottoposte al modello una volta sola. Le risposte DNS restano in cache in memoria per dieci minuti.


## Input ostile

* Gli allegati vengono identificati dai loro byte, mai eseguiti o aperti da un altro programma. Gli archivi ZIP vengono letti dalla loro directory centrale, con un limite al numero di voci; gli archivi annidati non vengono estratti.
* Il testo del corpo viene letto fino a `maxLength` (100.000 caratteri) e i server accettano messaggi fino a 25 MB.
* Ogni controllo di rete ha un timeout (`timeout`, 10 secondi per impostazione predefinita). Un controllo che fallisce o va in timeout viene saltato e l'analisi si conclude senza di esso.
* Le intestazioni `X-Spam-*` già presenti in un messaggio vengono rimosse dal milter, dal content filter e da `--headers`, quindi i mittenti non possono segnare la propria posta come pulita.
* Le intestazioni con il verdetto antispam di Microsoft sono considerate attendibili solo quando il messaggio arriva direttamente dai server di Microsoft, e le intestazioni Received non vengono mai usate per stabilire da dove proviene un messaggio.
* Il testo che si rivolge ai filtri IA riceve punti di spam, e al modello linguistico viene detto che il messaggio è un dato, non un'istruzione. [Prompt injection](llm.md#prompt-injection)


## Server

I server milter, HTTP, TCP e spamd sono in ascolto su 127.0.0.1, salvo diversa indicazione di `--host`. L'API HTTP confronta il suo token in tempo costante e rifiuta `/learn` senza token. Nessuno di essi supporta TLS: per raggiungerli attraverso una rete, usa una rete privata, un tunnel SSH o un reverse proxy con TLS.

Eseguili con un utente non privilegiato. L'[unità systemd nella guida a Postfix](postfix.md#1-run-the-milter) aggiunge le consuete misure di hardening.


## Segnalare una vulnerabilità

Segnala i problemi di sicurezza in privato tramite la [segnalazione delle vulnerabilità di GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), non nelle issue pubbliche.
