<!-- source: 1d7373f991c2 -->

# Sicurezza e privacy

Spam Scanner legge la posta, che è privata, proveniente da mittenti che possono essere ostili. Questa pagina elenca cosa invia all'esterno e come tratta ciò che legge.


## Cosa lascia la macchina

Per impostazione predefinita, una cosa sola: i **nomi host dei link** in un messaggio vengono cercati sui resolver con filtraggio di Cloudflare, 1.1.1.2 e 1.0.0.2 (malware e phishing) e 1.1.1.3 e 1.0.0.3 (anche contenuti per adulti). Sono normali query DNS per nomi come `example.com`; non viene inviata nessuna parte del messaggio o dei suoi indirizzi. Disattivale con `phishing: {cloudflare: false}` o `--no-cloudflare`, oppure disattiva solo il controllo per adulti con `phishing: {adult: false}`.

Tutto il resto è disattivato finché non viene configurato:

| Controllo           | Invia                                                                                                                             | A                                                                         |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `authentication`    | Query DNS per i record SPF, DKIM, DMARC e ARC del mittente                                                                        | Il tuo resolver, o `dnsServers`                                           |
| `dnsbl`             | L'indirizzo IP del client, invertito, e i domini dei link, come query DNS                                                         | I name server delle blocklist, tramite il tuo resolver o `dns.servers`    |
| `llm`               | Un riassunto del messaggio, con i dati personali rimossi per i provider remoti                                                    | Il server del modello linguistico che indichi ([privacy](llm.md#privacy)) |
| `reputation.apiUrl` | L'indirizzo IP e il nome host verificato del client, e gli indirizzi From, del mittente della busta e Reply-To, con i loro domini | Il servizio che indichi                                                   |
| `clamav`            | Gli allegati                                                                                                                      | Il tuo clamd, tramite il suo socket                                       |

Non c'è telemetria, nessun controllo degli aggiornamenti e nessun download durante l'esecuzione. Il modello è incluso nel pacchetto.


## Cosa conserva

Niente, se non richiesto. Le analisi non vengono registrate né archiviate. `learn()` modifica il classificatore in memoria; viene scritto su disco solo da `saveModel()`, `spamscanner learn` o dall'opzione `--out` dei server. Un file di modello contiene conteggi di feature sottoposti a hash, non parole né testo dei messaggi.

Le risposte del modello linguistico vengono memorizzate in cache in memoria, indicizzate da un hash di ciò che è stato inviato, quindi le copie ripetute dello stesso messaggio vengono sottoposte al modello una volta sola. Le risposte DNS restano in cache in memoria per dieci minuti, e quelle di un servizio di reputazione per cinque (`reputation.cacheTtl`; una richiesta fallita per un minuto).


## Input ostile

* Gli allegati vengono identificati dai loro byte, mai eseguiti o aperti da un altro programma. Gli archivi ZIP vengono letti dalla loro directory centrale, con limiti al numero di voci (2000) e ai byte dei loro nomi (1 MiB; un nome oltre 1 KiB conserva i suoi primi e ultimi 512 byte, e i risultati ne mostrano al massimo 100 caratteri), e ogni voce viene letta una sola volta per quante directory puntino a essa; nulla viene decompresso, quindi i programmi dentro archivi annidati o compressi non vengono visti. I messaggi allegati (`message/rfc822`, o allegati il cui nome di file termina in `.eml`) vengono aperti fino a tre livelli di profondità, per al massimo 100 dei loro allegati e 25 MB di messaggi allegati in tutto; gli allegati del messaggio stesso vengono sempre ispezionati tutti. Un messaggio che supera i limiti del parser MIME (più di 1000 parti, o l'intestazione di una parte oltre 1 MB) viene letto fin dove il parser lo consente (le sue prime parti, con un'intestazione troppo grande ridotta perché il suo mittente conti ancora) e riceve `MIME_TOO_COMPLEX`, che nessun credito compensa; ClamAV lo legge per intero. Anche un messaggio allegato su cui il parser fallisce lo riceve, e non fa mai fallire la scansione. I campi di indirizzo vengono letti fino a 16 KB ciascuno (2000 indirizzi, 16 gruppi annidati) e 64 KB in tutto per ogni messaggio, tagliati solo alla fine di un indirizzo intero, perché il parser degli indirizzi impiega un tempo che cresce con il quadrato del numero di indirizzi; anche mailauth legge From e Return-Path con questi limiti (gli altri campi così come sono, perché una firma su di essi resti valida), e un'intestazione che impiegherebbe più di un tempo lineare a leggere (migliaia di righe ripiegate, o firme che nominano migliaia di campi) viene ridotta. Un campo From tagliato fa fallire DMARC e non fa entrare nulla nell'allowlist. L'HTML viene letto dal parser di Spam Scanner stesso, in tempo lineare, per quanto profondamente sia annidato.
* Il testo del corpo viene letto fino a `maxLength` (100.000 caratteri) e i server accettano messaggi fino a 25 MB. I link vengono letti fino a `phishing.maxLength` (1.000.000 caratteri).
* Ogni controllo di rete ha un timeout (`timeout`, 10 secondi per impostazione predefinita). Un controllo che fallisce o va in timeout viene saltato e l'analisi si conclude senza di esso. L'autenticazione e il modello per le immagini (le prime 10 immagini) terminano ciascuno per intero entro questo limite: l'autenticazione non invia alcuna query DNS dopo di esso, né più di 300 per un messaggio (quanto basta per SPF ai limiti della RFC 7208, con DKIM, ARC, DMARC e BIMI), e controlla solo le prime 8 firme DKIM di un messaggio (mailauth stesso legge al massimo 50 set ARC). L'intestazione `Authentication-Results` aggiunta dal milter contiene al massimo 8 KiB di risultati. ClamAV (quattro allegati alla volta) ha un proprio limite per tutti gli allegati di un messaggio (`clamav.timeout`, 60 secondi), e gli allegati che non ha potuto analizzare sono elencati in `results.virusScanErrors`. Il modello linguistico ha un proprio limite (`llm.timeout`).
* La lista consentiti si fida solo di ciò che un mittente non può falsificare: l'indirizzo e il nome host verificato del client, e i domini mittente che l'autenticazione conferma. [Liste consentiti e di blocco](api.md#allowlist-and-denylist)
* Le intestazioni `X-Spam-*` già presenti in un messaggio vengono rimosse dal milter, dal content filter e da `--headers`, quindi i mittenti non possono segnare la propria posta come pulita.
* Le intestazioni con il verdetto antispam di Microsoft sono considerate attendibili solo quando il messaggio arriva direttamente dai server di Microsoft, e le intestazioni Received non vengono mai usate per stabilire da dove proviene un messaggio.
* Il testo che si rivolge ai filtri IA riceve punti di spam, e al modello linguistico viene detto che il messaggio è un dato, non un'istruzione. [Prompt injection](llm.md#prompt-injection)


## Server

I server milter, HTTP, TCP e spamd sono in ascolto su 127.0.0.1, salvo diversa indicazione di `--host`. L'API HTTP confronta il suo token in tempo costante e rifiuta `/learn` senza token. Nessuno di essi supporta TLS: per raggiungerli attraverso una rete, usa una rete privata, un tunnel SSH o un reverse proxy con TLS.

Eseguili con un utente non privilegiato. L'[unità systemd nella guida a Postfix](postfix.md#1-run-the-milter) aggiunge le consuete misure di hardening.


## Segnalare una vulnerabilità

Segnala i problemi di sicurezza in privato tramite la [segnalazione delle vulnerabilità di GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), non nelle issue pubbliche.
