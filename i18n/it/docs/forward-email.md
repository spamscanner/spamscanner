<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner è stato sviluppato da [Forward Email](https://forwardemail.net), il servizio email open source attento alla privacy, per i propri server di posta. Forward Email non conserva log del contenuto dei messaggi, quindi nessun servizio di filtraggio esterno era adatto: il filtro doveva girare sui suoi server e doveva spiegare ogni decisione senza che una persona leggesse la posta.

Questa pagina mostra come lo usa un server di posta come quello di Forward Email, e cosa è cambiato per il codice scritto per Spam Scanner 5 o 6.


## Su un server di posta in entrata

Forward Email riceve la posta con [smtp-server](https://nodemailer.com/extras/smtp-server/). Lo schema, per qualsiasi server basato su di esso:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()` accetta direttamente lo stream SMTP. Se hai già a disposizione i risultati di [mailauth](https://github.com/postalsys/mailauth), tralascia `authentication` e passa solo l'indirizzo IP.

Una risposta 421 o 451 fa sì che il server mittente metta in coda il messaggio e riprovi più tardi. Le nuove regole di rifiuto possono iniziare con un codice temporaneo e passare a 550 dopo aver verificato i risultati, senza perdere posta nel frattempo.


## Aggiornamento dalla versione 5 o 6

La versione 7 è una riscrittura. Il costruttore, `scan()` e i campi del risultato letti dal codice delle versioni 5 e 6 funzionano ancora; sono cambiati il classificatore, il modello e i controlli facoltativi basati su TensorFlow.

### Cosa resta uguale

* `new SpamScanner(options)` e `await scanner.scan(source)`.
* `require('spamscanner')` restituisce la classe, e `import SpamScanner from 'spamscanner'` funziona.
* `result.isSpam`, `result.message` e `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` e `.idnHomographAttack`.
* Ogni elemento di `results.phishing`, `.executables`, `.arbitrary` e `.viruses` si converte nello stesso tipo di stringa di messaggio di prima (`String(item)`, template literal, `message.includes('adult-related content')`). Ora sono oggetti con `type`, `message` e dettagli.
* `getTokensAndMailFromSource()`, `getClassification()` e `getTokens()`.
* Queste opzioni corrispondono ai loro nuovi nomi: `clamscan` a `clamav`, `enableMacroDetection: false` a `macros: false`, `enableArbitraryDetection: false` a `arbitrary: false`, `enableAuthentication` con `authOptions` a `authentication` e `session`, `enableReputation` con `reputationOptions.apiUrl` a `reputation`, `strictIDNDetection` a `phishing.homograph.strictMode`, e `allowlist` e `denylist`. `logger` e `memoize` vengono accettate e ignorate.

### Cosa è cambiato

| Prima                                                                                      | Ora                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` leggeva il file                                                 | Una stringa è testo del messaggio. Usa `scanFile(path)` o passa un Buffer                                                                                                  |
| Un modello naive Bayes di parole (`classifier.json`), ora non caricabile                   | Un nuovo classificatore e un nuovo formato del modello; riaddestra con `spamscanner train` ([addestramento](training.md))                                                  |
| I controlli di tossicità e NSFW caricavano modelli TensorFlow dalla rete al primo utilizzo | Porta il tuo modello: `toxicity: {model}` e `nsfw: {model}` accettano qualsiasi oggetto con un metodo `classify()`, ad esempio da `@tensorflow-models/toxicity` e `nsfwjs` |
| `results.arbitrary` elencava ogni schema corrispondente                                    | Elenca le regole abbastanza forti da segnare lo spam da sole; tutte le regole sono in `result.tests`                                                                       |
| Una risposta sì o no                                                                       | `result.score`, `result.action` (`accept`, `tag` o `reject`) e `result.tests`, ciascuno con punti e motivo                                                                 |
| `isSpam` deciso dal classificatore o da un singolo controllo                               | `isSpam` è un punteggio di 5 o più; soglie e punti si possono modificare                                                                                                   |
| Controlli di reputazione su un endpoint di Forward Email                                   | Un servizio di reputazione generico, disattivato se `reputation.apiUrl` non è impostato                                                                                    |

### Novità

* [Modelli linguistici](llm.md) per i casi dubbi, locali o in hosting.
* SPF, DKIM, DMARC e ARC; DNS blocklist; i resolver con filtraggio di Cloudflare.
* Controlli sugli allegati in base al contenuto: eseguibili camuffati, archivi, macro, PDF attivi.
* Un [milter, un'API HTTP, un server TCP e un server spamd](mail-servers.md), e una [riga di comando](cli.md).
* Addestramento, valutazione e apprendimento dalle segnalazioni, dalla riga di comando o dall'API.
