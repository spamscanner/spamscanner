<!-- source: e15795fd8287 -->

# Riferimento API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Crea un solo scanner e riutilizzalo: carica il modello una volta e mantiene in cache le risposte DNS e del modello linguistico.

Le dichiarazioni di tipo sono incluse. Richiedono TypeScript 4.7 o successivo con `import`, e 5.3 o successivo con `require`.


## Opzioni

Ogni opzione si può passare al costruttore. La maggior parte si può passare anche a `scan()` per un singolo messaggio, e in quel caso viene unita a quelle del costruttore, con la precedenza. Le opzioni passate come `undefined` mantengono il valore predefinito. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` e `strictIDNDetection` sono letti solo dal costruttore; un file o un oggetto di modello dato come `classifier` viene letto lì, quindi un modello mancante o danneggiato genera subito un errore.

| Opzione                 | Predefinito                      | Significato                                                                                                                                                                                                           |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Punteggio a cui un messaggio è spam                                                                                                                                                                                   |
| `rejectThreshold`       | `15`                             | Punteggio a cui `action` è `reject`                                                                                                                                                                                   |
| `scores`                | `{}`                             | Punti per test: chiavi di impostazione o nomi dei test ([test e punteggi](scoring.md))                                                                                                                                |
| `classifier`            | modello incluso                  | Un `Classifier`, un oggetto modello, il percorso di un file di modello o `false`                                                                                                                                      |
| `classifierOptions`     | `{}`                             | Opzioni per il modello incluso (vedi [Classifier](#classifier))                                                                                                                                                       |
| `allowedLanguages`      | `[]`                             | Codici ISO 639-1 (`no` è letto come `nb`, `fil` come `tl`, e i vecchi `iw`, `in`, `ji` come `he`, `id`, `yi`); le altre lingue ricevono `LANGUAGE_NOT_ALLOWED`                                                        |
| `phishing.cloudflare`   | `true`                           | Interroga i resolver con filtraggio di Cloudflare sugli host dei link                                                                                                                                                 |
| `phishing.adult`        | `true`                           | Interroga anche il resolver per famiglie, che blocca i siti per adulti                                                                                                                                                |
| `phishing.maxHosts`     | `25`                             | Host dei link cercati per messaggio                                                                                                                                                                                   |
| `phishing.maxLength`    | `1000000`                        | Caratteri del testo letti per cercare i link (il doppio per l'HTML); un testo più lungo imposta `results.linksTruncated`; `Infinity`, o qualsiasi valore che non sia un numero positivo, indica il valore predefinito |
| `phishing.homograph`    | `{}`                             | `brands` (sostituisce l'elenco integrato), `extraBrands`, `allowlist` (domini mai segnalati), `strictMode`                                                                                                            |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zone di DNS blocklist per l'IP del client e per i domini dei link                                                                                                                                                     |
| `dns`                   | `{servers: null, timeout: 3000}` | Name server per i controlli DNS (predefiniti: quelli del sistema)                                                                                                                                                     |
| `attachments`           | `true`                           | Esamina gli allegati                                                                                                                                                                                                  |
| `macros`                | `true`                           | Segnala macro, PDF attivi e oggetti RTF                                                                                                                                                                               |
| `arbitrary`             | `true`                           | Esegue le [regole](scoring.md#rules)                                                                                                                                                                                  |
| `authentication`        | `false`                          | `true`, oppure `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([punteggio](scoring.md#authentication))                                                                |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; le risposte vengono conservate per servizio e intestazioni, e `cacheSize` vale per l'intero scanner                              |
| `allowlist`, `denylist` |                                  | Indirizzi IP, domini o indirizzi; forma abbreviata di `reputation` → [Lista consentiti e lista di blocco](#allowlist-and-denylist)                                                                                    |
| `clamav`                | `false`                          | `true` (socket predefinito), `{socket}` o `{host, port}`, con `timeout`: millisecondi per tutti gli allegati di un messaggio (`60000`)                                                                                |
| `llm`                   | `null`                           | [Impostazioni del modello linguistico](llm.md#any-server-port-and-authentication), con `mode`, `minScore`, `maxScore`                                                                                                 |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: un modello il cui `classify([text])` risponde come `@tensorflow-models/toxicity`                                                                                                          |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: un modello il cui `classify(imageBuffer)` risponde come `nsfwjs`                                                                                                                          |
| `maxLength`             | `100000`                         | Caratteri del testo del corpo letti                                                                                                                                                                                   |
| `timeout`               | `10000`                          | Millisecondi concessi a ogni controllo di rete; l'autenticazione e il modello per le immagini hanno questo tempo in totale (ClamAV ha il proprio `clamav.timeout`)                                                    |
| `session`               | `{}`                             | Dettagli predefiniti della sessione SMTP                                                                                                                                                                              |

`scan()` accetta anche `session`:

```js
await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',             // the client's IP address
    resolvedClientHostname: 'mx.example.com', // its verified reverse DNS name
    helo: 'mx.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

Un server che ha già verificato SPF, DKIM, DMARC e ARC (con [mailauth](https://github.com/postalsys/mailauth)) può passarne i risultati come `authenticationResults`, che vengono conteggiati nel punteggio invece di essere verificati di nuovo:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Lista consentiti e lista di blocco

La lista di blocco confronta l'indirizzo IP e il nome host del client, gli indirizzi From, del mittente della busta e Reply-To, e i loro domini, qualunque essi siano: un nome sotto un dominio nella lista di blocco vi corrisponde anche se non è un nome host valido (come `a_b!.evil.example`, o uno con un'etichetta di più di 63 caratteri), in base alle sue ultime 127 etichette e ai suoi ultimi 253 caratteri. La lista consentiti, e la lista consentiti e le fonti attendibili di un servizio di reputazione, confrontano solo ciò che un mittente non può falsificare: l'indirizzo IP e il nome host verificato del client (`remoteAddress`, `resolvedClientHostname`), un indirizzo From quando DMARC supera la verifica per il suo dominio o una firma DKIM valida è allineata con esso (ed è un nome host valido; in modo rilassato, come in DMARC: il dominio From e il dominio firmatario o SPF hanno lo stesso dominio registrabile, che mailauth indica come dominio DMARC; una voce che indica un sottodominio, come `news.example.com`, conta solo quando quel dominio, uno sotto di esso o uno sopra di esso ha firmato il messaggio o superato SPF, non un altro sottodominio come `evil.example.com`, né un suffisso pubblico; una verifica DMARC superata per il dominio registrabile senza i dettagli di allineamento di mailauth conta solo per una voce che indica il dominio registrabile; con l'allineamento rigoroso, `adkim=s` o `aspf=s` nel record DMARC del dominio, con qualsiasi uso di maiuscole o spazi, conta solo una firma o una verifica SPF superata del dominio From stesso, e senza di essa DMARC fallisce), e il mittente della busta quando SPF supera la verifica per il suo dominio. Una firma DKIM solo dell'inizio del corpo (una lunghezza del corpo, `l=`, più corta del corpo: chiunque può aggiungere testo dopo) non conta nulla, così come una verifica DMARC superata che si basa su di essa, e nessuna firma conta quando DMARC fallisce, né per un campo From troppo lungo per essere letto per intero (`mail.from.truncated`). I risultati passati in `authenticationResults` contano solo quando indicano il dominio per cui hanno superato la verifica, e un dominio che non è un nome host (come `bank.example/x.attacker.example`, che i parser di URL leggono come `bank.example`) non conta per nessuno, così come una verifica DMARC superata che si basa su di esso. I domini internazionali corrispondono in entrambe le forme: `bücher.example` o `xn--bcher-kva.example`. Reply-To non conta mai. Per consentire un dominio, attivate `authentication` o passate `authenticationResults`.

Ogni voce è un singolo indirizzo IP, dominio o indirizzo email, confrontato in modo esatto: una voce di dominio copre anche i suoi sottodomini e gli indirizzi su di essi, ma non esistono intervalli di indirizzi (`192.0.2.0/24`), caratteri jolly (`*.example.com`) o pattern (`@example.com`). Gli indirizzi IPv6 corrispondono in qualsiasi forma (`2001:0db8::0001` è `2001:db8::1`, la forma della RFC 5952), un indirizzo IPv4 mappato in IPv6 (`::ffff:192.0.2.1`) corrisponde all'indirizzo IPv4, e un indirizzo IPv4 tradotto in IPv6 o sotto il prefisso NAT64 si scrive con l'indirizzo IPv4 in forma puntata (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), sia nelle voci sia negli indirizzi dei client.


## Metodi

| Metodo                               | Restituisce                                                                            |
| ------------------------------------ | -------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Il risultato. `source` è un Buffer, una stringa, un Uint8Array o uno stream leggibile  |
| `scanFile(path, options)`            | Il risultato per un file di messaggio                                                  |
| `learn(source, 'spam' \| 'ham')`     | Insegna un messaggio al classificatore                                                 |
| `unlearn(source, 'spam' \| 'ham')`   | Annulla `learn`                                                                        |
| `saveModel(path, options)`           | Scrive il classificatore in un file (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Il `Classifier` in uso, o `null`                                                       |
| `getClassification(features)`        | Il verdetto del classificatore per le feature restituite da `getFeatures`              |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` di un messaggio      |
| `getTokens(text, locale)`            | Le parole di un testo                                                                  |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                             |
| `parse(source)`                      | `{raw, mail, error}`, con `mail` prodotto da mailparser (vedi sotto)                   |

`scan`, `parse`, `learn`, `unlearn` e `getTokensAndMailFromSource` leggono tutti un messaggio allo stesso modo: uno che supera i limiti del parser MIME (più di 1000 parti, l'intestazione di una parte oltre 1 MB) viene letto fin dove il parser lo consente. I campi di indirizzo (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To e List-\*), del messaggio, delle sue parti e dei messaggi allegati, vengono letti fino a 16 KB ciascuno, 2000 virgole e punti e virgola e 16 gruppi annidati, e 64 KB in tutto per ogni messaggio, sempre fino alla fine di un indirizzo intero, così non viene letto alcun indirizzo che il campo non contenga; un campo tagliato è segnato `truncated` (`mail.to.truncated`), e un campo From tagliato non dà alcun credito per l'autenticazione del mittente. Un testo la cui prima riga non è un campo di intestazione (`Name: value`, o la riga `From` con cui inizia ogni messaggio nei file mbox) viene letto come il corpo di un messaggio senza intestazione, quindi `mail.text` è quel testo. Gli altri errori vengono sollevati. `parse` indica in `error` il limite del parser che un messaggio supera, come `scan` lo indica in `parseError`, e null per un messaggio letto per intero.

In `getFeatures`, `text` è il testo che mostra un client di posta, da cui vengono lette le parole, e `hidden` il numero di caratteri di testo che l'HTML nasconde. Qui mailparser non ricava testo dall'HTML: `mail.text` contiene solo le parti in testo semplice, ed è vuoto per un messaggio di solo HTML; il testo che mostra il suo HTML è `getFeatures(mail).text`.

`scanner.metrics` contiene `totalScans`, `averageTime` e `lastScanTime`.


## Il risultato

```js
{
  isSpam: true,
  score: 16.25,
  threshold: 5,
  rejectThreshold: 15,
  action: 'reject',                       // 'accept', 'tag' or 'reject'
  message: 'Spam (BAYES_999, PHISHING_LOOKALIKE_DOMAIN, DECEPTIVE_LINK, FROM_NAME_BRAND)',
  tests: [
    {name: 'BAYES_999', score: 6.25, description: 'Classifier spam probability 99.9%'},
    {name: 'PHISHING_LOOKALIKE_DOMAIN', score: 5, description: '"paypa1-secure.top" imitates paypal by swapping characters'},
    // ...
  ],
  results: {
    classification: {probability, category, spam, ham, clues, coverage},
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    virusScanErrors: [], // attachments ClamAV could not scan: {filename, error}
    virusScanSkipped: [], // attachments larger than clamd accepts, not scanned: {filename, reason}
    unopenedAttachments: [], // attached messages not opened, past the limits they are read within: {filename, reason}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value, answers} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'], // the links checked, of the whole message up to phishing.maxLength
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser; mail.text: the plain text parts only */},
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

I rilevamenti in `phishing`, `attachments`, `executables`, `macros`, `viruses` e `arbitrary` sono oggetti con un `type` e un `message`. `String(finding)` è il messaggio. Gli allegati di un messaggio allegato (`message/rfc822`, `.eml`) prendono il suo nome: `fw.eml/invoice.exe`. Un virus che ClamAV trova in un allegato simile viene segnalato solo per esso, non di nuovo per il messaggio allegato che lo contiene. `virusScanErrors` elenca gli allegati che ClamAV non ha potuto analizzare, come `{filename, error}`: un messaggio simile può contenere un virus, quindi trattenetelo invece di consegnarlo. Il milter e il filtro dei contenuti lo rinviano, a meno che `onError` (`--on-error`) sia `accept`, e ogni server contrassegna un messaggio simile che lascia passare con `X-Spam-Virus-Scan: failed`. `virusScanSkipped` elenca quelli più grandi di quanto clamd accetti (il suo `StreamMaxLength`), come `{filename, reason}`: clamd li rifiuta a ogni tentativo, quindi, così come clamav-milter salta un file oltre il suo `MaxFileSize`, non sono errori. Gli altri suoi limiti (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), che una bomba di archivio raggiunge, sono errori. I messaggi allegati vengono aperti fino a tre livelli, con al massimo 100 allegati al loro interno e 25 MB in tutto; `unopenedAttachments` elenca quelli non aperti oltre questi limiti, come `{filename, reason}`, i cui allegati non sono stati ispezionati. Non conta nel punteggio, perché i messaggi inoltrati possono essere annidati così, ma chi ha bisogno di un messaggio letto per intero, ad esempio per bloccare un programma che contiene, può rifiutarne uno che ne abbia.

Ogni elemento di `dnsbl` riporta le `answers` della lista (indirizzi in 127.0.0.0/8, il cui significato è documentato da ciascuna lista). Le risposte che le liste danno alle query che rifiutano o a cui non possono rispondere non sono inserimenti in lista, né per l'indirizzo del client né per i domini dei link (rilevamenti `uribl` in `phishing`): 127.255.255.x presso Spamhaus (come 127.255.255.254 per una query tramite un resolver pubblico, e 127.255.255.255 per troppe query), 127.0.1.255 presso la DBL di Spamhaus, 127.0.0.255 presso qualsiasi lista, e 127.0.0.1 presso SURBL e URIBL, che la restituiscono ai resolver che bloccano.


## Esportazioni

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, unwrapLink, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export
// unwrapLink(address): the URL a link goes to, through Safe Links and
// Proofpoint URL Defense, as the scanner reads it (null for no URL)

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Opzione                                | Predefinito    | Significato                                                                                                                                                  |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `strength`, `unknown`                  | `0.45`, `0.5`  | I parametri s e x di Robinson: quanto le feature rare vengono spinte verso 0,5                                                                               |
| `minDistance`                          | `0.1`          | Le feature più vicine a 0,5 di questo valore vengono ignorate                                                                                                |
| `maxClues`                             | `150`          | Feature più forti combinate per messaggio                                                                                                                    |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Limiti dell'intervallo `unsure`                                                                                                                              |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Messaggi ham necessari in una lingua per la piena confidenza, e un quinto di messaggi spam; meno quando `languageShare` di tutto l'ham o lo spam è inferiore |
| `languagePrior`                        | `true`         | Pesa le parole rispetto ai conteggi della loro lingua                                                                                                        |

Sono disponibili anche `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` e `entries()`. `Classifier.fromJSON` controlla il modello e genera un `TypeError` che inizia con `Corrupt classifier model` su dati danneggiati. JSON non ha `Infinity`, quindi un'opzione salvata come `Infinity` dalla versione 7.0.3 viene riletta come `null`: viene letta come `Infinity` per `maxClues`, `minDistance` e `minLanguageExamples`, come `-Infinity` per `hamCutoff` (mai ham) e `Infinity` per `spamCutoff` (mai spam), e come il valore predefinito per le altre. `toJSON` salva una soglia oltre 0 e 1 come -1 o 2, il che funziona allo stesso modo. `loadModel` rilegge un file quando cambia, e `saveModel` scrive tramite un nuovo file temporaneo, scaricato su disco prima che sostituisca il modello, che mantiene i suoi permessi.

### Addestramento

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` accetta elementi `{label, features}`, oppure `readExamples(sources)`, che legge le stesse sorgenti di `train`, e restituisce i conteggi, precisione, richiamo, F1, accuratezza e i tassi di falsi positivi, falsi negativi e incerti.

### Server

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

L'opzione `onError` del milter è la sua risposta quando un'analisi fallisce o ClamAV non ha potuto analizzare un allegato: `'tempfail'` (il valore predefinito) o `'accept'`, che lascia passare il messaggio contrassegnato con `X-Spam-Virus-Scan: failed`, senza le intestazioni `X-Spam-*` aggiunte dal mittente.

### Report ARF

`spamscanner/arf` legge e scrive gli abuse feedback report (RFC 5965), il formato che i provider di caselle di posta usano per segnalare i reclami per spam:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders?.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`parse()` accetta un Buffer, un Uint8Array o una stringa. `ArfParser.tryParse()` restituisce `null` invece di generare un'eccezione per i messaggi che non sono report, e `isArfMessage(mail)` verifica un messaggio già interpretato. `originalHeaders` è `null` per un report senza il messaggio originale. `create()` restituisce una stringa, oppure un `Buffer` quando lo è `originalMessage`, così i suoi byte vengono conservati qualunque sia il set di caratteri.
