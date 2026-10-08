<!-- source: 6f6b765c5fc1 -->

# Test e punteggi

Un messaggio è spam a 5 punti e viene rifiutato a 15. Ogni test qui sotto aggiunge o toglie punti; il risultato elenca quelli scattati.

Modifica le soglie con `threshold` e `rejectThreshold`. Modifica i punti con `scores`, tramite la chiave di impostazione (`scores: {deceptiveLink: 4}`) oppure tramite il nome del test, che fissa i punti di quel test (`scores: {FROM_NAME_BRAND: 4}`).


## Classificatore

| Test                        | Punti           | Significato                                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| da `BAYES_00` a `BAYES_999` | da -2,5 a +6,25 | La probabilità di spam del classificatore, su scala log-odds: 2,4 punti al 90%, 5 al 99% e 6,25 al 99,9%, quindi il classificatore segna lo spam da solo solo quando è sicuro almeno al 99%. Il nome indica la fascia: `BAYES_999` è 99,9% o più, `BAYES_99` dal 99% al 99,9%, `BAYES_50` dal 40% al 60%. Le chiavi di impostazione `bayesHam` e `bayesSpam` fissano i due estremi. |


## Phishing e link

| Test                        | Punti | Chiave di impostazione | Significato                                                               |
| --------------------------- | ----: | ---------------------- | ------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |     5 | `homograph`            | Il dominio di un link imita un marchio con caratteri sosia o scambiati    |
| `MIXED_SCRIPT_DOMAIN`       |     3 | `mixedScriptDomain`    | Un'etichetta di dominio mescola alfabeti diversi                          |
| `BRAND_IN_DOMAIN`           |   1,5 | `brandInDomain`        | Il nome di un marchio dentro il dominio di qualcun altro                  |
| `TYPO_DOMAIN`               |     1 | `typoDomain`           | A una lettera di distanza dal dominio di un marchio                       |
| `DECEPTIVE_LINK`            |     3 | `deceptiveLink`        | Un link mostra un indirizzo e porta a un altro                            |
| `MALICIOUS_DOMAIN`          |     6 | `maliciousDomain`      | Il resolver antimalware di Cloudflare blocca un dominio collegato         |
| `ADULT_DOMAIN`              |     2 | `adultDomain`          | Il resolver per famiglie di Cloudflare blocca un dominio collegato        |
| `URIBL_<LIST>`              |     5 | `uriblListed`          | Un dominio collegato è in una blocklist di domini, ad esempio `URIBL_DBL` |


## Allegati

| Test                    | Punti | Chiave di impostazione                   | Significato                                                  |
| ----------------------- | ----: | ---------------------------------------- | ------------------------------------------------------------ |
| `EXECUTABLE_ATTACHMENT` |    10 | `executable`                             | Un programma o uno script                                    |
| `DISGUISED_EXECUTABLE`  |    12 | `disguisedExecutable`                    | Un programma con il nome di un documento o di un'immagine    |
| `DOUBLE_EXTENSION`      |     6 | `doubleExtension`                        | Un nome come `invoice.pdf.exe`                               |
| `RTL_OVERRIDE_FILENAME` |     6 | `rtlOverride`                            | Un override da destra a sinistra nasconde la vera estensione |
| `EXECUTABLE_IN_ARCHIVE` |     8 | `executableInArchive`                    | Un programma dentro un file ZIP                              |
| `ENCRYPTED_ARCHIVE`     |     2 | `encryptedArchive`                       | Un archivio che gli scanner non possono aprire               |
| `MACRO_ATTACHMENT`      |     4 | `macro`                                  | Un file Office con macro                                     |
| `PDF_ACTIVE_CONTENT`    |     3 | `pdfActive`                              | Un PDF con JavaScript, azioni di avvio o file incorporati    |
| `RTF_EMBEDDED_OBJECT`   |     4 | `rtfObject`                              | Un file RTF con oggetti incorporati                          |
| `HTML_ATTACHMENT`       | 1 o 3 | `htmlAttachment`, `activeHtmlAttachment` | Un file HTML; 3 quando contiene script o moduli              |
| `VIRUS`                 |   100 | `virus`                                  | ClamAV ha trovato un virus                                   |


## Regole

| Test                      | Punti | Significato                                                                                                |
| ------------------------- | ----: | ---------------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |  1000 | La stringa di test GTUBE                                                                                   |
| `SEXTORTION_SUBJECT`      |     6 | Un oggetto usato dalle truffe di sextortion e di furto dell'account                                        |
| `PAYPAL_INVOICE`          |     6 | Una fattura o una richiesta di denaro PayPal, un canale sfruttato per le truffe                            |
| `MICROSOFT_SPAM_VERDICT`  |     5 | Microsoft ha segnato il messaggio come spam prima di inoltrarlo (attendibile solo dai server di Microsoft) |
| `MICROSOFT_HIGH_SCL`      |     3 | Microsoft gli ha assegnato un livello di confidenza di spam elevato (vale lo stesso)                       |
| `PROMPT_INJECTION`        |     3 | Testo rivolto a un filtro IA                                                                               |
| `SELF_SPOOF`              |     3 | Dichiara di provenire dal dominio del destinatario e non si autentica                                      |
| `FROM_NAME_OTHER_ADDRESS` |   2,5 | Il nome visualizzato contiene un indirizzo email diverso                                                   |
| `FROM_NAME_BRAND`         |     2 | Il nome visualizzato si spaccia per un marchio a cui l'indirizzo non appartiene                            |
| `DATE_IN_FUTURE`          |     1 | Datato più di un giorno avanti                                                                             |
| `MISSING_DATE`            |   0,5 | Nessuna intestazione Date                                                                                  |
| `MISSING_MESSAGE_ID`      |   0,5 | Nessuna intestazione Message-ID                                                                            |

Le regole che valgono almeno quanto la soglia di spam compaiono anche in `results.arbitrary`, come nelle versioni precedenti.


## Offuscamento e lingua

| Test                   | Punti | Chiave di impostazione | Significato                                                        |
| ---------------------- | ----: | ---------------------- | ------------------------------------------------------------------ |
| `INVISIBLE_CHARACTERS` |     2 | `invisibleCharacters`  | Tre o più caratteri invisibili all'interno del testo               |
| `MIXED_SCRIPT_WORDS`   |   2,5 | `mixedScriptWords`     | Due o più parole mescolano lettere di alfabeti diversi             |
| `STYLED_LETTERS`       |   1,5 | `styledLetters`        | Lettere matematiche o racchiuse che si spacciano per testo normale |
| `LANGUAGE_NOT_ALLOWED` |     3 | `languageNotAllowed`   | Non è in `allowedLanguages`                                        |


## Autenticazione

Richiede l'indirizzo IP del client e `authentication: true`.

| Test           | Punti | Chiave di impostazione (in `authentication.weights`) |
| -------------- | ----: | ---------------------------------------------------- |
| `SPF_PASS`     |  -0,5 | `spfPass`                                            |
| `SPF_FAIL`     |     2 | `spfFail`                                            |
| `SPF_SOFTFAIL` |     1 | `spfSoftfail`                                        |
| `DKIM_PASS`    |  -0,5 | `dkimPass`                                           |
| `DKIM_FAIL`    |     1 | `dkimFail`                                           |
| `DMARC_PASS`   |  -1,5 | `dmarcPass`                                          |
| `DMARC_FAIL`   |   3,5 | `dmarcFail`                                          |
| `ARC_PASS`     |  -0,5 | `arcPass`                                            |
| `ARC_FAIL`     |     1 | `arcFail`                                            |


## Reputazione e blocklist

| Test           | Punti | Chiave di impostazione | Significato                                                                   |
| -------------- | ----: | ---------------------- | ----------------------------------------------------------------------------- |
| `DENYLISTED`   |   100 | `denylisted`           | L'indirizzo IP, il dominio o l'indirizzo del mittente è nella lista di blocco |
| `ALLOWLISTED`  |   -20 | `allowlisted`          | È nella lista di consenso                                                     |
| `TRUTH_SOURCE` |    -5 | `truthSource`          | Un servizio di reputazione segna il mittente come attendibile                 |
| `RBL_<LIST>`   |     4 | `rblListed`            | L'indirizzo IP del client è in una blocklist, ad esempio `RBL_ZEN`            |


## Modello linguistico e modelli facoltativi

| Test                                                  | Punti     | Chiave di impostazione | Significato                                                   |
| ----------------------------------------------------- | --------- | ---------------------- | ------------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | fino a +6 | `llmSpam`              | Il verdetto del modello, moltiplicato per la sua confidenza   |
| `LLM_HAM`                                             | fino a -3 | `llmHam`               | Vale lo stesso                                                |
| `TOXIC_CONTENT`                                       | 3         | `toxicity`             | Un modello di tossicità fornito da te ha segnalato il testo   |
| `NSFW_IMAGE`                                          | 3         | `nsfw`                 | Un modello di immagini fornito da te ha segnalato un'immagine |
