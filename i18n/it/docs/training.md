<!-- source: 7cc30ff4ad91 -->

# Addestramento

Il modello incluso funziona subito. Un modello addestrato sulla tua posta funziona meglio, perché impara com'è fatto il tuo ham: le tue newsletter, lo stile dei tuoi colleghi, le lingue in cui ricevi posta.


## Addestrare un modello

Indica a `train` le cartelle di spam e di ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Le sorgenti possono essere:

* file **mbox**, anche compressi con gzip (`.mbox.gz`),
* una **Maildir** (vengono lette le sue cartelle `cur` e `new`, `tmp` viene saltata),
* una **cartella** di file `.eml`, letta ricorsivamente,
* un **dataset**: un file CSV o JSON Lines con una colonna di testo e una colonna di etichette (`--dataset`). Le colonne chiamate `text`, `message`, `body`, `email` o `content`, e `label`, `category`, `class`, `spam` o `is_spam`, vengono individuate automaticamente; altrimenti usa `--text-column` e `--label-column`. Etichette come `spam`, `1`, `phishing` e `ham`, `0`, `not_spam`, `legitimate` vengono riconosciute.

I messaggi duplicati vengono contati una volta sola. Per partire dal modello incluso invece che da un modello vuoto, aggiungi `--merge`.

Usare il modello:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Quanta posta basta: qualche centinaio di messaggi di ciascun tipo danno un modello utile, qualche migliaio un buon modello. Mantieni i due tipi più o meno bilanciati, e tieni nell'ham la posta che non vuoi filtrare (reimpostazioni della password, fatture dei tuoi fornitori).


## Misurarlo

Tieni una parte della posta fuori dall'addestramento e misura il modello su di essa:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Il modello incluso su SMS in 21 lingue che non ha mai visto, per la maggior parte in lingue che conosce appena:

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

La precisione indica quanta parte di ciò che chiama spam è davvero spam; il richiamo, quanta parte dello spam intercetta. Qui i messaggi incerti contano come spam mancato, anche se in un'analisi gli altri controlli e il modello linguistico possono ancora intercettarli. Il numero da tenere d'occhio sono i falsi positivi: ham segnato come spam. Nell'esecuzione sopra, il modello è incerto sulla maggior parte di questi messaggi invece di sbagliare, ed è il comportamento previsto per le lingue in cui ha poca posta.

`--json` fornisce gli stessi numeri per gli script.


## Imparare dalle segnalazioni

Quando gli utenti spostano la posta dentro o fuori da una cartella Junk, istruisci il modello un messaggio alla volta:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Il primo `learn` crea il file a partire dal modello incluso. Tramite HTTP, `POST /learn/spam` e `/learn/ham` dell'[API HTTP](http-api.md) fanno lo stesso, e `spamc -L spam` funziona con il [server spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) avviato con `--allow-tell`. L'[IMAPSieve di Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) può chiamare l'uno o l'altro quando un messaggio viene spostato.

Da Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Un messaggio segnalato come classificato male, se era già stato appreso, va prima disimparato dalla classe sbagliata e poi appreso in quella giusta.


## Il modello incluso

`model/classifier.json` viene generato da `npm run model:train` a partire da questi dataset pubblici su Hugging Face, tutti con licenze aperte:

| Dataset                                                                                                                                                                                                                                                                                                                    | Licenza                    | Contenuto                      |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------ |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                 | Messaggi ed email in 43 lingue |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Corpus pubblico di ricerca | Il corpus Enron-Spam           |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                    | Messaggi Telegram in russo     |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                        | Messaggi sintetici             |

Ha imparato da 62.480 messaggi di spam e 76.489 di ham. Lo script esclude un messaggio ogni dieci, addestra sul resto e misura il solo classificatore, senza gli altri controlli:

| Test sui messaggi esclusi | Messaggi | Precisione | Richiamo | Falsi positivi | Incerti |
| ------------------------- | -------: | ---------: | -------: | -------------: | ------: |
| Inglese                   |    6.564 |     100,0% |    97,0% |           0,0% |    2,4% |
| Russo                     |    1.682 |     100,0% |    97,4% |           0,0% |    2,2% |
| Italiano                  |    1.389 |      98,1% |    85,3% |           1,8% |   10,9% |
| Tedesco                   |    1.309 |      97,7% |    76,1% |           2,2% |   20,7% |
| Spagnolo                  |    1.281 |      97,5% |    82,5% |           2,6% |   16,8% |
| Enron-Spam                |    2.888 |     100,0% |    93,1% |           0,0% |    4,5% |
| all-scam-spam             |    4.236 |     100,0% |    88,8% |           0,0% |   11,2% |
| Tutti                     |   13.840 |      99,2% |    85,1% |           0,5% |   12,4% |

Qui spam significa una probabilità del classificatore pari o superiore al 99%, il punto in cui il solo classificatore raggiunge la soglia di spam. In un'analisi, lo spam di cui è meno sicuro riceve comunque punti, e gli altri controlli aggiungono i loro.

I risultati per tedesco, spagnolo e italiano provengono da dataset sintetici, che contengono messaggi quasi identici etichettati sia come spam sia come ham: parte di quell'errore sta nelle etichette, non nel modello. La posta nelle tue lingue è il rimedio migliore. I numeri, con ogni lingua e dataset, sono in `metadata.metrics` del modello.

### Altre lingue

`npm run model:train -- --with multilingual-sms` aggiunge la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): la SMS Spam Collection tradotta automaticamente in 21 lingue. È esclusa dal modello incluso perché la sua scheda indica una licenza GPL; verifica che sia compatibile con il modo in cui condividi il modello. Addestrando anche su di essa, i risultati sui messaggi esclusi per le lingue che il modello incluso conosce appena sono stati:

| Lingua     | Messaggi | Precisione | Richiamo | Falsi positivi |
| ---------- | -------: | ---------: | -------: | -------------: |
| Cinese     |      430 |     100,0% |    82,3% |           0,0% |
| Arabo      |      430 |     100,0% |    84,6% |           0,0% |
| Coreano    |      412 |     100,0% |    80,4% |           0,0% |
| Giapponese |      486 |      96,0% |    85,7% |           0,5% |
| Hindi      |      412 |     100,0% |    63,9% |           0,0% |
| Francese   |      480 |      98,6% |    94,2% |           0,6% |
| Turco      |      220 |     100,0% |    73,1% |           0,0% |

### Riaddestrarlo

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Il file del modello

Un modello è un file JSON: il numero di messaggi di spam e di ham appresi e, per ogni feature sottoposta a hash, quanti messaggi di spam e di ham la contenevano, ordinati e codificati in base64. Non contiene parole né testo dei messaggi. `--max-features` mantiene solo le feature più frequenti e `--min-count` elimina quelle rare, sacrificando precisione in cambio di dimensioni ridotte; il modello incluso mantiene 400.000 feature in circa 6 MB.

I modelli di Spam Scanner 6 e precedenti non si possono caricare: usavano hash di feature diverse. Addestrane uno nuovo dalla stessa posta.
