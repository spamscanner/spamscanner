<!-- source: 9537a0e62eb0 -->

# Lingue

Lo spam arriva in ogni lingua, e così la posta normale. Spam Scanner legge entrambi, ed è prudente con le lingue che conosce poco: un filtro antispam che segnala ogni messaggio in arabo o in cinese è peggio di nessun filtro.


## Leggere ogni sistema di scrittura

* **Parole.** Il testo viene suddiviso con `Intl.Segmenter`, che segue le regole Unicode sui confini delle parole e usa dizionari per cinese, giapponese, thailandese, lao, khmer e birmano, lingue scritte senza spazi. I testi lunghi vengono prima divisi in parti, perché il segmentatore di Node.js 18 rallenta sulle stringhe molto lunghe.
* **Normalizzazione.** La forma Unicode NFKC trasforma le lettere a larghezza piena e la maggior parte delle lettere stilizzate (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) in lettere normali. Il testo viene convertito in minuscolo secondo le regole Unicode.
* **Camuffamenti.** I caratteri invisibili dentro le parole (`free` con uno spazio a larghezza zero tra due lettere, trattini morbidi) vengono rimossi e contati. Le parole che mescolano alfabeti, come `pаypal` con una а cirillica, vengono ricondotte a un solo alfabeto e contate. Le cifre usate come lettere (`v1agra`) vengono convertite. Ogni camuffamento è una feature a sé, e tre o più caratteri invisibili, o due o più parole miste, aggiungono anche punti.


## Rilevare la lingua

La lingua di ogni messaggio viene rilevata dal suo sistema di scrittura e, per i sistemi condivisi da molte lingue, dalle sue lettere:

* L'hangul è coreano; hiragana e katakana indicano il giapponese; thailandese, greco, ebraico, armeno, georgiano, bengali, tamil e gli altri sistemi di scrittura usati da una sola lingua la identificano direttamente.
* Le lettere cirilliche presenti in una sola lingua decidono tra ucraino (і, ї, є, ґ), bielorusso (ў), serbo (ђ, ћ, џ), macedone (ѓ, ќ, ѕ) e russo (ы, э, ё).
* Il testo nei sistemi di scrittura condivisi da più lingue (latino, cirillico, arabo, devanagari e altri), quando è abbastanza lungo da poter essere valutato, passa a [franc](https://github.com/wooorm/franc), limitato alle lingue comuni nella posta elettronica perché i messaggi brevi non vengano etichettati con lingue rare.

La lingua è riportata come `result.language`, e `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) aggiunge 3 punti alla posta rilevata con sicurezza in qualsiasi altra lingua.


## Lingue che il modello conosce poco

Un classificatore impara dagli esempi. I dataset pubblici di spam contengono molto più spam in lingue straniere che ham in lingue straniere, quindi un classificatore ingenuo impara che il testo cinese o arabo in sé significa spam. Spam Scanner corregge questo problema in tre modi:

1. **La lingua non è mai una prova.** La lingua e il sistema di scrittura rilevati non vengono usati come indizi.
2. **Le parole vengono pesate all'interno della loro lingua.** La probabilità di spam di una parola viene calcolata rispetto al numero di messaggi di spam e di ham che il classificatore ha visto nella lingua del messaggio, non in tutte le lingue. Una parola portoghese di uso comune, in un modello che ha visto soprattutto spam in portoghese, resta neutra.
3. **La confidenza segue la copertura.** Il risultato viene spinto verso "incerto" in proporzione a quanti messaggi di ciascun tipo il classificatore ha visto in quella lingua: la piena confidenza richiede 1.000 messaggi di ciascun tipo (o il 2% della classe più piccola, per i piccoli modelli personali). Una lingua senza ham nei dati di addestramento riceve sempre "incerto".

Il modello incluso non ha mai visto la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), una raccolta di SMS tradotti automaticamente in 21 lingue. Prima di queste regole, segnava come spam il 5,7% di quell'ham, compreso il 55% di quello in portoghese e il 41% di quello in francese. Con queste regole, lo 0,18%: nessuno in cinese, arabo, coreano, giapponese, hindi, portoghese, francese o altre 20 lingue, e lo 0,27% in inglese.


## Intercettare lo spam in quelle lingue

"Incerto" è sicuro, ma non intercetta lo spam. Lo fanno tre cose:

* **Gli altri controlli** non dipendono dalla lingua: domini sosia, link ingannevoli, eseguibili, macro, autenticazione, blocklist, regole.
* **Un modello linguistico.** I modelli aperti moderni leggono da 100 a 200 lingue, e Spam Scanner ne consulta uno ogni volta che il classificatore è incerto. I test end-to-end verificano che `qwen3.5:4b` intercetti lo spam e lasci passare l'ham in cinese, arabo, coreano, hindi e thailandese. [Modelli linguistici](llm.md)
* **L'addestramento sulla tua posta.** In un modello addestrato sulla tua posta, qualche centinaio di messaggi di ciascun tipo in una lingua dà al classificatore piena confidenza in quella lingua. [Addestramento](training.md), e [un dataset facoltativo](training.md#more-languages) che aggiunge 21 lingue.
