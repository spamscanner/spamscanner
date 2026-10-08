<!-- source: 0ad167ddd34e -->

<!--
label: Filtro antispam multilingue
title: Filtro antispam multilingue: cinese, arabo, russo e ogni scrittura
description: Come Spam Scanner filtra lo spam in ogni lingua: segmentazione Unicode, camuffamenti annullati e nessuna segnalazione per le lingue poco note al modello.
keywords: filtro antispam multilingue, filtro antispam cinese, filtro antispam arabo, filtro antispam russo, filtro antispam giapponese, rilevamento spam Unicode, spam omoglifi
-->

# Filtro antispam multilingue

Molti filtri antispam sono stati progettati per l'inglese. Lo spam in altre lingue sfugge loro, e la posta normale in altre lingue viene segnalata per il suo sistema di scrittura. Spam Scanner è progettato per evitare entrambe le cose.


## Leggere le parole

Le parole vengono individuate con `Intl.Segmenter`, le regole Unicode sui confini delle parole con dizionari per cinese, giapponese, thailandese, lao, khmer e birmano. Una frase in cinese diventa parole come 恭喜, 获得 e 大奖, non una lunga stringa che non si ripete mai.

I camuffamenti vengono annullati prima del conteggio: caratteri invisibili dentro le parole, lettere cirilliche o greche dentro parole latine (`pаypal`), cifre al posto di lettere (`v1agra`) e lettere matematiche o racchiuse (𝐅𝐑𝐄𝐄). Ogni camuffamento è anche un indizio a sé.


## Non segnalare ciò che non conosce

I dataset pubblici di spam contengono molto più spam in lingue straniere che ham in lingue straniere, quindi un classificatore ingenuo impara che il testo arabo o coreano in sé è spam. Spam Scanner non usa mai la lingua come indizio, pesa ogni parola rispetto ai conteggi di spam e di ham della sua lingua e resta "incerto" in proporzione a quanto poco ham ha visto in una lingua.

In un test su SMS in 21 lingue che il modello incluso non aveva mai visto, questo ha portato a zero i suoi falsi positivi in cinese, arabo, coreano, giapponese, hindi, bengali, urdu, turco, ucraino e svedese.


## Intercettare lo spam in ogni lingua

* **Controlli che non leggono le parole:** domini sosia, link ingannevoli, eseguibili, macro, SPF, DKIM, DMARC e blocklist.
* **Un modello linguistico** per i messaggi incerti. Modelli aperti come Qwen 3.5 e Gemma 4 leggono da 140 a 200 lingue; i test end-to-end verificano spam e ham in cinese, arabo, coreano, hindi e thailandese con un modello reale.
* **La tua posta.** Qualche centinaio di messaggi di ciascun tipo in una lingua dà piena confidenza in quella lingua a un modello addestrato sulla tua posta.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Per accettare solo alcune lingue, `--allow-language en,de` aggiunge punti alla posta rilevata con sicurezza in qualsiasi altra lingua.

[Le lingue in dettaglio](../../docs/languages.md)
