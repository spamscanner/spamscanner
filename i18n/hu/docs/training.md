<!-- source: c4f8c2c7aa5a -->

# Tanítás

A beépített modell azonnal használható. A saját leveleken tanított modell jobban működik, mert megtanulja, milyen a saját ham: a hírlevelek, a kollégák írásmódja, a beérkező levelek nyelvei.


## Modell tanítása

A `train` parancsnak spam- és hammappákat kell megadni:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

A források lehetnek:

* **mbox**-fájlok, gzip-pel tömörítve is (`.mbox.gz`; a többi `.gz` fájlt kihagyja),
* egy **Maildir** (a `cur` és `new` mappáit olvassa, a `tmp` mappát kihagyja),
* `.eml` fájlokat tartalmazó **mappa**, rekurzívan beolvasva,
* egy **adatkészlet**: szöveg- és címkeoszlopot tartalmazó CSV- vagy JSON Lines-fájl (`--dataset`). A `text`, `message`, `body`, `email text`, `email`, `content`, `sms` vagy `v2`, illetve a `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` vagy `labels` nevű oszlopokat vagy JSON-mezőket kis- és nagybetűtől függetlenül magától megtalálja (JSON Linesban a `label_text` mezőt a `label` előtt); egyébként a `--text-column` és a `--label-column` használható. Azt a JSON-sort, amely nem objektum, kihagyja. Az olyan címkéket, mint a `spam`, `1`, `phishing` és a `ham`, `0`, `not_spam`, `legitimate`, felismeri.

Az ismétlődő leveleket egyszer számolja. A spam- és a ham-forrásokban egyaránt szereplő levelet spamként tartja meg, mert a spamforrásokat olvassa be először. Ha üres modell helyett a beépített modellre kell építeni, adja hozzá a `--merge` kapcsolót.

A modell használata:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Mennyi levél elég: mindkét fajtából néhány száz levél használható modellt ad, néhány ezer jót. A kettő arányát érdemes nagyjából kiegyensúlyozottan tartani, és azokat a leveleket, amelyeket nem kell szűrni (jelszó-visszaállítások, a saját beszállítók számlái), a ham közé kell tenni.


## Mérés

Tartson vissza néhány levelet a tanításból, és ezeken mérjen:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

A beépített modell 21 nyelvű, általa soha nem látott SMS-üzeneteken, amelyek többsége olyan nyelven íródott, amelyet alig ismer:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

A precizitás azt mutatja, hogy amit spamnek nevez, abból mennyi valóban spam; a felidézés azt, hogy a spam mekkora részét szűri ki. A bizonytalan levelek itt kihagyott spamnek számítanak, bár egy vizsgálatban a többi ellenőrzés és a nyelvi modell még kiszűrheti őket. A figyelendő szám a téves pozitívok száma: a spamnek jelölt ham. A fenti futásban a modell ezeknek a leveleknek a többségénél bizonytalan, nem pedig téved, és pontosan ez a szándékolt viselkedés azoknál a nyelveknél, amelyeken kevés levelet látott.

A `--json` ugyanezeket a számokat adja meg szkriptek számára.


## Tanulás a bejelentésekből

Amikor a felhasználók leveleket mozgatnak a Levélszemét mappába vagy onnan kifelé, a modell levelenként tanítható:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Az első `learn` a beépített modellből hozza létre a fájlt. HTTP-n keresztül a [HTTP API](http-api.md) `POST /learn/spam` és `/learn/ham` végpontja ugyanezt teszi, a `spamc -L spam` pedig a `--allow-tell` kapcsolóval a [spamd szerver](mail-servers.md#a-drop-in-for-spamassassins-spamd) ellen működik. A [Dovecot IMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning) bármelyiket meghívhatja, amikor egy levelet áthelyeznek.

Node.js-ből:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

A tévesen besoroltként bejelentett levelet, ha korábban már tanulta, előbb el kell felejtetni a rossz osztályból, és csak utána megtanítani a helyesben.


## A beépített modell

A `model/classifier.json` fájlt az `npm run model:train` készíti el ezekből a Hugging Face-en található, nyílt licencű nyilvános adatkészletekből:

| Adatkészlet                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Licenc                     | Tartalom                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------ |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | Üzenetek és e-mailek 43 nyelven                                                |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Nyilvános kutatási korpusz | Az Enron-Spam korpusz                                                          |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | Orosz Telegram-üzenetek                                                        |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Szintetikus üzenetek                                                           |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Levelezőlisták, hírlevelek, spam, adathalász és csaló e-mailek                 |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Üzenetek India 14 nyelvén                                                      |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | Indonéz e-mailek kategóriánként                                                |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | Egy vállalat levelezése spanyolul                                              |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | Hétköznapi levelek: számlák, foglalások, hírlevelek, akciók és fiókértesítések |

A ham hétköznapi üzleti és bolti leveleket is tartalmaz (számlák, rendelési és fiókértesítések, hírlevelek, akciók), így az ilyen levél önmagában nem számít spamnek.

77 564 spam- és 112 586 hamlevélből tanult. A szkript minden tizedik levelet félretesz, a többin tanít, és csak az osztályozót méri, a többi ellenőrzés nélkül:

| Félretett teszt | Levelek | Precizitás | Felidézés | Téves pozitívok | Bizonytalan |
| --------------- | ------: | ---------: | --------: | --------------: | ----------: |
| Angol           |   8 515 |     100,0% |     96,4% |            0,0% |        2,6% |
| Orosz           |   1 680 |     100,0% |     97,4% |            0,0% |        2,3% |
| Olasz           |   1 392 |      98,6% |     81,0% |            1,2% |       12,5% |
| Német           |   1 314 |      97,8% |     72,5% |            2,1% |       22,6% |
| Spanyol         |   2 088 |      98,5% |     56,1% |            0,4% |       15,7% |
| Enron-Spam      |   2 888 |     100,0% |     92,4% |            0,0% |        4,4% |
| all-scam-spam   |   4 236 |     100,0% |     89,3% |            0,0% |       11,6% |
| Összes          |  18 967 |      99,6% |     77,2% |            0,2% |       15,8% |

A spam itt legalább 99%-os osztályozói valószínűséget jelent, azt a pontot, ahol az osztályozó önmagában eléri a spamküszöböt. Egy vizsgálatban a kevésbé biztos spam is kap pontokat, és a többi ellenőrzés is hozzáadja a sajátját.

A német, spanyol és olasz eredmények szintetikus adatkészletekből származnak, amelyek közel azonos, spamnek és hamnek is címkézett leveleket tartalmaznak: a hiba egy része a címkékben van, nem a modellben. A legjobb megoldás a saját nyelveken írt levelek. A számok minden nyelvre és adatkészletre a modell `metadata.metrics` mezőjében találhatók.

### További nyelvek

Az `npm run model:train -- --with multilingual-sms` hozzáadja az [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) adatkészletet: az SMS Spam Collection 21 nyelvre gépi fordítással átültetett változatát. A beépített modellből kimaradt, mert az adatlapja GPL-licencet ad meg; ellenőrizze, hogy ez megfelel-e a modell megosztásának módjához. Ezzel tanítva a beépített modell által alig ismert nyelveken a félretett eredmények a következők voltak:

| Nyelv   | Levelek | Precizitás | Felidézés | Téves pozitívok |
| ------- | ------: | ---------: | --------: | --------------: |
| Kínai   |     432 |     100,0% |     86,1% |            0,0% |
| Arab    |     432 |     100,0% |     83,1% |            0,0% |
| Koreai  |     412 |     100,0% |     78,3% |            0,0% |
| Japán   |     486 |      96,1% |     87,5% |            0,5% |
| Hindi   |     494 |     100,0% |     76,2% |            0,0% |
| Francia |     511 |      98,7% |     88,6% |            0,6% |
| Török   |     222 |     100,0% |     70,4% |            0,0% |

### Újratanítás

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## A modellfájl

A modell egy JSON-fájl: a megtanult spam- és hamlevelek száma, valamint minden hashelt jellemzőre az, hogy hány spam- és hamlevél tartalmazta, rendezve és base64-kódolva. Nem tartalmaz szavakat és levélszöveget. A `--max-features` csak a leggyakoribb jellemzőket tartja meg, a `--min-count` pedig elveti a ritkákat, így a méret a pontosság rovására csökken; a beépített modell 400 000 jellemzőt tart meg körülbelül 6 MB-ban.

A Spam Scanner 6-os és korábbi verzióinak modelljei nem tölthetők be: más jellemzőket hasheltek. Ugyanazokból a levelekből új modellt kell tanítani.
