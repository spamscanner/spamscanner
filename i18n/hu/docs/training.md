<!-- source: 7cc30ff4ad91 -->

# Tanítás

A beépített modell azonnal használható. A saját leveleken tanított modell jobban működik, mert megtanulja, milyen a saját ham: a hírlevelek, a kollégák írásmódja, a beérkező levelek nyelvei.


## Modell tanítása

A `train` parancsnak spam- és hammappákat kell megadni:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

A források lehetnek:

* **mbox**-fájlok, gzip-pel tömörítve is (`.mbox.gz`),
* egy **Maildir** (a `cur` és `new` mappáit olvassa, a `tmp` mappát kihagyja),
* `.eml` fájlokat tartalmazó **mappa**, rekurzívan beolvasva,
* egy **adatkészlet**: szöveg- és címkeoszlopot tartalmazó CSV- vagy JSON Lines-fájl (`--dataset`). A `text`, `message`, `body`, `email` vagy `content`, illetve a `label`, `category`, `class`, `spam` vagy `is_spam` nevű oszlopokat magától megtalálja; egyébként a `--text-column` és a `--label-column` használható. Az olyan címkéket, mint a `spam`, `1`, `phishing` és a `ham`, `0`, `not_spam`, `legitimate`, felismeri.

Az ismétlődő leveleket egyszer számolja. Ha üres modell helyett a beépített modellre kell építeni, adja hozzá a `--merge` kapcsolót.

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
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
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

| Adatkészlet                                                                                                                                                                                                                                                                                                                | Licenc                     | Tartalom                        |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                 | Üzenetek és e-mailek 43 nyelven |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Nyilvános kutatási korpusz | Az Enron-Spam korpusz           |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                    | Orosz Telegram-üzenetek         |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                        | Szintetikus üzenetek            |

62 480 spam- és 76 489 hamlevélből tanult. A szkript minden tizedik levelet félretesz, a többin tanít, és csak az osztályozót méri, a többi ellenőrzés nélkül:

| Félretett teszt | Levelek | Precizitás | Felidézés | Téves pozitívok | Bizonytalan |
| --------------- | ------: | ---------: | --------: | --------------: | ----------: |
| Angol           |   6 564 |     100,0% |     97,0% |            0,0% |        2,4% |
| Orosz           |   1 682 |     100,0% |     97,4% |            0,0% |        2,2% |
| Olasz           |   1 389 |      98,1% |     85,3% |            1,8% |       10,9% |
| Német           |   1 309 |      97,7% |     76,1% |            2,2% |       20,7% |
| Spanyol         |   1 281 |      97,5% |     82,5% |            2,6% |       16,8% |
| Enron-Spam      |   2 888 |     100,0% |     93,1% |            0,0% |        4,5% |
| all-scam-spam   |   4 236 |     100,0% |     88,8% |            0,0% |       11,2% |
| Összes          |  13 840 |      99,2% |     85,1% |            0,5% |       12,4% |

A spam itt legalább 99%-os osztályozói valószínűséget jelent, azt a pontot, ahol az osztályozó önmagában eléri a spamküszöböt. Egy vizsgálatban a kevésbé biztos spam is kap pontokat, és a többi ellenőrzés is hozzáadja a sajátját.

A német, spanyol és olasz eredmények szintetikus adatkészletekből származnak, amelyek közel azonos, spamnek és hamnek is címkézett leveleket tartalmaznak: a hiba egy része a címkékben van, nem a modellben. A legjobb megoldás a saját nyelveken írt levelek. A számok minden nyelvre és adatkészletre a modell `metadata.metrics` mezőjében találhatók.

### További nyelvek

Az `npm run model:train -- --with multilingual-sms` hozzáadja az [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) adatkészletet: az SMS Spam Collection 21 nyelvre gépi fordítással átültetett változatát. A beépített modellből kimaradt, mert az adatlapja GPL-licencet ad meg; ellenőrizze, hogy ez megfelel-e a modell megosztásának módjához. Ezzel tanítva a beépített modell által alig ismert nyelveken a félretett eredmények a következők voltak:

| Nyelv   | Levelek | Precizitás | Felidézés | Téves pozitívok |
| ------- | ------: | ---------: | --------: | --------------: |
| Kínai   |     430 |     100,0% |     82,3% |            0,0% |
| Arab    |     430 |     100,0% |     84,6% |            0,0% |
| Koreai  |     412 |     100,0% |     80,4% |            0,0% |
| Japán   |     486 |      96,0% |     85,7% |            0,5% |
| Hindi   |     412 |     100,0% |     63,9% |            0,0% |
| Francia |     480 |      98,6% |     94,2% |            0,6% |
| Török   |     220 |     100,0% |     73,1% |            0,0% |

### Újratanítás

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## A modellfájl

A modell egy JSON-fájl: a megtanult spam- és hamlevelek száma, valamint minden hashelt jellemzőre az, hogy hány spam- és hamlevél tartalmazta, rendezve és base64-kódolva. Nem tartalmaz szavakat és levélszöveget. A `--max-features` csak a leggyakoribb jellemzőket tartja meg, a `--min-count` pedig elveti a ritkákat, így a méret a pontosság rovására csökken; a beépített modell 400 000 jellemzőt tart meg körülbelül 6 MB-ban.

A Spam Scanner 6-os és korábbi verzióinak modelljei nem tölthetők be: más jellemzőket hasheltek. Ugyanazokból a levelekből új modellt kell tanítani.
