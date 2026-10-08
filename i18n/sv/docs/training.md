<!-- source: 7cc30ff4ad91 -->

# Träning

Den medföljande modellen fungerar direkt. En modell som tränats på din egen e-post fungerar bättre, eftersom den lär sig hur din ham (önskad e-post) ser ut: dina nyhetsbrev, dina kollegors sätt att skriva, de språk du tar emot.


## Träna en modell

Peka `train` mot mappar med spam och ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Källor kan vara:

* **mbox**-filer, även gzip-komprimerade (`.mbox.gz`),
* en **Maildir** (dess mappar `cur` och `new` läses, `tmp` hoppas över),
* en **mapp** med `.eml`-filer, som läses rekursivt,
* ett **dataset**: en CSV- eller JSON Lines-fil med en textkolumn och en etikettkolumn (`--dataset`). Kolumner med namnen `text`, `message`, `body`, `email` eller `content`, och `label`, `category`, `class`, `spam` eller `is_spam`, hittas automatiskt; annars använder du `--text-column` och `--label-column`. Etiketter som `spam`, `1`, `phishing` och `ham`, `0`, `not_spam`, `legitimate` förstås.

Dubblettmeddelanden räknas en gång. För att bygga vidare på den medföljande modellen i stället för att börja tomt, lägg till `--merge`.

Använd modellen:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Hur mycket e-post som räcker: några hundra meddelanden av varje slag ger en användbar modell, några tusen en bra. Håll de två ungefär i balans, och lägg e-post som du inte vill filtrera (lösenordsåterställningar, fakturor från dina egna leverantörer) bland hammen.


## Mät den

Håll undan en del e-post från träningen och mät på den:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Den medföljande modellen på sms på 21 språk som den aldrig sett, de flesta på språk som den knappt kan:

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

Precision är hur stor del av det den kallar spam som faktiskt är spam; täckning (recall) hur stor del av spammen den fångar. Osäkra meddelanden räknas här som missad spam, även om de andra kontrollerna och språkmodellen fortfarande kan fånga dem i en skanning. Siffran att hålla ögonen på är falska positiva: ham som markerats som spam. I körningen ovan är modellen osäker på de flesta av dessa meddelanden snarare än fel om dem, vilket är det avsedda beteendet för språk som den har lite e-post på.

`--json` ger samma siffror för skript.


## Lära sig av rapporter

När användare flyttar e-post till eller från en skräppostmapp, lär modellen ett meddelande i taget:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Den första `learn` skapar filen från den medföljande modellen. Över HTTP gör `POST /learn/spam` och `/learn/ham` i [HTTP-API:t](http-api.md) samma sak, och `spamc -L spam` fungerar mot [spamd-servern](mail-servers.md#a-drop-in-for-spamassassins-spamd) med `--allow-tell`. [Dovecots IMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning) kan anropa någon av dem när ett meddelande flyttas.

Från Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Ett meddelande som rapporterats som felklassificerat bör avläras från fel klass innan det lärs in i rätt klass, om det har lärts in tidigare.


## Den medföljande modellen

`model/classifier.json` byggs av `npm run model:train` från dessa offentliga dataset på Hugging Face, alla under öppna licenser:

| Dataset                                                                                                                                                                                                                                                                                                                    | Licens                     | Innehåll                           |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ---------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                 | Meddelanden och e-post på 43 språk |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Offentlig forskningskorpus | Enron-Spam-korpusen                |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                    | Ryska Telegram-meddelanden         |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                        | Syntetiska meddelanden             |

Den lärde sig av 62 480 spam- och 76 489 hammeddelanden. Skriptet håller undan vart tionde meddelande, tränar på resten och mäter enbart klassificeraren, utan de andra kontrollerna:

| Undanhållet test | Meddelanden | Precision | Täckning | Falska positiva | Osäkra |
| ---------------- | ----------: | --------: | -------: | --------------: | -----: |
| Engelska         |       6 564 |   100,0 % |   97,0 % |           0,0 % |  2,4 % |
| Ryska            |       1 682 |   100,0 % |   97,4 % |           0,0 % |  2,2 % |
| Italienska       |       1 389 |    98,1 % |   85,3 % |           1,8 % | 10,9 % |
| Tyska            |       1 309 |    97,7 % |   76,1 % |           2,2 % | 20,7 % |
| Spanska          |       1 281 |    97,5 % |   82,5 % |           2,6 % | 16,8 % |
| Enron-Spam       |       2 888 |   100,0 % |   93,1 % |           0,0 % |  4,5 % |
| all-scam-spam    |       4 236 |   100,0 % |   88,8 % |           0,0 % | 11,2 % |
| Alla             |      13 840 |    99,2 % |   85,1 % |           0,5 % | 12,4 % |

Spam betyder här en sannolikhet från klassificeraren på 99 % eller mer, den punkt där klassificeraren ensam når spamgränsen. I en skanning får spam som den är mindre säker på ändå poäng, och de andra kontrollerna lägger till sina.

Resultaten för tyska, spanska och italienska kommer från syntetiska dataset, som innehåller nästan identiska meddelanden märkta både som spam och ham: en del av felet ligger i etiketterna, inte i modellen. E-post på dina egna språk är den bästa lösningen. Siffrorna, med alla språk och dataset, finns i modellens `metadata.metrics`.

### Fler språk

`npm run model:train -- --with multilingual-sms` lägger till [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection maskinöversatt till 21 språk. Den ingår inte i den medföljande modellen eftersom dess beskrivning anger en GPL-licens; kontrollera att den passar hur du delar modellen. Tränad med den blev de undanhållna resultaten för språk som den medföljande modellen knappt kan:

| Språk     | Meddelanden | Precision | Täckning | Falska positiva |
| --------- | ----------: | --------: | -------: | --------------: |
| Kinesiska |         430 |   100,0 % |   82,3 % |           0,0 % |
| Arabiska  |         430 |   100,0 % |   84,6 % |           0,0 % |
| Koreanska |         412 |   100,0 % |   80,4 % |           0,0 % |
| Japanska  |         486 |    96,0 % |   85,7 % |           0,5 % |
| Hindi     |         412 |   100,0 % |   63,9 % |           0,0 % |
| Franska   |         480 |    98,6 % |   94,2 % |           0,6 % |
| Turkiska  |         220 |   100,0 % |   73,1 % |           0,0 % |

### Träna om den

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Modellfilen

En modell är en JSON-fil: antalet inlärda spam- och hammeddelanden och, för varje hashad egenskap, hur många spam- och hammeddelanden som innehöll den, sorterat och base64-kodat. Den innehåller inga ord och ingen meddelandetext. `--max-features` behåller bara de vanligaste egenskaperna och `--min-count` tar bort sällsynta, vilket byter träffsäkerhet mot storlek; den medföljande modellen behåller 400 000 egenskaper på ungefär 6 MB.

Modeller från Spam Scanner 6 och tidigare kan inte läsas in: de hashade andra egenskaper. Träna en ny från samma e-post.
