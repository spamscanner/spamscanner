<!-- source: 7cc30ff4ad91 -->

# Træning

Den medfølgende model virker med det samme. En model, der er trænet på din egen post, virker bedre, fordi den lærer, hvordan din ham ser ud: dine nyhedsbreve, dine kollegers skrivemåde, de sprog, du modtager post på.


## Træn en model

Peg `train` på mapper med spam og ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Kilderne kan være:

* **mbox**-filer, også gzip-komprimerede (`.mbox.gz`),
* en **Maildir** (dens mapper `cur` og `new` læses, `tmp` springes over),
* en **mappe** med `.eml`-filer, der læses rekursivt,
* et **datasæt**: en CSV- eller JSON Lines-fil med en tekstkolonne og en etiketkolonne (`--dataset`). Kolonner med navnene `text`, `message`, `body`, `email` eller `content` og `label`, `category`, `class`, `spam` eller `is_spam` findes automatisk; ellers bruger du `--text-column` og `--label-column`. Etiketter som `spam`, `1`, `phishing` og `ham`, `0`, `not_spam`, `legitimate` forstås.

Dubletter tælles én gang. For at bygge videre på den medfølgende model i stedet for at starte tomt tilføjer du `--merge`.

Brug modellen:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Hvor meget post er nok: et par hundrede beskeder af hver slags giver en brugbar model, et par tusinde en god model. Hold de to nogenlunde i balance, og hold post, du ikke vil have filtreret (nulstilling af adgangskoder, fakturaer fra dine egne leverandører), i ham.


## Mål den

Hold noget post ude af træningen, og mål på den:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Den medfølgende model på SMS-beskeder på 21 sprog, som den aldrig har set, de fleste på sprog, den knap nok kender:

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

Præcision er, hvor meget af det, den kalder spam, der er spam; genkaldelse er, hvor meget af spammen den fanger. Usikre beskeder tæller her som misset spam, selv om de andre tjek og sprogmodellen stadig kan fange dem i en scanning. Det tal, der skal holdes øje med, er falske positiver: ham markeret som spam. I kørslen ovenfor er modellen usikker på de fleste af disse beskeder i stedet for at tage fejl af dem, hvilket er den tilsigtede adfærd for sprog, den har set lidt post på.

`--json` giver de samme tal til scripts.


## Indlæring fra rapporter

Når brugere flytter post ind i eller ud af en Junk-mappe, lærer du modellen op én besked ad gangen:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Den første `learn` opretter filen ud fra den medfølgende model. Over HTTP gør `POST /learn/spam` og `/learn/ham` i [HTTP API'et](http-api.md) det samme, og `spamc -L spam` virker mod [spamd-serveren](mail-servers.md#a-drop-in-for-spamassassins-spamd) med `--allow-tell`. [Dovecots IMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning) kan kalde begge, når en besked flyttes.

Fra Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

En besked, der er rapporteret som fejlklassificeret, bør aflæres fra den forkerte klasse, før den læres i den rigtige, hvis den er blevet lært før.


## Den medfølgende model

`model/classifier.json` bygges af `npm run model:train` ud fra disse offentlige datasæt på Hugging Face, alle under åbne licenser:

| Datasæt                                                                                                                                                                                                                                                                                                                    | Licens                      | Indhold                         |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                  | Beskeder og e-mails på 43 sprog |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Offentligt forskningskorpus | Enron-Spam-korpusset            |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                     | Russiske Telegram-beskeder      |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                         | Syntetiske beskeder             |

Den har lært af 62.480 spambeskeder og 76.489 ham-beskeder. Scriptet holder hver tiende besked ude, træner på resten og måler klassifikatoren alene, uden de andre tjek:

| Test på udeladte beskeder | Beskeder | Præcision | Genkaldelse | Falske positiver | Usikre |
| ------------------------- | -------: | --------: | ----------: | ---------------: | -----: |
| Engelsk                   |    6.564 |   100,0 % |      97,0 % |            0,0 % |  2,4 % |
| Russisk                   |    1.682 |   100,0 % |      97,4 % |            0,0 % |  2,2 % |
| Italiensk                 |    1.389 |    98,1 % |      85,3 % |            1,8 % | 10,9 % |
| Tysk                      |    1.309 |    97,7 % |      76,1 % |            2,2 % | 20,7 % |
| Spansk                    |    1.281 |    97,5 % |      82,5 % |            2,6 % | 16,8 % |
| Enron-Spam                |    2.888 |   100,0 % |      93,1 % |            0,0 % |  4,5 % |
| all-scam-spam             |    4.236 |   100,0 % |      88,8 % |            0,0 % | 11,2 % |
| Alle                      |   13.840 |    99,2 % |      85,1 % |            0,5 % | 12,4 % |

Spam betyder her en sandsynlighed fra klassifikatoren på 99 % eller mere, det punkt, hvor klassifikatoren alene når spamgrænsen. I en scanning får spam, som den er mindre sikker på, stadig point, og de andre tjek lægger deres til.

De tyske, spanske og italienske resultater kommer fra syntetiske datasæt, som indeholder næsten identiske beskeder mærket både spam og ham: en del af den fejl ligger i etiketterne, ikke i modellen. Post på dine egne sprog er den bedste løsning. Tallene for alle sprog og datasæt står i modellens `metadata.metrics`.

### Flere sprog

`npm run model:train -- --with multilingual-sms` tilføjer [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection maskinoversat til 21 sprog. Det er udeladt af den medfølgende model, fordi dets datasætkort angiver en GPL-licens; tjek, at det passer til, hvordan du deler modellen. Trænet med det var resultaterne på udeladte beskeder for sprog, som den medfølgende model knap nok kender:

| Sprog    | Beskeder | Præcision | Genkaldelse | Falske positiver |
| -------- | -------: | --------: | ----------: | ---------------: |
| Kinesisk |      430 |   100,0 % |      82,3 % |            0,0 % |
| Arabisk  |      430 |   100,0 % |      84,6 % |            0,0 % |
| Koreansk |      412 |   100,0 % |      80,4 % |            0,0 % |
| Japansk  |      486 |    96,0 % |      85,7 % |            0,5 % |
| Hindi    |      412 |   100,0 % |      63,9 % |            0,0 % |
| Fransk   |      480 |    98,6 % |      94,2 % |            0,6 % |
| Tyrkisk  |      220 |   100,0 % |      73,1 % |            0,0 % |

### Træn den igen

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Modelfilen

En model er en JSON-fil: antallet af lærte spam- og ham-beskeder og, for hver hashet feature, hvor mange spam- og ham-beskeder der indeholdt den, sorteret og base64-kodet. Den indeholder ingen ord og ingen beskedtekst. `--max-features` beholder kun de hyppigste features, og `--min-count` fjerner sjældne, hvilket bytter nøjagtighed for størrelse; den medfølgende model beholder 400.000 features på omkring 6 MB.

Modeller fra Spam Scanner 6 og tidligere kan ikke indlæses: de hashede andre features. Træn en ny ud fra den samme post.
