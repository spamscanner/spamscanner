<!-- source: 7cc30ff4ad91 -->

# Trening

Den medfølgende modellen virker uten oppsett. En modell trent på din egen e-post virker bedre, fordi den lærer hvordan din ham ser ut: nyhetsbrevene dine, hvordan kollegene dine skriver, språkene du mottar.


## Tren en modell

Pek `train` mot mapper med spam og ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Kilder kan være:

* **mbox**-filer, også gzip-komprimerte (`.mbox.gz`),
* en **Maildir** (mappene `cur` og `new` leses, `tmp` hoppes over),
* en **mappe** med `.eml`-filer, lest rekursivt,
* et **datasett**: en CSV- eller JSON Lines-fil med en tekstkolonne og en etikettkolonne (`--dataset`). Kolonner med navnene `text`, `message`, `body`, `email` eller `content`, og `label`, `category`, `class`, `spam` eller `is_spam`, finnes automatisk; ellers bruker du `--text-column` og `--label-column`. Etiketter som `spam`, `1`, `phishing` og `ham`, `0`, `not_spam`, `legitimate` forstås.

Dupliserte meldinger telles én gang. For å bygge videre på den medfølgende modellen i stedet for å starte tomt, legger du til `--merge`.

Bruk modellen:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Hvor mye e-post som er nok: noen hundre meldinger av hver type gir en nyttig modell, noen tusen en god modell. Hold de to omtrent i balanse, og ta med e-post du ikke vil filtrere (tilbakestilling av passord, fakturaer fra dine egne leverandører) i hammen.


## Mål den

Hold noe e-post utenfor treningen og mål på den:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Den medfølgende modellen på SMS-meldinger på 21 språk som den aldri har sett, de fleste på språk den knapt kjenner:

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

Presisjon er hvor mye av det den kaller spam, som faktisk er spam; gjenkalling er hvor mye av spammen den fanger. Usikre meldinger teller her som spam den bommet på, selv om de andre sjekkene og språkmodellen fortsatt kan fange dem i en skanning. Tallet å følge med på er falske positiver: ham merket som spam. I kjøringen ovenfor er modellen usikker på de fleste av disse meldingene i stedet for å ta feil om dem, og det er den tiltenkte oppførselen for språk den har lite e-post på.

`--json` gir de samme tallene for skript.


## Læring fra rapporter

Når brukere flytter e-post inn i eller ut av en Søppelpost-mappe, lærer du opp modellen én melding om gangen:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Den første `learn` oppretter filen fra den medfølgende modellen. Over HTTP gjør `POST /learn/spam` og `/learn/ham` i [HTTP API-et](http-api.md) det samme, og `spamc -L spam` virker mot [spamd-serveren](mail-servers.md#a-drop-in-for-spamassassins-spamd) med `--allow-tell`. [Dovecots IMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning) kan kalle en av dem når en melding flyttes.

Fra Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

En melding som er rapportert som feilklassifisert, bør avlæres fra feil klasse før den læres i riktig klasse, hvis den er lært tidligere.


## Den medfølgende modellen

`model/classifier.json` bygges av `npm run model:train` fra disse offentlige datasettene på Hugging Face, alle med åpne lisenser:

| Datasett                                                                                                                                                                                                                                                                                                                   | Lisens                     | Innhold                           |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                 | Meldinger og e-poster på 43 språk |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Offentlig forskningskorpus | Enron-Spam-korpuset               |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                    | Russiske Telegram-meldinger       |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                        | Syntetiske meldinger              |

Den lærte av 62 480 spam- og 76 489 ham-meldinger. Skriptet holder tilbake hver tiende melding, trener på resten og måler klassifisereren alene, uten de andre sjekkene:

| Tilbakeholdt test | Meldinger | Presisjon | Gjenkalling | Falske positiver | Usikre |
| ----------------- | --------: | --------: | ----------: | ---------------: | -----: |
| Engelsk           |     6 564 |   100,0 % |      97,0 % |            0,0 % |  2,4 % |
| Russisk           |     1 682 |   100,0 % |      97,4 % |            0,0 % |  2,2 % |
| Italiensk         |     1 389 |    98,1 % |      85,3 % |            1,8 % | 10,9 % |
| Tysk              |     1 309 |    97,7 % |      76,1 % |            2,2 % | 20,7 % |
| Spansk            |     1 281 |    97,5 % |      82,5 % |            2,6 % | 16,8 % |
| Enron-Spam        |     2 888 |   100,0 % |      93,1 % |            0,0 % |  4,5 % |
| all-scam-spam     |     4 236 |   100,0 % |      88,8 % |            0,0 % | 11,2 % |
| Alle              |    13 840 |    99,2 % |      85,1 % |            0,5 % | 12,4 % |

Spam betyr her en sannsynlighet fra klassifisereren på 99 % eller mer, punktet der klassifisereren alene når spamterskelen. I en skanning får spam den er mindre sikker på, likevel poeng, og de andre sjekkene legger til sine.

Resultatene for tysk, spansk og italiensk kommer fra syntetiske datasett, som inneholder nesten identiske meldinger merket både som spam og som ham: en del av feilen ligger i etikettene, ikke i modellen. E-post på dine egne språk er den beste løsningen. Tallene, med alle språk og datasett, finnes i modellens `metadata.metrics`.

### Flere språk

`npm run model:train -- --with multilingual-sms` legger til [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection maskinoversatt til 21 språk. Den er utelatt fra den medfølgende modellen fordi datasettkortet oppgir en GPL-lisens; sjekk at det passer med hvordan du deler modellen. Trent med den ble resultatene på tilbakeholdte meldinger for språk den medfølgende modellen knapt kjenner:

| Språk    | Meldinger | Presisjon | Gjenkalling | Falske positiver |
| -------- | --------: | --------: | ----------: | ---------------: |
| Kinesisk |       430 |   100,0 % |      82,3 % |            0,0 % |
| Arabisk  |       430 |   100,0 % |      84,6 % |            0,0 % |
| Koreansk |       412 |   100,0 % |      80,4 % |            0,0 % |
| Japansk  |       486 |    96,0 % |      85,7 % |            0,5 % |
| Hindi    |       412 |   100,0 % |      63,9 % |            0,0 % |
| Fransk   |       480 |    98,6 % |      94,2 % |            0,6 % |
| Tyrkisk  |       220 |   100,0 % |      73,1 % |            0,0 % |

### Tren den på nytt

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Modellfilen

En modell er en JSON-fil: antall spam- og ham-meldinger som er lært, og for hver hashede egenskap hvor mange spam- og ham-meldinger som inneholdt den, sortert og base64-kodet. Den inneholder ingen ord og ingen meldingstekst. `--max-features` beholder bare de hyppigste egenskapene, og `--min-count` fjerner sjeldne, slik at nøyaktighet byttes mot størrelse; den medfølgende modellen beholder 400 000 egenskaper på omtrent 6 MB.

Modeller fra Spam Scanner 6 og eldre kan ikke lastes inn: de hashet andre egenskaper. Tren en ny fra den samme e-posten.
