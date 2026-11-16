<!-- source: c4f8c2c7aa5a -->

# Training

Het meegeleverde model werkt direct. Een model dat op je eigen mail is getraind, werkt beter, omdat het leert hoe je ham eruitziet: je nieuwsbrieven, de schrijfstijl van je collega's, de talen die je ontvangt.


## Een model trainen

Wijs `train` naar mappen met spam en ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Bronnen kunnen zijn:

* **mbox**-bestanden, ook gzip-gecomprimeerd (`.mbox.gz`; andere `.gz`-bestanden worden overgeslagen),
* een **Maildir** (de mappen `cur` en `new` worden gelezen, `tmp` wordt overgeslagen),
* een **map** met `.eml`-bestanden, recursief gelezen,
* een **dataset**: een CSV- of JSON Lines-bestand met een tekstkolom en een labelkolom (`--dataset`). Kolommen, of JSON-velden, met de naam `text`, `message`, `body`, `email text`, `email`, `content`, `sms` of `v2`, en `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` of `labels`, in hoofd- of kleine letters, worden vanzelf gevonden (in JSON Lines `label_text` vóór `label`); gebruik anders `--text-column` en `--label-column`. Een JSON-regel die geen object is, wordt overgeslagen. Labels zoals `spam`, `1`, `phishing` en `ham`, `0`, `not_spam`, `legitimate` worden begrepen.

Dubbele berichten worden één keer geteld. Een bericht dat zowel in de spam- als in de hambronnen staat, blijft spam, omdat de spambronnen eerst worden gelezen. Voeg `--merge` toe om op het meegeleverde model voort te bouwen in plaats van leeg te beginnen.

Gebruik het model:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Hoeveel mail genoeg is: een paar honderd berichten van elk soort geven een bruikbaar model, een paar duizend een goed model. Houd de twee ongeveer in balans, en houd mail die je niet wilt filteren (wachtwoordherstel, facturen van je eigen leveranciers) in de ham.


## Het meten

Houd wat mail buiten de training en meet daarop:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Het meegeleverde model op sms-berichten in 21 talen die het nooit had gezien, de meeste in talen die het nauwelijks kent:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Precisie is hoeveel van wat het spam noemt ook spam is; recall is hoeveel van de spam het vangt. Onzekere berichten tellen hier als gemiste spam, al kunnen de andere controles en het taalmodel ze in een scan nog vangen. Het getal om in de gaten te houden is het aantal fout-positieven: ham die als spam is gemarkeerd. In de run hierboven is het model over de meeste van deze berichten onzeker in plaats van ernaast te zitten. Dat is het bedoelde gedrag voor talen waarin het weinig mail heeft gezien.

`--json` geeft dezelfde getallen voor scripts.


## Leren van meldingen

Als gebruikers mail naar of uit een Junk-map verplaatsen, leer het model dan bericht voor bericht bij:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

De eerste `learn` maakt het bestand aan vanuit het meegeleverde model. Via HTTP doen `POST /learn/spam` en `/learn/ham` op de [HTTP API](http-api.md) hetzelfde, en `spamc -L spam` werkt tegen de [spamd-server](mail-servers.md#a-drop-in-for-spamassassins-spamd) met `--allow-tell`. [IMAPSieve van Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) kan een van beide aanroepen als een bericht wordt verplaatst.

Vanuit Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Een bericht dat als verkeerd geclassificeerd is gemeld, moet uit de verkeerde klasse worden afgeleerd voordat het in de juiste wordt aangeleerd, als het eerder al was aangeleerd.


## Het meegeleverde model

`model/classifier.json` wordt door `npm run model:train` gebouwd uit deze openbare datasets op Hugging Face, allemaal met een open licentie:

| Dataset                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Licentie                   | Inhoud                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ----------------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | Berichten en e-mails in 43 talen                                                    |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Openbaar onderzoekscorpus  | Het Enron-Spam-corpus                                                               |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | Russische Telegram-berichten                                                        |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Synthetische berichten                                                              |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Mailinglijsten, nieuwsbrieven, spam, phishing en fraudemails                        |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Berichten in 14 talen van India                                                     |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | Indonesische e-mails per categorie                                                  |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | De post van een bedrijf in het Spaans                                               |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | Gewone post: rekeningen, boekingen, nieuwsbrieven, aanbiedingen en accountmeldingen |

De ham bevat gewone zakelijke en winkelpost (facturen, bestel- en accountmeldingen, nieuwsbrieven, aanbiedingen), zodat zulke post op zichzelf niet als spam wordt gelezen.

Het leerde van 77.564 spam- en 112.586 hamberichten. Het script houdt elk tiende bericht achter, traint op de rest en meet alleen de classifier, zonder de andere controles:

| Achtergehouden test | Berichten | Precisie | Recall | Fout-positieven | Onzeker |
| ------------------- | --------: | -------: | -----: | --------------: | ------: |
| Engels              |     8.515 |   100,0% |  96,4% |            0,0% |    2,6% |
| Russisch            |     1.680 |   100,0% |  97,4% |            0,0% |    2,3% |
| Italiaans           |     1.392 |    98,6% |  81,0% |            1,2% |   12,5% |
| Duits               |     1.314 |    97,8% |  72,5% |            2,1% |   22,6% |
| Spaans              |     2.088 |    98,5% |  56,1% |            0,4% |   15,7% |
| Enron-Spam          |     2.888 |   100,0% |  92,4% |            0,0% |    4,4% |
| all-scam-spam       |     4.236 |   100,0% |  89,3% |            0,0% |   11,6% |
| Alle                |    18.967 |    99,6% |  77,2% |            0,2% |   15,8% |

Spam betekent hier een classifierkans van 99% of meer, het punt waarop de classifier op zichzelf de spamdrempel haalt. In een scan krijgt spam waarover hij minder zeker is nog steeds punten, en de andere controles tellen de hunne erbij op.

De Duitse, Spaanse en Italiaanse resultaten komen uit synthetische datasets, die bijna identieke berichten bevatten met zowel het label spam als ham: een deel van die fout zit in de labels, niet in het model. Mail in je eigen talen is de beste oplossing. De getallen, met elke taal en dataset, staan in `metadata.metrics` van het model.

### Meer talen

`npm run model:train -- --with multilingual-sms` voegt de [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) toe: de SMS Spam Collection, machinaal vertaald in 21 talen. Die is weggelaten uit het meegeleverde model omdat de datasetkaart een GPL-licentie noemt; controleer of dat past bij hoe je het model deelt. Daarmee getraind waren de resultaten op achtergehouden berichten voor talen die het meegeleverde model nauwelijks kent:

| Taal     | Berichten | Precisie | Recall | Fout-positieven |
| -------- | --------: | -------: | -----: | --------------: |
| Chinees  |       432 |   100,0% |  86,1% |            0,0% |
| Arabisch |       432 |   100,0% |  83,1% |            0,0% |
| Koreaans |       412 |   100,0% |  78,3% |            0,0% |
| Japans   |       486 |    96,1% |  87,5% |            0,5% |
| Hindi    |       494 |   100,0% |  76,2% |            0,0% |
| Frans    |       511 |    98,7% |  88,6% |            0,6% |
| Turks    |       222 |   100,0% |  70,4% |            0,0% |

### Opnieuw trainen

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Het modelbestand

Een model is een JSON-bestand: het aantal geleerde spam- en hamberichten, en voor elk gehasht kenmerk hoeveel spam- en hamberichten het bevatten, gesorteerd en base64-gecodeerd. Het bevat geen woorden en geen berichttekst. `--max-features` houdt alleen de vaakst voorkomende kenmerken en `--min-count` laat zeldzame weg, wat nauwkeurigheid inruilt voor grootte; het meegeleverde model houdt 400.000 kenmerken in ongeveer 6 MB.

Modellen van Spam Scanner 6 en eerder kunnen niet worden geladen: die hashten andere kenmerken. Train een nieuw model op dezelfde mail.
