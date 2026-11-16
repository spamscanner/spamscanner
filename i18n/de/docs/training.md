<!-- source: c4f8c2c7aa5a -->

# Training

Das mitgelieferte Modell funktioniert sofort. Ein Modell, das mit den eigenen E-Mails trainiert ist, funktioniert besser, weil es lernt, wie Ihr Ham aussieht: Ihre Newsletter, wie Ihre Kollegen schreiben, die Sprachen, in denen Sie Post erhalten.


## Ein Modell trainieren

Richten Sie `train` auf Ordner mit Spam und Ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Quellen können sein:

* **mbox**-Dateien, auch gzip-komprimiert (`.mbox.gz`; andere `.gz`-Dateien werden übersprungen),
* ein **Maildir** (seine Ordner `cur` und `new` werden gelesen, `tmp` wird übersprungen),
* ein **Ordner** mit `.eml`-Dateien, rekursiv gelesen,
* ein **Datensatz**: eine CSV- oder JSON-Lines-Datei mit einer Textspalte und einer Label-Spalte (`--dataset`). Spalten oder JSON-Felder namens `text`, `message`, `body`, `email text`, `email`, `content`, `sms` oder `v2` sowie `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` oder `labels`, in beliebiger Groß- und Kleinschreibung, werden selbst erkannt (in JSON Lines `label_text` vor `label`); andernfalls verwenden Sie `--text-column` und `--label-column`. Eine JSON-Zeile, die kein Objekt ist, wird übersprungen. Labels wie `spam`, `1`, `phishing` und `ham`, `0`, `not_spam`, `legitimate` werden verstanden.

Doppelte Nachrichten werden einmal gezählt. Eine Nachricht, die sowohl in den Spam- als auch in den Ham-Quellen vorkommt, wird als Spam behalten, da die Spam-Quellen zuerst gelesen werden. Um auf dem mitgelieferten Modell aufzubauen, statt leer zu beginnen, fügen Sie `--merge` hinzu.

Das Modell verwenden:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Wie viele E-Mails genügen: Einige hundert Nachrichten jeder Art ergeben ein brauchbares Modell, einige tausend ein gutes. Halten Sie beide Arten etwa im Gleichgewicht, und nehmen Sie E-Mails, die nicht gefiltert werden sollen (Passwort-Zurücksetzungen, Rechnungen Ihrer eigenen Lieferanten), in den Ham auf.


## Messen

Halten Sie einige E-Mails aus dem Training heraus und messen Sie daran:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Das mitgelieferte Modell auf SMS-Nachrichten in 21 Sprachen, die es nie gesehen hat, die meisten davon in Sprachen, die es kaum kennt:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Die Präzision (Precision) gibt an, wie viel von dem, was es Spam nennt, tatsächlich Spam ist; die Trefferquote (Recall), wie viel des Spams es erkennt. Unsichere Nachrichten zählen hier als verfehlter Spam, obwohl bei einem Scan die anderen Prüfungen und das Sprachmodell sie noch erkennen können. Entscheidend sind die Fehlalarme (False Positives): als Spam markierter Ham. Im obigen Lauf ist das Modell bei den meisten dieser Nachrichten unsicher, statt falsch zu liegen. Das ist das beabsichtigte Verhalten bei Sprachen, in denen es wenige E-Mails gesehen hat.

`--json` liefert dieselben Zahlen für Skripte.


## Aus Meldungen lernen

Wenn Benutzer E-Mails in einen Junk-Ordner oder aus ihm heraus verschieben, bringen Sie dem Modell jeweils eine Nachricht bei:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Das erste `learn` legt die Datei aus dem mitgelieferten Modell an. Über HTTP tun `POST /learn/spam` und `/learn/ham` der [HTTP-API](http-api.md) dasselbe, und `spamc -L spam` funktioniert mit `--allow-tell` gegen den [spamd-Server](mail-servers.md#a-drop-in-for-spamassassins-spamd). [IMAPSieve von Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) kann beides aufrufen, wenn eine Nachricht verschoben wird.

Aus Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Eine als falsch eingestuft gemeldete Nachricht sollte, falls sie zuvor gelernt wurde, aus der falschen Klasse verlernt werden, bevor sie in der richtigen gelernt wird.


## Das mitgelieferte Modell

`model/classifier.json` wird von `npm run model:train` aus diesen öffentlichen Datensätzen auf Hugging Face erstellt, alle unter offenen Lizenzen:

| Datensatz                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Lizenz                        | Inhalt                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------- | ---------------------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                    | Nachrichten und E-Mails in 43 Sprachen                                                   |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Öffentliches Forschungskorpus | Das Enron-Spam-Korpus                                                                    |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                       | Russische Telegram-Nachrichten                                                           |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                           | Synthetische Nachrichten                                                                 |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                     | Mailinglisten, Newsletter, Spam, Phishing- und Betrugs-E-Mails                           |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                           | Nachrichten in 14 Sprachen Indiens                                                       |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                    | Indonesische E-Mails nach Kategorie                                                      |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                    | Die Post eines Unternehmens auf Spanisch                                                 |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0    | Gewöhnliche Post: Rechnungen, Buchungen, Newsletter, Werbeaktionen und Kontomitteilungen |

Zum Ham gehört gewöhnliche Geschäfts- und Shop-Post (Rechnungen, Bestell- und Kontomitteilungen, Newsletter, Werbeaktionen), sodass solche Post allein nicht als Spam gilt.

Es hat aus 77.564 Spam- und 112.586 Ham-Nachrichten gelernt. Das Skript hält jede zehnte Nachricht zurück, trainiert mit dem Rest und misst den Klassifikator allein, ohne die anderen Prüfungen:

| Zurückgehaltener Test | Nachrichten | Präzision | Trefferquote | Fehlalarme | Unsicher |
| --------------------- | ----------: | --------: | -----------: | ---------: | -------: |
| Englisch              |       8.515 |   100,0 % |       96,4 % |      0,0 % |    2,6 % |
| Russisch              |       1.680 |   100,0 % |       97,4 % |      0,0 % |    2,3 % |
| Italienisch           |       1.392 |    98,6 % |       81,0 % |      1,2 % |   12,5 % |
| Deutsch               |       1.314 |    97,8 % |       72,5 % |      2,1 % |   22,6 % |
| Spanisch              |       2.088 |    98,5 % |       56,1 % |      0,4 % |   15,7 % |
| Enron-Spam            |       2.888 |   100,0 % |       92,4 % |      0,0 % |    4,4 % |
| all-scam-spam         |       4.236 |   100,0 % |       89,3 % |      0,0 % |   11,6 % |
| Alle                  |      18.967 |    99,6 % |       77,2 % |      0,2 % |   15,8 % |

Spam bedeutet hier eine Wahrscheinlichkeit des Klassifikators von 99 % oder mehr, der Punkt, an dem der Klassifikator allein den Spam-Schwellenwert erreicht. Bei einem Scan erhält Spam, bei dem er weniger sicher ist, trotzdem Punkte, und die anderen Prüfungen fügen ihre hinzu.

Die Ergebnisse für Deutsch, Spanisch und Italienisch stammen aus synthetischen Datensätzen, die nahezu identische Nachrichten enthalten, die sowohl als Spam als auch als Ham gelabelt sind: Ein Teil dieses Fehlers liegt in den Labels, nicht im Modell. E-Mails in Ihren eigenen Sprachen sind die beste Abhilfe. Die Zahlen für jede Sprache und jeden Datensatz stehen in `metadata.metrics` des Modells.

### Weitere Sprachen

`npm run model:train -- --with multilingual-sms` fügt die [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) hinzu: die SMS Spam Collection, maschinell in 21 Sprachen übersetzt. Sie ist nicht im mitgelieferten Modell enthalten, weil ihre Dataset Card eine GPL-Lizenz angibt; prüfen Sie, ob das dazu passt, wie Sie das Modell weitergeben. Damit trainiert, ergaben sich für Sprachen, die das mitgelieferte Modell kaum kennt, diese Ergebnisse auf den zurückgehaltenen Nachrichten:

| Sprache     | Nachrichten | Präzision | Trefferquote | Fehlalarme |
| ----------- | ----------: | --------: | -----------: | ---------: |
| Chinesisch  |         432 |   100,0 % |       86,1 % |      0,0 % |
| Arabisch    |         432 |   100,0 % |       83,1 % |      0,0 % |
| Koreanisch  |         412 |   100,0 % |       78,3 % |      0,0 % |
| Japanisch   |         486 |    96,1 % |       87,5 % |      0,5 % |
| Hindi       |         494 |   100,0 % |       76,2 % |      0,0 % |
| Französisch |         511 |    98,7 % |       88,6 % |      0,6 % |
| Türkisch    |         222 |   100,0 % |       70,4 % |      0,0 % |

### Neu trainieren

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Die Modelldatei

Ein Modell ist eine JSON-Datei: die Zahl der gelernten Spam- und Ham-Nachrichten und für jedes gehashte Merkmal, wie viele Spam- und Ham-Nachrichten es enthielten, sortiert und base64-kodiert. Sie enthält keine Wörter und keinen Nachrichtentext. `--max-features` behält nur die häufigsten Merkmale, `--min-count` verwirft seltene; beides tauscht Genauigkeit gegen Größe. Das mitgelieferte Modell behält 400.000 Merkmale in etwa 6 MB.

Modelle aus Spam Scanner 6 und früher lassen sich nicht laden: Sie haben andere Merkmale gehasht. Trainieren Sie ein neues aus denselben E-Mails.
