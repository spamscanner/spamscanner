<!-- source: 7cc30ff4ad91 -->

# Training

Das mitgelieferte Modell funktioniert sofort. Ein Modell, das mit den eigenen E-Mails trainiert ist, funktioniert besser, weil es lernt, wie Ihr Ham aussieht: Ihre Newsletter, wie Ihre Kollegen schreiben, die Sprachen, in denen Sie Post erhalten.


## Ein Modell trainieren

Richten Sie `train` auf Ordner mit Spam und Ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Quellen können sein:

* **mbox**-Dateien, auch gzip-komprimiert (`.mbox.gz`),
* ein **Maildir** (seine Ordner `cur` und `new` werden gelesen, `tmp` wird übersprungen),
* ein **Ordner** mit `.eml`-Dateien, rekursiv gelesen,
* ein **Datensatz**: eine CSV- oder JSON-Lines-Datei mit einer Textspalte und einer Label-Spalte (`--dataset`). Spalten namens `text`, `message`, `body`, `email` oder `content` sowie `label`, `category`, `class`, `spam` oder `is_spam` werden selbst erkannt; andernfalls verwenden Sie `--text-column` und `--label-column`. Labels wie `spam`, `1`, `phishing` und `ham`, `0`, `not_spam`, `legitimate` werden verstanden.

Doppelte Nachrichten werden einmal gezählt. Um auf dem mitgelieferten Modell aufzubauen, statt leer zu beginnen, fügen Sie `--merge` hinzu.

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
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
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

| Datensatz                                                                                                                                                                                                                                                                                                                  | Lizenz                        | Inhalt                                 |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | -------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                    | Nachrichten und E-Mails in 43 Sprachen |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Öffentliches Forschungskorpus | Das Enron-Spam-Korpus                  |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                       | Russische Telegram-Nachrichten         |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                           | Synthetische Nachrichten               |

Es hat aus 62.480 Spam- und 76.489 Ham-Nachrichten gelernt. Das Skript hält jede zehnte Nachricht zurück, trainiert mit dem Rest und misst den Klassifikator allein, ohne die anderen Prüfungen:

| Zurückgehaltener Test | Nachrichten | Präzision | Trefferquote | Fehlalarme | Unsicher |
| --------------------- | ----------: | --------: | -----------: | ---------: | -------: |
| Englisch              |       6.564 |   100,0 % |       97,0 % |      0,0 % |    2,4 % |
| Russisch              |       1.682 |   100,0 % |       97,4 % |      0,0 % |    2,2 % |
| Italienisch           |       1.389 |    98,1 % |       85,3 % |      1,8 % |   10,9 % |
| Deutsch               |       1.309 |    97,7 % |       76,1 % |      2,2 % |   20,7 % |
| Spanisch              |       1.281 |    97,5 % |       82,5 % |      2,6 % |   16,8 % |
| Enron-Spam            |       2.888 |   100,0 % |       93,1 % |      0,0 % |    4,5 % |
| all-scam-spam         |       4.236 |   100,0 % |       88,8 % |      0,0 % |   11,2 % |
| Alle                  |      13.840 |    99,2 % |       85,1 % |      0,5 % |   12,4 % |

Spam bedeutet hier eine Wahrscheinlichkeit des Klassifikators von 99 % oder mehr, der Punkt, an dem der Klassifikator allein den Spam-Schwellenwert erreicht. Bei einem Scan erhält Spam, bei dem er weniger sicher ist, trotzdem Punkte, und die anderen Prüfungen fügen ihre hinzu.

Die Ergebnisse für Deutsch, Spanisch und Italienisch stammen aus synthetischen Datensätzen, die nahezu identische Nachrichten enthalten, die sowohl als Spam als auch als Ham gelabelt sind: Ein Teil dieses Fehlers liegt in den Labels, nicht im Modell. E-Mails in Ihren eigenen Sprachen sind die beste Abhilfe. Die Zahlen für jede Sprache und jeden Datensatz stehen in `metadata.metrics` des Modells.

### Weitere Sprachen

`npm run model:train -- --with multilingual-sms` fügt die [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) hinzu: die SMS Spam Collection, maschinell in 21 Sprachen übersetzt. Sie ist nicht im mitgelieferten Modell enthalten, weil ihre Dataset Card eine GPL-Lizenz angibt; prüfen Sie, ob das dazu passt, wie Sie das Modell weitergeben. Damit trainiert, ergaben sich für Sprachen, die das mitgelieferte Modell kaum kennt, diese Ergebnisse auf den zurückgehaltenen Nachrichten:

| Sprache     | Nachrichten | Präzision | Trefferquote | Fehlalarme |
| ----------- | ----------: | --------: | -----------: | ---------: |
| Chinesisch  |         430 |   100,0 % |       82,3 % |      0,0 % |
| Arabisch    |         430 |   100,0 % |       84,6 % |      0,0 % |
| Koreanisch  |         412 |   100,0 % |       80,4 % |      0,0 % |
| Japanisch   |         486 |    96,0 % |       85,7 % |      0,5 % |
| Hindi       |         412 |   100,0 % |       63,9 % |      0,0 % |
| Französisch |         480 |    98,6 % |       94,2 % |      0,6 % |
| Türkisch    |         220 |   100,0 % |       73,1 % |      0,0 % |

### Neu trainieren

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Die Modelldatei

Ein Modell ist eine JSON-Datei: die Zahl der gelernten Spam- und Ham-Nachrichten und für jedes gehashte Merkmal, wie viele Spam- und Ham-Nachrichten es enthielten, sortiert und base64-kodiert. Sie enthält keine Wörter und keinen Nachrichtentext. `--max-features` behält nur die häufigsten Merkmale, `--min-count` verwirft seltene; beides tauscht Genauigkeit gegen Größe. Das mitgelieferte Modell behält 400.000 Merkmale in etwa 6 MB.

Modelle aus Spam Scanner 6 und früher lassen sich nicht laden: Sie haben andere Merkmale gehasht. Trainieren Sie ein neues aus denselben E-Mails.
