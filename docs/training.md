# Training

The bundled model works out of the box. A model trained on your own mail works better, because it learns what your ham looks like: your newsletters, your colleagues' writing, the languages you receive.


## Train a model

Point `train` at folders of spam and ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Sources can be:

* **mbox** files, also gzip-compressed (`.mbox.gz`),
* a **Maildir** (its `cur` and `new` folders are read, `tmp` is skipped),
* a **folder** of `.eml` files, read recursively,
* a **dataset**: a CSV or JSON Lines file with a text column and a label column (`--dataset`). Columns named `text`, `message`, `body`, `email` or `content`, and `label`, `category`, `class`, `spam` or `is_spam`, are found on their own; otherwise use `--text-column` and `--label-column`. Labels such as `spam`, `1`, `phishing` and `ham`, `0`, `not_spam`, `legitimate` are understood.

Duplicate messages are counted once. To build on the bundled model rather than start empty, add `--merge`.

Use the model:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

How much mail is enough: a few hundred messages of each kind give a useful model, a few thousand a good one. Keep the two roughly balanced, and keep mail you do not want to filter (password resets, invoices from your own suppliers) in the ham.


## Measure it

Keep some mail out of training and measure on it:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

The bundled model on SMS messages in 21 languages that it never saw, most of them in languages it barely knows:

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

Precision is how much of what it calls spam is spam; recall, how much of the spam it catches. Unsure messages count as missed spam here, though in a scan the other checks and the language model can still catch them. The number to watch is false positives: ham marked as spam. In the run above, the model is unsure about most of these messages rather than wrong about them, which is the intended behavior for languages it has little mail in.

`--json` gives the same numbers for scripts.


## Learning from reports

When users move mail into or out of a Junk folder, teach the model one message at a time:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

The first `learn` creates the file from the bundled model. Over HTTP, `POST /learn/spam` and `/learn/ham` on the [HTTP API](http-api.md) do the same, and `spamc -L spam` works against the [spamd server](mail-servers.md#a-drop-in-for-spamassassins-spamd) with `--allow-tell`. [Dovecot's IMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning) can call either when a message is moved.

From Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

A message reported as misclassified should be unlearned from the wrong class before it is learned in the right one, if it was learned before.


## The bundled model

`model/classifier.json` is built by `npm run model:train` from these public datasets on Hugging Face, all under open licenses:

| Dataset                                                                                                                                                                                                                                                                                                                    | License                | Content                             |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ----------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0             | Messages and emails in 43 languages |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Public research corpus | The Enron-Spam corpus               |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                | Russian Telegram messages           |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                    | Synthetic messages                  |

It learned from 62,480 spam and 76,489 ham messages. The script holds out every tenth message, trains on the rest and measures the classifier alone, without the other checks:

| Held-out test | Messages | Precision | Recall | False positives | Unsure |
| ------------- | -------: | --------: | -----: | --------------: | -----: |
| English       |    6,564 |    100.0% |  97.0% |            0.0% |   2.4% |
| Russian       |    1,682 |    100.0% |  97.4% |            0.0% |   2.2% |
| Italian       |    1,389 |     98.1% |  85.3% |            1.8% |  10.9% |
| German        |    1,309 |     97.7% |  76.1% |            2.2% |  20.7% |
| Spanish       |    1,281 |     97.5% |  82.5% |            2.6% |  16.8% |
| Enron-Spam    |    2,888 |    100.0% |  93.1% |            0.0% |   4.5% |
| all-scam-spam |    4,236 |    100.0% |  88.8% |            0.0% |  11.2% |
| All           |   13,840 |     99.2% |  85.1% |            0.5% |  12.4% |

Spam here means a classifier probability of 99% or more, the point at which the classifier alone reaches the spam threshold. In a scan, spam it is less sure of still gets points, and the other checks add theirs.

The German, Spanish and Italian results come from synthetic datasets, which contain near-identical messages labelled both spam and ham: part of that error is in the labels, not the model. Mail in your own languages is the best fix. The numbers, with every language and dataset, are in the model's `metadata.metrics`.

### More languages

`npm run model:train -- --with multilingual-sms` adds the [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): the SMS Spam Collection machine-translated into 21 languages. It is left out of the bundled model because its card gives a GPL license; check that it suits how you share the model. Trained with it, the held-out results for languages the bundled model barely knows were:

| Language | Messages | Precision | Recall | False positives |
| -------- | -------: | --------: | -----: | --------------: |
| Chinese  |      430 |    100.0% |  82.3% |            0.0% |
| Arabic   |      430 |    100.0% |  84.6% |            0.0% |
| Korean   |      412 |    100.0% |  80.4% |            0.0% |
| Japanese |      486 |     96.0% |  85.7% |            0.5% |
| Hindi    |      412 |    100.0% |  63.9% |            0.0% |
| French   |      480 |     98.6% |  94.2% |            0.6% |
| Turkish  |      220 |    100.0% |  73.1% |            0.0% |

### Retrain it

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## The model file

A model is a JSON file: the number of spam and ham messages learned, and for each hashed feature how many spam and ham messages contained it, sorted and base64-encoded. It holds no words and no message text. `--max-features` keeps only the most frequent features and `--min-count` drops rare ones, trading accuracy for size; the bundled model keeps 400,000 features in about 6 MB.

Models from Spam Scanner 6 and earlier cannot be loaded: they hashed different features. Train a new one from the same mail.
