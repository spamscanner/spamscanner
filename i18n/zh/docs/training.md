<!-- source: c4f8c2c7aa5a -->

# 训练

内置模型开箱即用。用你自己的邮件训练的模型效果更好，因为它会学到你的 ham（正常邮件）是什么样子：你订阅的通讯、你同事的写作风格、你收到的语言。


## 训练模型

让 `train` 指向垃圾邮件和正常邮件的文件夹：

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

来源可以是：

* **mbox** 文件，也可以是 gzip 压缩的（`.mbox.gz`；其他 `.gz` 文件会被跳过），
* **Maildir**（读取其 `cur` 和 `new` 文件夹，跳过 `tmp`），
* 存放 `.eml` 文件的**文件夹**，递归读取，
* **数据集**：带有文本列和标签列的 CSV 或 JSON Lines 文件（`--dataset`）。名为 `text`、`message`、`body`、`email text`、`email`、`content`、`sms` 或 `v2` 的列或 JSON 字段，以及名为 `label`、`category`、`is_spam`、`spam`、`email type`、`class`、`type`、`label_text`、`v1` 或 `labels` 的列或 JSON 字段，不区分大小写，会被自动识别（在 JSON Lines 中，`label_text` 优先于 `label`）；否则请使用 `--text-column` 和 `--label-column`。不是对象的 JSON 行会被跳过。可以识别 `spam`、`1`、`phishing` 以及 `ham`、`0`、`not_spam`、`legitimate` 等标签。

重复的邮件只计一次。同时出现在垃圾邮件来源和正常邮件来源中的邮件会保留为垃圾邮件，因为垃圾邮件来源先被读取。要在内置模型的基础上训练而不是从空模型开始，请添加 `--merge`。

使用模型：

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

多少邮件才够：每类几百封就能得到有用的模型，几千封就能得到好的模型。让两类数量大致平衡，并把你不希望被过滤的邮件（密码重置、你自己的供应商发来的账单）放在正常邮件中。


## 测量效果

留出一部分邮件不参与训练，并在其上测量：

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

内置模型在 21 种语言、它从未见过的短信上的结果，其中大多数语言它几乎不了解：

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

精确率是指它判为垃圾邮件的邮件中有多少确实是垃圾邮件；召回率是指垃圾邮件中有多少被它识别出来。这里“不确定”的邮件计为漏判的垃圾邮件，尽管在实际扫描中，其他检查和语言模型仍可能识别出它们。需要关注的数字是误报：被判为垃圾邮件的正常邮件。在上面的运行中，模型对这些邮件中的大多数是不确定，而不是判错，这正是对于它见过邮件很少的语言所预期的行为。

`--json` 为脚本提供同样的数字。


## 从举报中学习

当用户把邮件移入或移出 Junk 文件夹时，逐封训练模型：

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

第一次 `learn` 会基于内置模型创建该文件。通过 HTTP，[HTTP API](http-api.md) 上的 `POST /learn/spam` 和 `/learn/ham` 作用相同；使用 `--allow-tell` 时，`spamc -L spam` 也可以对 [spamd 服务器](mail-servers.md#a-drop-in-for-spamassassins-spamd)使用。[Dovecot 的 IMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning) 可以在邮件被移动时调用其中任一种。

在 Node.js 中：

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

如果一封被举报为分类错误的邮件之前已被学习过，应先将它从错误的类别中撤销学习，再将它作为正确的类别学习。


## 内置模型

`model/classifier.json` 由 `npm run model:train` 从 Hugging Face 上的以下公开数据集构建，均采用开放许可证：

| 数据集                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | 许可证                        | 内容                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------ |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | 43 种语言的消息和电子邮件           |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | 公开研究语料库                    | Enron-Spam 语料库           |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | 俄语 Telegram 消息           |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german)、[-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian)、[-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                     | MIT                        | 合成邮件                     |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | 邮件列表、新闻通讯、垃圾邮件、钓鱼邮件和诈骗邮件 |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | 印度 14 种语言的消息             |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | 按类别划分的印度尼西亚语邮件           |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | 一家公司的西班牙语邮件              |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | 普通邮件：账单、预订、新闻通讯、促销和账户通知  |

正常邮件包括普通的企业和商店邮件（发票、订单和账户通知、新闻通讯、促销），因此这类邮件本身不会被判为垃圾邮件。

它从 77,564 封垃圾邮件和 112,586 封正常邮件中学习。脚本每十封留出一封，用其余邮件训练，并只测量分类器本身，不含其他检查：

| 留出测试          |     邮件 |    精确率 |   召回率 |   误报 |   不确定 |
| ------------- | -----: | -----: | ----: | ---: | ----: |
| 英语            |  8,515 | 100.0% | 96.4% | 0.0% |  2.6% |
| 俄语            |  1,680 | 100.0% | 97.4% | 0.0% |  2.3% |
| 意大利语          |  1,392 |  98.6% | 81.0% | 1.2% | 12.5% |
| 德语            |  1,314 |  97.8% | 72.5% | 2.1% | 22.6% |
| 西班牙语          |  2,088 |  98.5% | 56.1% | 0.4% | 15.7% |
| Enron-Spam    |  2,888 | 100.0% | 92.4% | 0.0% |  4.4% |
| all-scam-spam |  4,236 | 100.0% | 89.3% | 0.0% | 11.6% |
| 全部            | 18,967 |  99.6% | 77.2% | 0.2% | 15.8% |

这里的垃圾邮件是指分类器概率达到 99% 或以上，即分类器单独达到垃圾邮件阈值的那一点。在实际扫描中，它不那么确定的垃圾邮件仍会得到分值，其他检查也会加上各自的分值。

德语、西班牙语和意大利语的结果来自合成数据集，其中包含几乎相同却分别被标为垃圾邮件和正常邮件的邮件：部分误差来自标签，而不是模型。使用你自己语言的邮件是最好的解决办法。包含每种语言和每个数据集的数字记录在模型的 `metadata.metrics` 中。

### 更多语言

`npm run model:train -- --with multilingual-sms` 会加入 [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset)：机器翻译成 21 种语言的 SMS Spam Collection。它没有包含在内置模型中，因为其数据集卡片标注的是 GPL 许可证；请确认它是否适合你分享模型的方式。用它训练后，内置模型几乎不了解的语言的留出测试结果如下：

| 语言   |  邮件 |    精确率 |   召回率 |   误报 |
| ---- | --: | -----: | ----: | ---: |
| 中文   | 432 | 100.0% | 86.1% | 0.0% |
| 阿拉伯语 | 432 | 100.0% | 83.1% | 0.0% |
| 韩语   | 412 | 100.0% | 78.3% | 0.0% |
| 日语   | 486 |  96.1% | 87.5% | 0.5% |
| 印地语  | 494 | 100.0% | 76.2% | 0.0% |
| 法语   | 511 |  98.7% | 88.6% | 0.6% |
| 土耳其语 | 222 | 100.0% | 70.4% | 0.0% |

### 重新训练

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## 模型文件

模型是一个 JSON 文件：包含已学习的垃圾邮件和正常邮件数量，以及每个经过哈希的特征出现在多少封垃圾邮件和正常邮件中，排序后以 base64 编码。它不包含任何词语或邮件文本。`--max-features` 只保留最常见的特征，`--min-count` 丢弃罕见特征，以准确率换取体积；内置模型保留 400,000 个特征，约 6 MB。

Spam Scanner 6 及更早版本的模型无法加载：它们哈希的是不同的特征。请用同样的邮件训练一个新模型。
