<!-- source: 6f344039ec5d -->

# 学習

同梱モデルは、そのままですぐに使えます。自分のメールで学習したモデルのほうがよく働きます。購読しているニュースレター、同僚の文章、受け取るメールの言語など、自分のハムがどのようなものかを学習するためです。


## モデルを学習させる

`train`にスパムとハムのフォルダーを指定します。

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

使えるソース：

* **mbox**ファイル（gzip圧縮したもの`.mbox.gz`も含む。その他の`.gz`ファイルはスキップする）
* **Maildir**（`cur`と`new`フォルダーを読み、`tmp`は読み飛ばします）
* `.eml`ファイルの**フォルダー**（再帰的に読みます）
* **データセット**：テキストの列とラベルの列を持つCSVまたはJSON Linesのファイル（`--dataset`）。`text`、`message`、`body`、`email text`、`email`、`content`、`sms`、`v2`という名前の列またはJSONフィールドと、`label`、`category`、`is_spam`、`spam`、`email type`、`class`、`type`、`label_text`、`v1`、`labels`という名前の列またはJSONフィールドは、大文字小文字を問わず自動的に見つけます（JSON Linesでは`label`より`label_text`を優先）。それ以外の場合は`--text-column`と`--label-column`を使ってください。オブジェクトでないJSONの行はスキップします。`spam`、`1`、`phishing`や、`ham`、`0`、`not_spam`、`legitimate`といったラベルを理解します。

重複したメッセージは1回だけ数えます。スパムとハムの両方のソースにあるメッセージは、スパムのソースを先に読むため、スパムとして残ります。空の状態からではなく同梱モデルをもとに学習させるには、`--merge`を追加します。

モデルを使う：

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

必要なメールの量の目安：それぞれ数百通あれば役に立つモデルに、数千通あれば良いモデルになります。両者の数はおおよそ釣り合わせ、フィルタリングしたくないメール（パスワードのリセット、自社の取引先からの請求書など）はハムに入れてください。


## 計測する

一部のメールを学習から外しておき、それで計測します。

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

同梱モデルを、一度も見たことのない21言語のSMSメッセージで計測した結果です。その多くは、モデルがほとんど知らない言語です。

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

適合率（Precision）は、スパムと判定したもののうち実際にスパムだった割合です。再現率（Recall）は、スパムのうち検出できた割合です。ここでは判定不能のメッセージをスパムの見逃しとして数えていますが、実際のスキャンではほかの検査や言語モデルがそれらを検出できます。注目すべき数値は誤検知、つまりスパムと判定されたハムです。上の実行結果では、モデルはこれらのメッセージの大半について誤った判定をするのではなく判定不能としています。これは、学習したメールが少ない言語で意図した動作です。

`--json`を使うと、同じ数値をスクリプト向けに出力します。


## 報告から学習する

ユーザーがメールを迷惑メールフォルダーに移動したり、そこから戻したりしたときは、メッセージを1通ずつモデルに学習させます。

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

最初の`learn`で、同梱モデルからファイルが作られます。HTTPでは、[HTTP API](http-api.md)の`POST /learn/spam`と`/learn/ham`が同じことを行い、`--allow-tell`を指定した[spamdサーバー](mail-servers.md#a-drop-in-for-spamassassins-spamd)に対しては`spamc -L spam`が使えます。[DovecotのIMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning)から、メッセージの移動時にどちらかを呼び出せます。

Node.jsからは次のようにします。

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

誤分類として報告されたメッセージを以前に学習させていた場合は、正しいクラスで学習させる前に、誤ったクラスから学習を取り消してください。


## 同梱モデル

`model/classifier.json`は、`npm run model:train`がHugging Faceにある次の公開データセットから作ります。いずれもオープンなライセンスです。

| データセット                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | ライセンス                      | 内容                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | -------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | 43言語のメッセージとメール                         |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | 公開研究用コーパス                  | Enron-Spamコーパス                         |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | ロシア語のTelegramメッセージ                     |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german)、[-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian)、[-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                     | MIT                        | 合成メッセージ                                |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | メーリングリスト、ニュースレター、スパム、フィッシング、詐欺メール      |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | インドの14言語のメッセージ                         |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | カテゴリ別のインドネシア語メール                       |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | ある企業のスペイン語メール                          |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | 通常のメール: 請求書、予約、ニュースレター、プロモーション、アカウント通知 |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | 人がアシスタントに頼むこと（20言語）                    |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                  | 架空の企業のフランス語メール                         |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | このプロジェクトと同じ                | このプロジェクトのために書いた、23言語の日常のメールと詐欺メール      |

ハムには通常の業務メールやショップのメール（請求書、注文やアカウントの通知、ニュースレター、プロモーション）が含まれるため、そうしたメールがそれだけでスパムと判定されることはありません。

データセット内のバウンスメールは除外されます。スパムの中にしか含まれておらず、すべてのバウンスメールがスパムだと分類器に学習させてしまうためです。

最後の3行は、ほかのデータセットにはほとんどスパムしかない言語（フランス語、ポルトガル語、オランダ語、北欧の言語、ポーランド語、トルコ語、アラビア語、日本語、韓国語、中国語など）の普通の文章です。これがなければ、こうした言語では普通の言葉がどれもスパムと読まれてしまいます。モデルが学習していない20言語の普通の文章10,000件のうち、確率が80%以上になるのは1.4%（この3行がなければ4.8%）、99%以上になるのは0.1%です。この文章は本物のメールではなく、各言語のために書いた詐欺メールもわずかです。分類器はこれらの言語の普通のメールをより確かに見分けられるようになりますが、スパムの検出はわずかに増えるだけです。

このモデルは81,254通のスパムと133,317通のハムから学習しました。スクリプトは10通に1通を取り分け、残りで学習し、ほかの検査を使わずに分類器単体を計測します。

| 取り分けたテスト      |  メッセージ |    適合率 |   再現率 |  誤検知 |  判定不能 |
| ------------- | -----: | -----: | ----: | ---: | ----: |
| 英語            |  8,481 | 100.0% | 96.3% | 0.0% |  2.6% |
| ロシア語          |  1,680 | 100.0% | 97.4% | 0.0% |  2.2% |
| イタリア語         |  1,392 |  99.0% | 81.0% | 0.9% | 12.6% |
| ドイツ語          |  1,314 |  97.9% | 71.4% | 1.9% | 22.3% |
| スペイン語         |  2,088 |  98.7% | 53.3% | 0.4% | 16.2% |
| Enron-Spam    |  2,870 | 100.0% | 95.2% | 0.0% |  2.6% |
| all-scam-spam |  4,222 |  99.9% | 92.2% | 0.0% |  9.1% |
| すべて           | 21,329 |  99.6% | 76.6% | 0.2% | 14.2% |

ここでのスパムは、分類器の確率が99%以上のものを指します。これは分類器単体でスパムのしきい値に達する点です。実際のスキャンでは、確信度がそれより低いスパムにも点数が付き、ほかの検査もそれぞれの点数を加えます。

ドイツ語、スペイン語、イタリア語の結果は合成データセットによるもので、ほぼ同じ内容のメッセージがスパムとハムの両方のラベルで含まれています。そのため誤りの一部はモデルではなくラベルにあります。最善の対策は、自分の言語のメールです。すべての言語とデータセットの数値は、モデルの`metadata.metrics`にあります。

### 言語を増やす

`npm run model:train -- --with multilingual-sms`は、[SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset)を追加します。これはSMS Spam Collectionを21言語に機械翻訳したものです。データセットのカードにGPLライセンスと記載されているため、同梱モデルには含めていません。モデルを共有する方法に合うかどうか確認してください。これを加えて学習させると、同梱モデルがほとんど知らない言語での、取り分けたテストの結果は次のとおりでした。

| 言語     | メッセージ |    適合率 |   再現率 |  誤検知 |
| ------ | ----: | -----: | ----: | ---: |
| 中国語    |   432 | 100.0% | 86.1% | 0.0% |
| アラビア語  |   432 | 100.0% | 83.1% | 0.0% |
| 韓国語    |   412 | 100.0% | 78.3% | 0.0% |
| 日本語    |   486 |  96.1% | 87.5% | 0.5% |
| ヒンディー語 |   494 | 100.0% | 76.2% | 0.0% |
| フランス語  |   511 |  98.7% | 88.6% | 0.6% |
| トルコ語   |   222 | 100.0% | 70.4% | 0.0% |

### 再学習させる

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## モデルファイル

モデルはJSONファイルです。学習したスパムとハムのメッセージ数と、ハッシュ化した各特徴を含んでいたスパムとハムのメッセージ数を、並べ替えてbase64でエンコードしたものが入っています。単語もメッセージのテキストも含みません。`--max-features`は最も頻度の高い特徴だけを残し、`--min-count`はまれな特徴を捨てます。どちらも精度と引き換えにサイズを小さくします。同梱モデルは40万の特徴を約6 MBで保持しています。

Spam Scanner 6以前のモデルは読み込めません。ハッシュ化する特徴が異なるためです。同じメールから新しいモデルを学習させてください。
