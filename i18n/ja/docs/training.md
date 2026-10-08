<!-- source: 7cc30ff4ad91 -->

# 学習

同梱モデルは、そのままですぐに使えます。自分のメールで学習したモデルのほうがよく働きます。購読しているニュースレター、同僚の文章、受け取るメールの言語など、自分のハムがどのようなものかを学習するためです。


## モデルを学習させる

`train`にスパムとハムのフォルダーを指定します。

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

使えるソース：

* **mbox**ファイル（gzip圧縮したもの`.mbox.gz`も含む）
* **Maildir**（`cur`と`new`フォルダーを読み、`tmp`は読み飛ばします）
* `.eml`ファイルの**フォルダー**（再帰的に読みます）
* **データセット**：テキストの列とラベルの列を持つCSVまたはJSON Linesのファイル（`--dataset`）。`text`、`message`、`body`、`email`、`content`という名前の列と、`label`、`category`、`class`、`spam`、`is_spam`という名前の列は自動的に見つけます。それ以外の場合は`--text-column`と`--label-column`を使ってください。`spam`、`1`、`phishing`や、`ham`、`0`、`not_spam`、`legitimate`といったラベルを理解します。

重複したメッセージは1回だけ数えます。空の状態からではなく同梱モデルをもとに学習させるには、`--merge`を追加します。

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
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
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

| データセット                                                                                                                                                                                                                                                                                                                   | ライセンス      | 内容                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- | ------------------ |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                     | Apache-2.0 | 43言語のメッセージとメール     |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                   | 公開研究用コーパス  | Enron-Spamコーパス     |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                       | CC0-1.0    | ロシア語のTelegramメッセージ |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german)、[-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian)、[-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT        | 合成メッセージ            |

このモデルは62,480通のスパムと76,489通のハムから学習しました。スクリプトは10通に1通を取り分け、残りで学習し、ほかの検査を使わずに分類器単体を計測します。

| 取り分けたテスト      |  メッセージ |    適合率 |   再現率 |  誤検知 |  判定不能 |
| ------------- | -----: | -----: | ----: | ---: | ----: |
| 英語            |  6,564 | 100.0% | 97.0% | 0.0% |  2.4% |
| ロシア語          |  1,682 | 100.0% | 97.4% | 0.0% |  2.2% |
| イタリア語         |  1,389 |  98.1% | 85.3% | 1.8% | 10.9% |
| ドイツ語          |  1,309 |  97.7% | 76.1% | 2.2% | 20.7% |
| スペイン語         |  1,281 |  97.5% | 82.5% | 2.6% | 16.8% |
| Enron-Spam    |  2,888 | 100.0% | 93.1% | 0.0% |  4.5% |
| all-scam-spam |  4,236 | 100.0% | 88.8% | 0.0% | 11.2% |
| すべて           | 13,840 |  99.2% | 85.1% | 0.5% | 12.4% |

ここでのスパムは、分類器の確率が99%以上のものを指します。これは分類器単体でスパムのしきい値に達する点です。実際のスキャンでは、確信度がそれより低いスパムにも点数が付き、ほかの検査もそれぞれの点数を加えます。

ドイツ語、スペイン語、イタリア語の結果は合成データセットによるもので、ほぼ同じ内容のメッセージがスパムとハムの両方のラベルで含まれています。そのため誤りの一部はモデルではなくラベルにあります。最善の対策は、自分の言語のメールです。すべての言語とデータセットの数値は、モデルの`metadata.metrics`にあります。

### 言語を増やす

`npm run model:train -- --with multilingual-sms`は、[SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset)を追加します。これはSMS Spam Collectionを21言語に機械翻訳したものです。データセットのカードにGPLライセンスと記載されているため、同梱モデルには含めていません。モデルを共有する方法に合うかどうか確認してください。これを加えて学習させると、同梱モデルがほとんど知らない言語での、取り分けたテストの結果は次のとおりでした。

| 言語     | メッセージ |    適合率 |   再現率 |  誤検知 |
| ------ | ----: | -----: | ----: | ---: |
| 中国語    |   430 | 100.0% | 82.3% | 0.0% |
| アラビア語  |   430 | 100.0% | 84.6% | 0.0% |
| 韓国語    |   412 | 100.0% | 80.4% | 0.0% |
| 日本語    |   486 |  96.0% | 85.7% | 0.5% |
| ヒンディー語 |   412 | 100.0% | 63.9% | 0.0% |
| フランス語  |   480 |  98.6% | 94.2% | 0.6% |
| トルコ語   |   220 | 100.0% | 73.1% | 0.0% |

### 再学習させる

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## モデルファイル

モデルはJSONファイルです。学習したスパムとハムのメッセージ数と、ハッシュ化した各特徴を含んでいたスパムとハムのメッセージ数を、並べ替えてbase64でエンコードしたものが入っています。単語もメッセージのテキストも含みません。`--max-features`は最も頻度の高い特徴だけを残し、`--min-count`はまれな特徴を捨てます。どちらも精度と引き換えにサイズを小さくします。同梱モデルは40万の特徴を約6 MBで保持しています。

Spam Scanner 6以前のモデルは読み込めません。ハッシュ化する特徴が異なるためです。同じメールから新しいモデルを学習させてください。
