<!-- source: 7cc30ff4ad91 -->

# 학습

번들 모델은 설치하자마자 동작합니다. 직접 받은 메일로 학습한 모델은 더 잘 동작합니다. 뉴스레터, 동료의 글, 받는 메일의 언어처럼 실제로 받는 ham이 어떤 모습인지 배우기 때문입니다.


## 모델 학습

`train`에 스팸 폴더와 ham 폴더를 지정합니다.

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

다음을 입력으로 사용할 수 있습니다.

* **mbox** 파일(gzip으로 압축한 `.mbox.gz` 포함),
* **Maildir**(`cur`와 `new` 폴더를 읽고 `tmp`는 건너뜁니다),
* `.eml` 파일이 든 **폴더**(하위 폴더까지 읽습니다),
* **데이터 세트**: 텍스트 열과 레이블 열이 있는 CSV 또는 JSON Lines 파일(`--dataset`). 이름이 `text`, `message`, `body`, `email`, `content`인 열과 `label`, `category`, `class`, `spam`, `is_spam`인 열은 자동으로 찾습니다. 그렇지 않으면 `--text-column`과 `--label-column`을 사용합니다. `spam`, `1`, `phishing`과 `ham`, `0`, `not_spam`, `legitimate` 같은 레이블을 인식합니다.

중복 메시지는 한 번만 셉니다. 빈 모델에서 시작하지 않고 번들 모델 위에 학습하려면 `--merge`를 추가합니다.

모델 사용:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

필요한 메일의 양: 각 종류마다 수백 개면 쓸 만한 모델이, 수천 개면 좋은 모델이 됩니다. 두 종류의 양을 대략 맞추고, 필터링되면 안 되는 메일(비밀번호 재설정, 거래처에서 받은 청구서)은 ham에 넣어 두십시오.


## 성능 측정

일부 메일은 학습에서 빼 두고 그 메일로 측정합니다.

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

번들 모델이 본 적 없는 21개 언어의 SMS 메시지로 측정한 결과입니다. 대부분 모델이 거의 모르는 언어입니다.

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

정밀도는 스팸이라고 판정한 것 중 실제 스팸의 비율이고, 재현율은 스팸 중 잡아낸 비율입니다. 여기서는 unsure 메시지를 놓친 스팸으로 계산하지만, 실제 검사에서는 나머지 검사와 언어 모델이 여전히 잡아낼 수 있습니다. 주의해서 볼 숫자는 오탐, 즉 스팸으로 표시된 ham입니다. 위 결과에서 모델은 이 메시지 대부분에 대해 틀린 것이 아니라 확신하지 못했습니다. 메일을 거의 학습하지 못한 언어에 대해 의도한 동작입니다.

`--json`은 스크립트용으로 같은 숫자를 출력합니다.


## 신고 기반 학습

사용자가 메일을 Junk 폴더로 옮기거나 Junk 폴더에서 꺼내면, 메시지를 하나씩 모델에 학습시킵니다.

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

처음 `learn`을 실행하면 번들 모델로 파일을 만듭니다. HTTP로는 [HTTP API](http-api.md)의 `POST /learn/spam`과 `/learn/ham`이 같은 일을 하며, `--allow-tell`을 사용한 [spamd 서버](mail-servers.md#a-drop-in-for-spamassassins-spamd)에서는 `spamc -L spam`이 동작합니다. [Dovecot의 IMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning)는 메시지를 옮길 때 둘 중 하나를 호출할 수 있습니다.

Node.js에서:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

잘못 분류되었다고 신고된 메시지를 이전에 학습한 적이 있다면, 올바른 분류로 학습하기 전에 잘못된 분류에서 먼저 학습을 취소해야 합니다.


## 번들 모델

`model/classifier.json`은 `npm run model:train`이 Hugging Face의 다음 공개 데이터 세트로 빌드하며, 모두 공개 라이선스입니다.

| 데이터 세트                                                                                                                                                                                                                                                                                                                     | 라이선스       | 내용                |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0 | 43개 언어의 메시지와 이메일  |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | 공개 연구용 말뭉치 | Enron-Spam 말뭉치    |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0    | 러시아어 Telegram 메시지 |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT        | 합성 메시지            |

스팸 메시지 62,480개와 ham 메시지 76,489개로 학습했습니다. 스크립트는 열 번째마다 메시지를 학습에서 제외하고, 나머지로 학습한 뒤, 다른 검사 없이 분류기만으로 성능을 측정합니다.

| 제외한 테스트 세트    |    메시지 |    정밀도 |   재현율 |   오탐 | unsure |
| ------------- | -----: | -----: | ----: | ---: | -----: |
| 영어            |  6,564 | 100.0% | 97.0% | 0.0% |   2.4% |
| 러시아어          |  1,682 | 100.0% | 97.4% | 0.0% |   2.2% |
| 이탈리아어         |  1,389 |  98.1% | 85.3% | 1.8% |  10.9% |
| 독일어           |  1,309 |  97.7% | 76.1% | 2.2% |  20.7% |
| 스페인어          |  1,281 |  97.5% | 82.5% | 2.6% |  16.8% |
| Enron-Spam    |  2,888 | 100.0% | 93.1% | 0.0% |   4.5% |
| all-scam-spam |  4,236 | 100.0% | 88.8% | 0.0% |  11.2% |
| 전체            | 13,840 |  99.2% | 85.1% | 0.5% |  12.4% |

여기서 스팸은 분류기 확률이 99% 이상인 경우를 뜻합니다. 분류기 단독으로 스팸 임계값에 이르는 지점입니다. 실제 검사에서는 분류기가 덜 확신하는 스팸도 점수를 받으며, 나머지 검사도 점수를 더합니다.

독일어, 스페인어, 이탈리아어 결과는 합성 데이터 세트에서 나왔습니다. 이 데이터 세트에는 거의 같은 메시지가 스팸과 ham 양쪽으로 레이블되어 있으므로, 오류의 일부는 모델이 아니라 레이블에 있습니다. 가장 좋은 해결책은 직접 받는 언어의 메일입니다. 모든 언어와 데이터 세트별 수치는 모델의 `metadata.metrics`에 있습니다.

### 추가 언어

`npm run model:train -- --with multilingual-sms`를 실행하면 SMS Spam Collection을 21개 언어로 기계 번역한 [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset)이 추가됩니다. 이 데이터 세트의 카드에는 GPL 라이선스가 표시되어 있어 번들 모델에서는 제외했습니다. 모델을 공유하는 방식에 맞는지 확인하십시오. 이 데이터 세트를 포함해 학습했을 때, 번들 모델이 거의 모르는 언어의 제외 테스트 결과는 다음과 같았습니다.

| 언어   | 메시지 |    정밀도 |   재현율 |   오탐 |
| ---- | --: | -----: | ----: | ---: |
| 중국어  | 430 | 100.0% | 82.3% | 0.0% |
| 아랍어  | 430 | 100.0% | 84.6% | 0.0% |
| 한국어  | 412 | 100.0% | 80.4% | 0.0% |
| 일본어  | 486 |  96.0% | 85.7% | 0.5% |
| 힌디어  | 412 | 100.0% | 63.9% | 0.0% |
| 프랑스어 | 480 |  98.6% | 94.2% | 0.6% |
| 터키어  | 220 | 100.0% | 73.1% | 0.0% |

### 다시 학습

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## 모델 파일

모델은 JSON 파일입니다. 학습한 스팸 메시지와 ham 메시지의 수, 그리고 해시된 각 특징이 몇 개의 스팸 메시지와 ham 메시지에 들어 있었는지를 정렬해 base64로 인코딩해 담습니다. 단어나 메시지 텍스트는 들어 있지 않습니다. `--max-features`는 가장 자주 나오는 특징만 남기고 `--min-count`는 드문 특징을 버려, 정확도를 조금 내주고 크기를 줄입니다. 번들 모델은 약 6MB에 특징 400,000개를 담고 있습니다.

Spam Scanner 6 이하의 모델은 불러올 수 없습니다. 다른 특징을 해시했기 때문입니다. 같은 메일로 새 모델을 학습하십시오.
