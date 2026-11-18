<!-- source: 6f344039ec5d -->

# 학습

번들 모델은 설치하자마자 동작합니다. 직접 받은 메일로 학습한 모델은 더 잘 동작합니다. 뉴스레터, 동료의 글, 받는 메일의 언어처럼 실제로 받는 ham이 어떤 모습인지 배우기 때문입니다.


## 모델 학습

`train`에 스팸 폴더와 ham 폴더를 지정합니다.

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

다음을 입력으로 사용할 수 있습니다.

* **mbox** 파일(gzip으로 압축한 `.mbox.gz` 포함. 다른 `.gz` 파일은 건너뜁니다),
* **Maildir**(`cur`와 `new` 폴더를 읽고 `tmp`는 건너뜁니다),
* `.eml` 파일이 든 **폴더**(하위 폴더까지 읽습니다),
* **데이터 세트**: 텍스트 열과 레이블 열이 있는 CSV 또는 JSON Lines 파일(`--dataset`). 이름이 `text`, `message`, `body`, `email text`, `email`, `content`, `sms`, `v2`인 열이나 JSON 필드와 `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1`, `labels`인 열이나 JSON 필드는 대소문자에 관계없이 자동으로 찾습니다(JSON Lines에서는 `label_text`를 `label`보다 먼저 찾습니다). 그렇지 않으면 `--text-column`과 `--label-column`을 사용합니다. 객체가 아닌 JSON 줄은 건너뜁니다. `spam`, `1`, `phishing`과 `ham`, `0`, `not_spam`, `legitimate` 같은 레이블을 인식합니다.

중복 메시지는 한 번만 셉니다. 스팸 출처와 햄 출처 양쪽에 있는 메시지는 스팸 출처를 먼저 읽으므로 스팸으로 남습니다. 빈 모델에서 시작하지 않고 번들 모델 위에 학습하려면 `--merge`를 추가합니다.

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
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
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

| 데이터 세트                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | 라이선스                       | 내용                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ---------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | 43개 언어의 메시지와 이메일                   |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | 공개 연구용 말뭉치                 | Enron-Spam 말뭉치                     |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | 러시아어 Telegram 메시지                  |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | 합성 메시지                             |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | 메일링 리스트, 뉴스레터, 스팸, 피싱 및 사기 이메일     |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | 인도의 14개 언어로 된 메시지                  |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | 범주별 인도네시아어 이메일                     |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | 한 회사의 스페인어 메일                      |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | 일반 메일: 청구서, 예약, 뉴스레터, 프로모션 및 계정 알림 |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | 사람들이 어시스턴트에게 요청하는 말(20개 언어)        |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                  | 가상 회사의 프랑스어 메일                     |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | 이 프로젝트와 동일                 | 이 프로젝트를 위해 쓴 23개 언어의 일상 메일과 사기 메일  |

햄에는 일반적인 업무 메일과 상점 메일(청구서, 주문 및 계정 알림, 뉴스레터, 프로모션)이 포함되므로, 그런 메일이 그것만으로 스팸으로 읽히지는 않습니다.

데이터셋에 있는 반송 메일(바운스)은 제외합니다. 스팸에만 들어 있어, 모든 반송 메일이 스팸이라고 분류기가 학습하게 되기 때문입니다.

마지막 세 행은 다른 데이터셋에 스팸이 대부분인 언어(프랑스어, 포르투갈어, 네덜란드어, 북유럽 언어, 폴란드어, 터키어, 아랍어, 일본어, 한국어, 중국어 등)의 평범한 글입니다. 이것이 없으면 이런 언어에서는 평범한 단어가 모두 스팸으로 읽힙니다. 모델이 학습하지 않은 20개 언어의 평범한 글 10,000개 가운데 1.4%가 80% 이상의 확률을 받고(이 행들이 없으면 4.8%), 0.1%가 99% 이상의 확률을 받습니다. 이 글은 실제 메일이 아니며 언어마다 쓴 사기 메일도 적습니다. 분류기는 이들 언어의 평범한 메일을 더 확실히 알아보게 되지만, 스팸은 조금 더 잡아낼 뿐입니다.

스팸 메시지 81,254개와 ham 메시지 133,317개로 학습했습니다. 스크립트는 열 번째마다 메시지를 학습에서 제외하고, 나머지로 학습한 뒤, 다른 검사 없이 분류기만으로 성능을 측정합니다.

| 제외한 테스트 세트    |    메시지 |    정밀도 |   재현율 |   오탐 | unsure |
| ------------- | -----: | -----: | ----: | ---: | -----: |
| 영어            |  8,481 | 100.0% | 96.3% | 0.0% |   2.6% |
| 러시아어          |  1,680 | 100.0% | 97.4% | 0.0% |   2.2% |
| 이탈리아어         |  1,392 |  99.0% | 81.0% | 0.9% |  12.6% |
| 독일어           |  1,314 |  97.9% | 71.4% | 1.9% |  22.3% |
| 스페인어          |  2,088 |  98.7% | 53.3% | 0.4% |  16.2% |
| Enron-Spam    |  2,870 | 100.0% | 95.2% | 0.0% |   2.6% |
| all-scam-spam |  4,222 |  99.9% | 92.2% | 0.0% |   9.1% |
| 전체            | 21,329 |  99.6% | 76.6% | 0.2% |  14.2% |

여기서 스팸은 분류기 확률이 99% 이상인 경우를 뜻합니다. 분류기 단독으로 스팸 임계값에 이르는 지점입니다. 실제 검사에서는 분류기가 덜 확신하는 스팸도 점수를 받으며, 나머지 검사도 점수를 더합니다.

독일어, 스페인어, 이탈리아어 결과는 합성 데이터 세트에서 나왔습니다. 이 데이터 세트에는 거의 같은 메시지가 스팸과 ham 양쪽으로 레이블되어 있으므로, 오류의 일부는 모델이 아니라 레이블에 있습니다. 가장 좋은 해결책은 직접 받는 언어의 메일입니다. 모든 언어와 데이터 세트별 수치는 모델의 `metadata.metrics`에 있습니다.

### 추가 언어

`npm run model:train -- --with multilingual-sms`를 실행하면 SMS Spam Collection을 21개 언어로 기계 번역한 [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset)이 추가됩니다. 이 데이터 세트의 카드에는 GPL 라이선스가 표시되어 있어 번들 모델에서는 제외했습니다. 모델을 공유하는 방식에 맞는지 확인하십시오. 이 데이터 세트를 포함해 학습했을 때, 번들 모델이 거의 모르는 언어의 제외 테스트 결과는 다음과 같았습니다.

| 언어   | 메시지 |    정밀도 |   재현율 |   오탐 |
| ---- | --: | -----: | ----: | ---: |
| 중국어  | 432 | 100.0% | 86.1% | 0.0% |
| 아랍어  | 432 | 100.0% | 83.1% | 0.0% |
| 한국어  | 412 | 100.0% | 78.3% | 0.0% |
| 일본어  | 486 |  96.1% | 87.5% | 0.5% |
| 힌디어  | 494 | 100.0% | 76.2% | 0.0% |
| 프랑스어 | 511 |  98.7% | 88.6% | 0.6% |
| 터키어  | 222 | 100.0% | 70.4% | 0.0% |

### 다시 학습

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## 모델 파일

모델은 JSON 파일입니다. 학습한 스팸 메시지와 ham 메시지의 수, 그리고 해시된 각 특징이 몇 개의 스팸 메시지와 ham 메시지에 들어 있었는지를 정렬해 base64로 인코딩해 담습니다. 단어나 메시지 텍스트는 들어 있지 않습니다. `--max-features`는 가장 자주 나오는 특징만 남기고 `--min-count`는 드문 특징을 버려, 정확도를 조금 내주고 크기를 줄입니다. 번들 모델은 약 6MB에 특징 400,000개를 담고 있습니다.

Spam Scanner 6 이하의 모델은 불러올 수 없습니다. 다른 특징을 해시했기 때문입니다. 같은 메일로 새 모델을 학습하십시오.
