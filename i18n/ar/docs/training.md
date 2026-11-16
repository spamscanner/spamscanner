<!-- source: c4f8c2c7aa5a -->

# التدريب

يعمل النموذج المرفق مباشرة دون إعداد. والنموذج المدرَّب على بريدك يعمل أفضل، لأنه يتعلّم شكل البريد المرغوب لديك: نشراتك الإخبارية، وأسلوب كتابة زملائك، واللغات التي تستقبلها.


## درّب نموذجًا

وجّه `train` إلى مجلدات البريد المزعج والمرغوب:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

يمكن أن تكون المصادر:

* ملفات **mbox**، حتى المضغوطة بـ gzip (`.mbox.gz`؛ وتُتخطى ملفات `.gz` الأخرى)،
* **Maildir** (يُقرأ مجلدا `cur` و`new`، ويُتخطى `tmp`)،
* **مجلد** ملفات `.eml`، يُقرأ تعاوديًا،
* **مجموعة بيانات**: ملف CSV أو JSON Lines بعمود نص وعمود تصنيف (`--dataset`). تُكتشف تلقائيًا الأعمدة، أو حقول JSON، المسماة `text` أو `message` أو `body` أو `email text` أو `email` أو `content` أو `sms` أو `v2`، و`label` أو `category` أو `is_spam` أو `spam` أو `email type` أو `class` أو `type` أو `label_text` أو `v1` أو `labels`، بأي حالة أحرف (وفي JSON Lines يأتي `label_text` قبل `label`)؛ وإلا فاستخدم `--text-column` و`--label-column`. ويُتخطى سطر JSON الذي ليس كائنًا. تُفهم تصنيفات مثل `spam` و`1` و`phishing`، و`ham` و`0` و`not_spam` و`legitimate`.

تُعدّ الرسائل المكررة مرة واحدة. والرسالة الموجودة في مصادر spam وham معًا تُحفظ على أنها spam، لأن مصادر spam تُقرأ أولًا. للبناء على النموذج المرفق بدل البدء من نموذج فارغ، أضف `--merge`.

استخدم النموذج:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

كم من البريد يكفي: بضع مئات من الرسائل من كل نوع تعطي نموذجًا مفيدًا، وبضعة آلاف تعطي نموذجًا جيدًا. حافظ على توازن تقريبي بين النوعين، واحتفظ بالبريد الذي لا تريد ترشيحه (إعادة تعيين كلمات المرور، وفواتير مورّديك) ضمن البريد المرغوب.


## قِس أداءه

أبقِ بعض البريد خارج التدريب وقِس الأداء عليه:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

النموذج المرفق على رسائل SMS بـ 21 لغة لم يرها قط، معظمها بلغات لا يكاد يعرفها:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

الدقة هي نسبة ما يسمّيه بريدًا مزعجًا وهو مزعج فعلًا؛ والاستدعاء هو نسبة البريد المزعج الذي يلتقطه. تُحسب الرسائل غير المؤكدة هنا بريدًا مزعجًا فائتًا، مع أن الفحوص الأخرى والنموذج اللغوي ما زال بإمكانها التقاطها أثناء الفحص. الرقم الذي يجب مراقبته هو الإيجابيات الكاذبة: بريد مرغوب وُسم بأنه مزعج. في التشغيل أعلاه، النموذج غير متأكد من معظم هذه الرسائل بدل أن يخطئ فيها، وهذا هو السلوك المقصود للغات التي لا يملك فيها إلا القليل من البريد.

يعطي `--json` الأرقام نفسها للسكربتات.


## التعلّم من التقارير

عندما ينقل المستخدمون البريد إلى مجلد Junk أو منه، علّم النموذج رسالة واحدة في كل مرة:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

ينشئ أول `learn` الملف من النموذج المرفق. عبر HTTP، يفعل `POST /learn/spam` و`/learn/ham` في [HTTP API](http-api.md) الشيء نفسه، ويعمل `spamc -L spam` مع [خادم spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) عند استخدام `--allow-tell`. يستطيع [IMAPSieve في Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) استدعاء أي منهما عند نقل رسالة.

من Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

الرسالة المبلَّغ عن تصنيفها خطأً ينبغي إلغاء تعلّمها من الفئة الخاطئة قبل تعلّمها في الفئة الصحيحة، إذا كانت قد تُعلِّمت من قبل.


## النموذج المرفق

يُبنى `model/classifier.json` بالأمر `npm run model:train` من مجموعات البيانات العامة هذه على Hugging Face، وكلها بتراخيص مفتوحة:

| مجموعة البيانات                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | الترخيص                    | المحتوى                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ---------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | رسائل ورسائل بريد إلكتروني بـ 43 لغة                                   |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | مدوّنة بحثية عامة          | مدوّنة Enron-Spam                                                      |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | رسائل Telegram روسية                                                   |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german)، [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian)، [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | رسائل اصطناعية                                                         |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | قوائم بريدية ونشرات إخبارية ورسائل مزعجة وتصيّد واحتيال                |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | رسائل بـ14 لغة من لغات الهند                                           |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | رسائل بريد إندونيسية حسب الفئة                                         |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | بريد شركة باللغة الإسبانية                                             |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | بريد عادي: فواتير وحجوزات ونشرات إخبارية وعروض ترويجية وإشعارات حسابات |

يتضمن البريد السليم بريد الأعمال والمتاجر العادي (الفواتير وإشعارات الطلبات والحسابات والنشرات الإخبارية والعروض الترويجية)، فلا يُقرأ هذا البريد وحده على أنه بريد مزعج.

تعلّم من 77,564 رسالة مزعجة و112,586 رسالة مرغوبة. يحجز السكربت كل رسالة عاشرة، ويتدرّب على البقية، ويقيس أداء المصنِّف وحده، دون الفحوص الأخرى:

| اختبار الرسائل المحجوزة | الرسائل |  الدقة | الاستدعاء | الإيجابيات الكاذبة | غير متأكد |
| ----------------------- | ------: | -----: | --------: | -----------------: | --------: |
| الإنجليزية              |   8,515 | 100.0% |     96.4% |               0.0% |      2.6% |
| الروسية                 |   1,680 | 100.0% |     97.4% |               0.0% |      2.3% |
| الإيطالية               |   1,392 |  98.6% |     81.0% |               1.2% |     12.5% |
| الألمانية               |   1,314 |  97.8% |     72.5% |               2.1% |     22.6% |
| الإسبانية               |   2,088 |  98.5% |     56.1% |               0.4% |     15.7% |
| Enron-Spam              |   2,888 | 100.0% |     92.4% |               0.0% |      4.4% |
| all-scam-spam           |   4,236 | 100.0% |     89.3% |               0.0% |     11.6% |
| الكل                    |  18,967 |  99.6% |     77.2% |               0.2% |     15.8% |

البريد المزعج هنا يعني احتمالًا بحسب المصنِّف قدره 99% أو أكثر، وهي النقطة التي يبلغ عندها المصنِّف وحده عتبة البريد المزعج. أثناء الفحص، يحصل البريد المزعج الذي يكون المصنِّف أقل تأكدًا منه على نقاط مع ذلك، وتضيف الفحوص الأخرى نقاطها.

تأتي نتائج الألمانية والإسبانية والإيطالية من مجموعات بيانات اصطناعية، تحتوي رسائل شبه متطابقة مصنّفة مزعجة ومرغوبة معًا: جزء من ذلك الخطأ في التصنيفات، لا في النموذج. البريد بلغاتك هو أفضل حل. الأرقام، بكل لغة ومجموعة بيانات، موجودة في `metadata.metrics` الخاص بالنموذج.

### لغات أخرى

يضيف `npm run model:train -- --with multilingual-sms` مجموعة [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): مجموعة SMS Spam Collection مترجمة آليًا إلى 21 لغة. استُبعدت من النموذج المرفق لأن بطاقتها تذكر ترخيص GPL؛ تحقق من أنها تناسب طريقة مشاركتك للنموذج. عند التدريب بها، كانت نتائج الرسائل المحجوزة للغات التي لا يكاد النموذج المرفق يعرفها:

| اللغة     | الرسائل |  الدقة | الاستدعاء | الإيجابيات الكاذبة |
| --------- | ------: | -----: | --------: | -----------------: |
| الصينية   |     432 | 100.0% |     86.1% |               0.0% |
| العربية   |     432 | 100.0% |     83.1% |               0.0% |
| الكورية   |     412 | 100.0% |     78.3% |               0.0% |
| اليابانية |     486 |  96.1% |     87.5% |               0.5% |
| الهندية   |     494 | 100.0% |     76.2% |               0.0% |
| الفرنسية  |     511 |  98.7% |     88.6% |               0.6% |
| التركية   |     222 | 100.0% |     70.4% |               0.0% |

### أعد تدريبه

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## ملف النموذج

النموذج ملف JSON: عدد الرسائل المزعجة والمرغوبة التي تعلّمها، ولكل سمة مجزّأة عدد الرسائل المزعجة والمرغوبة التي احتوتها، مرتّبة ومرمّزة بـ base64. لا يحتوي أي كلمات ولا أي نص رسائل. يحتفظ `--max-features` بأكثر السمات تكرارًا فقط، ويُسقط `--min-count` السمات النادرة، مقايضةً بين الدقة والحجم؛ ويحتفظ النموذج المرفق بـ 400,000 سمة في نحو 6 ميغابايت.

لا يمكن تحميل النماذج من Spam Scanner 6 وما قبله: فقد كانت تجزّئ سمات مختلفة. درّب نموذجًا جديدًا من البريد نفسه.
