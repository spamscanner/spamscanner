<!-- source: 6f344039ec5d -->

# การฝึกโมเดล

โมเดลที่มาพร้อมแพ็กเกจใช้งานได้ทันที แต่โมเดลที่ฝึกจากอีเมลของคุณเองจะทำงานได้ดีกว่า เพราะเรียนรู้ว่า ham ของคุณมีลักษณะอย่างไร: จดหมายข่าวที่คุณรับ สำนวนการเขียนของเพื่อนร่วมงาน และภาษาที่คุณได้รับ


## ฝึกโมเดล

ชี้ `train` ไปที่โฟลเดอร์ของสแปมและ ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

แหล่งข้อมูลอาจเป็น:

* ไฟล์ **mbox** รวมถึงไฟล์ที่บีบอัดด้วย gzip (`.mbox.gz`; ไฟล์ `.gz` อื่นจะถูกข้าม)
* **Maildir** (อ่านโฟลเดอร์ `cur` และ `new` ข้าม `tmp`)
* **โฟลเดอร์** ของไฟล์ `.eml` อ่านแบบเรียกซ้ำลงไปในโฟลเดอร์ย่อย
* **ชุดข้อมูล**: ไฟล์ CSV หรือ JSON Lines ที่มีคอลัมน์ข้อความและคอลัมน์ป้ายกำกับ (`--dataset`) คอลัมน์หรือฟิลด์ JSON ชื่อ `text`, `message`, `body`, `email text`, `email`, `content`, `sms` หรือ `v2` และ `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` หรือ `labels` ไม่ว่าจะเป็นตัวพิมพ์เล็กหรือใหญ่ จะถูกตรวจพบเอง (ใน JSON Lines จะใช้ `label_text` ก่อน `label`) มิฉะนั้นให้ใช้ `--text-column` และ `--label-column` บรรทัด JSON ที่ไม่ใช่ออบเจ็กต์จะถูกข้าม ป้ายกำกับอย่าง `spam`, `1`, `phishing` และ `ham`, `0`, `not_spam`, `legitimate` เข้าใจได้ทั้งหมด

ข้อความที่ซ้ำกันนับเพียงครั้งเดียว ข้อความที่อยู่ทั้งในแหล่งสแปมและแหล่ง ham จะถูกเก็บเป็นสแปม เพราะแหล่งสแปมถูกอ่านก่อน หากต้องการต่อยอดจากโมเดลที่มาพร้อมแพ็กเกจแทนการเริ่มจากโมเดลว่าง ให้เพิ่ม `--merge`

ใช้โมเดล:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

อีเมลมากเท่าใดจึงพอ: ข้อความแต่ละประเภทไม่กี่ร้อยข้อความให้โมเดลที่ใช้งานได้ ไม่กี่พันข้อความให้โมเดลที่ดี รักษาจำนวนทั้งสองประเภทให้ใกล้เคียงกัน และใส่อีเมลที่คุณไม่ต้องการให้ถูกกรอง (อีเมลรีเซ็ตรหัสผ่าน ใบแจ้งหนี้จากซัพพลายเออร์ของคุณเอง) ไว้ใน ham


## วัดผล

กันอีเมลบางส่วนไว้ไม่ใช้ฝึก แล้ววัดผลกับอีเมลส่วนนั้น:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

โมเดลที่มาพร้อมแพ็กเกจ ทดสอบกับข้อความ SMS ใน 21 ภาษาที่ไม่เคยเห็น ซึ่งส่วนใหญ่เป็นภาษาที่โมเดลแทบไม่รู้จัก:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Precision คือสัดส่วนของสิ่งที่โมเดลเรียกว่าสแปมซึ่งเป็นสแปมจริง ส่วน recall คือสัดส่วนของสแปมที่โมเดลจับได้ ในที่นี้ข้อความที่ไม่แน่ใจนับเป็นสแปมที่พลาด แม้ว่าในการสแกนจริง การตรวจอื่นและโมเดลภาษายังจับได้อยู่ ตัวเลขที่ต้องจับตาคือผลบวกลวง: ham ที่ถูกตีว่าเป็นสแปม ในการรันข้างต้น โมเดลไม่แน่ใจเกี่ยวกับข้อความส่วนใหญ่ แทนที่จะตัดสินผิด ซึ่งเป็นพฤติกรรมที่ตั้งใจไว้สำหรับภาษาที่โมเดลมีอีเมลน้อย

`--json` ให้ตัวเลขชุดเดียวกันสำหรับสคริปต์


## เรียนรู้จากรายงาน

เมื่อผู้ใช้ย้ายอีเมลเข้าหรือออกจากโฟลเดอร์ Junk ให้สอนโมเดลทีละข้อความ:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

`learn` ครั้งแรกจะสร้างไฟล์จากโมเดลที่มาพร้อมแพ็กเกจ ผ่าน HTTP ใช้ `POST /learn/spam` และ `/learn/ham` บน [HTTP API](http-api.md) ได้ผลเหมือนกัน และ `spamc -L spam` ใช้ได้กับ[เซิร์ฟเวอร์ spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) เมื่อเปิด `--allow-tell` [IMAPSieve ของ Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) เรียกใช้วิธีใดก็ได้เมื่อข้อความถูกย้าย

จาก Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

ข้อความที่ถูกรายงานว่าจัดประเภทผิด ควรถูก unlearn ออกจากประเภทที่ผิดก่อนจะเรียนรู้ในประเภทที่ถูก หากเคยเรียนรู้ไว้แล้ว


## โมเดลที่มาพร้อมแพ็กเกจ

`model/classifier.json` สร้างโดย `npm run model:train` จากชุดข้อมูลสาธารณะเหล่านี้บน Hugging Face ซึ่งใช้สัญญาอนุญาตแบบเปิดทั้งหมด:

| ชุดข้อมูล                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | สัญญาอนุญาต                | เนื้อหา                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | -------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | ข้อความและอีเมลใน 43 ภาษา                                                  |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | คลังข้อมูลวิจัยสาธารณะ     | คลังข้อมูล Enron-Spam                                                      |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | ข้อความ Telegram ภาษารัสเซีย                                               |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | ข้อความสังเคราะห์                                                          |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | เมลลิงลิสต์ จดหมายข่าว สแปม ฟิชชิง และอีเมลหลอกลวง                         |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | ข้อความใน 14 ภาษาของอินเดีย                                                |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | อีเมลภาษาอินโดนีเซียตามหมวดหมู่                                            |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | อีเมลของบริษัทแห่งหนึ่งในภาษาสเปน                                          |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | อีเมลทั่วไป: ใบแจ้งหนี้ การจอง จดหมายข่าว โปรโมชัน และการแจ้งเตือนบัญชี    |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | สิ่งที่ผู้คนขอจากผู้ช่วยเสียง ใน 20 ภาษา                                   |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                  | อีเมลของบริษัทสมมติในภาษาฝรั่งเศส                                          |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | พร้อมกับโครงการนี้         | อีเมลในชีวิตประจำวันและอีเมลหลอกลวงใน 23 ภาษา ที่เขียนขึ้นสำหรับโครงการนี้ |

แฮมรวมถึงอีเมลธุรกิจและร้านค้าทั่วไป (ใบแจ้งหนี้ การแจ้งเตือนคำสั่งซื้อและบัญชี จดหมายข่าว โปรโมชัน) ดังนั้นอีเมลเช่นนี้เพียงอย่างเดียวจะไม่ถูกอ่านว่าเป็นสแปม

ข้อความตีกลับ (bounce) ในชุดข้อมูลจะถูกตัดออก เพราะมีอยู่เฉพาะในกลุ่มสแปม ซึ่งจะสอนให้ตัวจำแนกเข้าใจว่าข้อความตีกลับทุกฉบับเป็นสแปม

สามแถวสุดท้ายเป็นข้อความทั่วไปในภาษาที่ชุดข้อมูลอื่นมีแต่สแปมเป็นส่วนใหญ่ (ฝรั่งเศส โปรตุเกส ดัตช์ กลุ่มภาษานอร์ดิก โปแลนด์ ตุรกี อาหรับ ญี่ปุ่น เกาหลี จีน และอื่น ๆ) ซึ่งหากไม่มีข้อความเหล่านี้ คำทั่วไปทุกคำจะถูกอ่านว่าเป็นสแปม จากข้อความทั่วไป 10,000 ข้อความใน 20 ภาษาที่โมเดลไม่ได้ใช้ฝึก มี 1.4% ที่ได้ความน่าจะเป็น 80% ขึ้นไป (4.8% หากไม่มีแถวเหล่านี้) และ 0.1% ที่ได้ 99% ขึ้นไป ข้อความเหล่านี้ไม่ใช่อีเมลจริง และอีเมลหลอกลวงที่เขียนขึ้นสำหรับแต่ละภาษามีน้อย: ตัวจำแนกจะมั่นใจในอีเมลทั่วไปของภาษาเหล่านี้มากขึ้น และจับสแปมของภาษาเหล่านี้ได้เพิ่มขึ้นเพียงเล็กน้อย

โมเดลเรียนรู้จากสแปม 81,254 ข้อความและ ham 133,317 ข้อความ สคริปต์กันทุกข้อความที่สิบไว้ ฝึกด้วยส่วนที่เหลือ และวัดผลตัวจำแนกอย่างเดียว โดยไม่มีการตรวจอื่น:

| ชุดทดสอบที่กันไว้ | ข้อความ | Precision | Recall | ผลบวกลวง | ไม่แน่ใจ |
| ----------------- | ------: | --------: | -----: | -------: | -------: |
| ภาษาอังกฤษ        |   8,481 |    100.0% |  96.3% |     0.0% |     2.6% |
| ภาษารัสเซีย       |   1,680 |    100.0% |  97.4% |     0.0% |     2.2% |
| ภาษาอิตาลี        |   1,392 |     99.0% |  81.0% |     0.9% |    12.6% |
| ภาษาเยอรมัน       |   1,314 |     97.9% |  71.4% |     1.9% |    22.3% |
| ภาษาสเปน          |   2,088 |     98.7% |  53.3% |     0.4% |    16.2% |
| Enron-Spam        |   2,870 |    100.0% |  95.2% |     0.0% |     2.6% |
| all-scam-spam     |   4,222 |     99.9% |  92.2% |     0.0% |     9.1% |
| ทั้งหมด           |  21,329 |     99.6% |  76.6% |     0.2% |    14.2% |

สแปมในที่นี้หมายถึงความน่าจะเป็นจากตัวจำแนกตั้งแต่ 99% ขึ้นไป ซึ่งเป็นจุดที่ตัวจำแนกอย่างเดียวถึงเกณฑ์สแปม ในการสแกนจริง สแปมที่ตัวจำแนกมั่นใจน้อยกว่านั้นยังได้คะแนน และการตรวจอื่นก็เพิ่มคะแนนของตัวเองเข้าไป

ผลของภาษาเยอรมัน สเปน และอิตาลีมาจากชุดข้อมูลสังเคราะห์ ซึ่งมีข้อความที่แทบเหมือนกันแต่ติดป้ายทั้งสแปมและ ham: ความผิดพลาดส่วนหนึ่งจึงอยู่ที่ป้ายกำกับ ไม่ใช่โมเดล อีเมลในภาษาของคุณเองคือวิธีแก้ที่ดีที่สุด ตัวเลขของทุกภาษาและทุกชุดข้อมูลอยู่ใน `metadata.metrics` ของโมเดล

### ภาษาเพิ่มเติม

`npm run model:train -- --with multilingual-sms` เพิ่ม [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection ที่แปลด้วยเครื่องเป็น 21 ภาษา ชุดข้อมูลนี้ไม่ได้รวมไว้ในโมเดลที่มาพร้อมแพ็กเกจ เพราะ dataset card ระบุสัญญาอนุญาต GPL ตรวจสอบว่าเหมาะกับวิธีที่คุณแบ่งปันโมเดลหรือไม่ เมื่อฝึกรวมชุดข้อมูลนี้ ผลทดสอบที่กันไว้สำหรับภาษาที่โมเดลที่มาพร้อมแพ็กเกจแทบไม่รู้จักเป็นดังนี้:

| ภาษา         | ข้อความ | Precision | Recall | ผลบวกลวง |
| ------------ | ------: | --------: | -----: | -------: |
| ภาษาจีน      |     432 |    100.0% |  86.1% |     0.0% |
| ภาษาอาหรับ   |     432 |    100.0% |  83.1% |     0.0% |
| ภาษาเกาหลี   |     412 |    100.0% |  78.3% |     0.0% |
| ภาษาญี่ปุ่น  |     486 |     96.1% |  87.5% |     0.5% |
| ภาษาฮินดี    |     494 |    100.0% |  76.2% |     0.0% |
| ภาษาฝรั่งเศส |     511 |     98.7% |  88.6% |     0.6% |
| ภาษาตุรกี    |     222 |    100.0% |  70.4% |     0.0% |

### ฝึกใหม่

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## ไฟล์โมเดล

โมเดลเป็นไฟล์ JSON: จำนวนข้อความสแปมและ ham ที่เรียนรู้ และสำหรับแต่ละคุณลักษณะที่แฮชแล้ว จำนวนข้อความสแปมและ ham ที่มีคุณลักษณะนั้น เรียงลำดับและเข้ารหัสแบบ base64 ไฟล์ไม่มีคำและไม่มีเนื้อหาข้อความ `--max-features` เก็บเฉพาะคุณลักษณะที่พบบ่อยที่สุด และ `--min-count` ตัดคุณลักษณะที่พบน้อยออก โดยแลกความแม่นยำกับขนาด โมเดลที่มาพร้อมแพ็กเกจเก็บ 400,000 คุณลักษณะในขนาดประมาณ 6 MB

โมเดลจาก Spam Scanner 6 และก่อนหน้าโหลดไม่ได้ เพราะแฮชคุณลักษณะต่างกัน ให้ฝึกโมเดลใหม่จากอีเมลชุดเดิม
