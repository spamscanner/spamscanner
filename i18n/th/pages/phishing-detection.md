<!-- source: 0378a5e0f12b -->

<!--
label: การตรวจจับฟิชชิง
title: ตรวจจับฟิชชิงในอีเมล: โดเมนเลียนแบบ ลิงก์หลอกลวง และการปลอมแปลง
description: Spam Scanner ตรวจจับอีเมลฟิชชิงอย่างไร: โดเมนเลียนแบบ Unicode ลิงก์ที่แสดงที่อยู่หนึ่งแต่ไปอีกที่ ชื่อแบรนด์ในชื่อที่แสดง resolver ของ Cloudflare และ DMARC
keywords: ตรวจจับฟิชชิง, กรองอีเมลฟิชชิง, อีเมลหลอกลวง, โจมตีแบบ homograph, IDN homograph, ตรวจจับโดเมนปลอม, ลิงก์หลอกลวง, อีเมลแอบอ้างแบรนด์
-->

# การตรวจจับฟิชชิงในอีเมล

ฟิชชิงได้ผลเพราะทำตัวให้ดูเหมือนคนอื่น Spam Scanner ตรวจจุดที่การปลอมตัวเผยให้เห็น


## โดเมนเลียนแบบ

แต่ละโดเมนในลิงก์ถูกลดรูปเป็นโครงด้วยตาราง confusables ของ Unicode แล้วเทียบกับแบรนด์ที่ถูกแอบอ้างบ่อยเกือบ 100 แบรนด์:

| โดเมน                               | ตรวจพบในฐานะ             |
| ----------------------------------- | ------------------------ |
| `pаypal.com` (а แบบซีริลลิก)        | อักขระที่หน้าตาคล้ายกัน  |
| `paypa1-secure.top`                 | อักขระที่สลับกัน         |
| `xn--pple-43d.com`                  | Punycode ของ `аpple.com` |
| `paypal.com.account-verify.example` | แบรนด์ในโดเมนของผู้อื่น  |
| `paypall.com`                       | ต่างกันหนึ่งตัวอักษร     |

เพิ่มแบรนด์ได้ และใส่โดเมนที่คุณเป็นเจ้าของไว้ในรายการอนุญาตได้


## ลิงก์หลอกลวง

ลิงก์ HTML ที่ข้อความเป็นที่อยู่หนึ่งแต่ปลายทางเป็นอีกที่อยู่หนึ่ง เช่น ข้อความ `https://www.paypal.com/signin` ที่ชี้ไปที่ `http://paypa1-secure.top/login` จะเพิ่ม 3 คะแนน


## ชื่อที่แสดงและการปลอมแปลง

* ชื่อที่แสดงที่มีชื่อแบรนด์ ("PayPal Security") จากที่อยู่ในโดเมนอื่น
* ชื่อที่แสดงที่มีที่อยู่อีเมลอื่นอยู่ข้างใน
* อีเมลที่อ้างว่ามาจากโดเมนของผู้รับเองแต่ไม่ผ่าน SPF, DKIM และ DMARC


## เว็บไซต์อันตรายที่รู้จัก

โฮสต์ของลิงก์ถูกค้นหาใน resolver 1.1.1.2 ของ Cloudflare ซึ่งบล็อกเว็บไซต์มัลแวร์และฟิชชิงที่รู้จัก และเลือกค้นหาใน domain blocklist เช่น Spamhaus DBL ได้ด้วย


## ไฟล์แนบ

ฟิชชิงยังมาในรูปไฟล์แนบ HTML ที่วาดหน้าล็อกอินปลอมแบบออฟไลน์ และไฟล์โปรแกรมที่เปลี่ยนชื่อเป็น `.pdf` ทั้งสองแบบตรวจพบได้จากเนื้อหาของไฟล์

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

[การตรวจทำงานอย่างไร](../../docs/how-it-works.md#phishing)
