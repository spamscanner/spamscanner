<!-- source: 1562b843d858 -->

<!--
label: ทางเลือกแทน SpamAssassin
title: ทางเลือกแทน SpamAssassin ที่รองรับโปรโตคอล spamd
description: ใช้ Spam Scanner แทน spamd ของ SpamAssassin โดย spamc, Exim และ Haraka ทำงานต่อได้ ส่วนหัว X-Spam ใช้ชื่อเดิม และรองรับทุกภาษา
keywords: ทางเลือกแทน SpamAssassin, ใช้แทน spamd, spamc, ตัวกรองสแปม Exim, Haraka spamassassin, ทางเลือกแทน rspamd, X-Spam-Status, ตัวกรองอีเมลขยะ โอเพนซอร์ส
-->

# ทางเลือกแทน SpamAssassin ที่รองรับโปรโตคอล spamd

Spam Scanner ตอบโปรโตคอล spamd ของ SpamAssassin ซอฟต์แวร์ที่เขียนไว้สำหรับ SpamAssassin จึงใช้ได้โดยไม่ต้องแก้ไข: spamc, เงื่อนไข `spam` ของ Exim, ปลั๊กอิน `spamassassin` ของ Haraka และอื่น ๆ


## สลับมาใช้

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

โปรแกรมตอบ `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` และ `TELL` สำหรับการเรียนรู้เมื่อใช้ `--allow-tell` การทดสอบแบบ end-to-end ของโครงการรัน spamc ของ SpamAssassin เองกับเซิร์ฟเวอร์นี้


## สิ่งที่ยังเหมือนเดิม

* ส่วนหัว: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` และ `X-Spam-Status` ในรูปแบบของ SpamAssassin กฎ Sieve, procmail และโปรแกรมอีเมลที่มีอยู่จึงทำงานต่อได้
* คะแนนที่มีเกณฑ์ 5 ประกอบจากการทดสอบที่มีชื่อและคะแนน: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` เป็นต้น
* เปลี่ยนคะแนนของแต่ละการทดสอบได้ด้วยชื่อการทดสอบ


## สิ่งที่แตกต่าง

* **ภาษา** คำถูกตัดตามกฎของ Unicode ภาษาจีน ญี่ปุ่น และไทยจึงถูกอ่านเป็นคำ แทนที่จะเป็นสตริงยาวสตริงเดียว และการอำพราง เช่น อักขระที่มองไม่เห็น หรือตัวอักษรซีริลลิกในคำภาษาละติน จะถูกแปลงกลับก่อน
* **ฟิชชิง** โดเมนเลียนแบบ ลิงก์หลอกลวง และชื่อแบรนด์ในชื่อที่แสดงถูกตรวจโดยไม่ต้องมีกฎเพิ่มเติม
* **ไฟล์แนบ** ถูกระบุจากไบต์ของไฟล์: ไฟล์โปรแกรมที่เปลี่ยนชื่อเป็น `.pdf` ก็ยังเป็นไฟล์โปรแกรม
* **โมเดลภาษา** กรณีที่ตัดสินยากส่งไปให้โมเดลในเครื่องผ่าน Ollama หรือโมเดลแบบโฮสต์ได้
* **Node.js** ติดตั้งด้วย `npm install` ครั้งเดียว หรือใช้ไบนารีแบบสแตนด์อโลน ไม่ต้องดูแลโมดูล Perl หรืออัปเดตกฎ

Spam Scanner ไม่รันไฟล์กฎของ SpamAssassin และรูปแบบฐานข้อมูล Bayes เป็นของตัวเอง: ฝึกจากอีเมลชุดเดิมด้วย `spamscanner train`


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot และ procmail](../../docs/mail-servers.md)
