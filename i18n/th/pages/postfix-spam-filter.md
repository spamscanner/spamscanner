<!-- source: f33722183f00 -->

<!--
label: ตัวกรองสแปม Postfix
title: ตัวกรองสแปม Postfix ด้วย milter หรือตัวกรองเนื้อหา
description: กรองสแปมบนเซิร์ฟเวอร์ Postfix ด้วย milter หรือตัวกรองเนื้อหาของ Spam Scanner: การติดตั้ง systemd unit การปฏิเสธด้วย 4xx หรือ 5xx และโฟลเดอร์ Junk
keywords: ตัวกรองสแปม Postfix, Postfix milter, smtpd_milters, ตัวกรองเนื้อหา Postfix, Postfix กันสแปม, ปฏิเสธสแปม Postfix, ตั้งค่าเมลเซิร์ฟเวอร์ กันสแปม
-->

# ตัวกรองสแปม Postfix

Spam Scanner เริ่มกรองเซิร์ฟเวอร์ Postfix ได้ในเวลาประมาณห้านาที โปรแกรมทำงานเป็น milter ดังนั้น Postfix จะถามเกี่ยวกับแต่ละข้อความระหว่างเซสชัน SMTP และปฏิเสธสแปมได้ก่อนรับเข้ามา


## ติดตั้งและรัน

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` ตรวจ SPF, DKIM, DMARC และ ARC ส่วน `--subject-tag` ทำเครื่องหมายสแปมในหัวเรื่อง ทุกข้อความจะได้ส่วนหัว `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` และ `X-Spam-Action` และส่วนหัว `X-Spam-*` ที่ผู้ส่งใส่มาจะถูกลบออกก่อน


## เชื่อมต่อ Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` ปล่อยอีเมลผ่านโดยไม่กรองหาก milter ใช้งานไม่ได้ ส่วน `tempfail` จะขอให้ผู้ส่งลองใหม่แทน


## ปฏิเสธสแปมระหว่างเซสชัน SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

ข้อความที่ถึงเกณฑ์ปฏิเสธ (15 คะแนน) จะถูกปฏิเสธด้วย `451 4.7.1 Message rejected as spam` รหัส 451 เป็นการปฏิเสธชั่วคราว: ผู้ส่งเก็บข้อความไว้และลองใหม่ การตัดสินที่ผิดจึงทำให้เกิดแค่ความล่าช้า ไม่ใช่ข้อความสูญหาย เมื่อผลลัพธ์ดูถูกต้องแล้ว `--reject-code 550` จะทำให้การปฏิเสธเป็นแบบถาวร


## โดยไม่ใช้ milter

ตัวกรองเนื้อหาทำงานหลังจาก Postfix รับข้อความแล้ว: Postfix ส่งข้อความผ่าน pipe ไปยัง `spamscanner filter` ซึ่งเพิ่มส่วนหัวแล้วส่งกลับ ไม่มีการปฏิเสธใดระหว่างเซสชันเลย และความล้มเหลวจะเลื่อนการส่งออกไปเสมอแทนการตีกลับ [การตั้งค่าตัวกรองเนื้อหา](../../docs/postfix.md#content-filter)


## ย้ายสแปมไปที่ Junk

เมื่อใช้ Dovecot กฎ Sieve จะย้ายอีเมลที่ติดป้ายไว้:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## ทดสอบกับ Postfix จริง

การทดสอบแบบ end-to-end ของโครงการรัน Postfix ร่วมกับ milter และตัวกรองเนื้อหา: ham ถูกส่งถึงผู้รับพร้อมส่วนหัว และ `X-Spam-Flag` ที่ปลอมขึ้นถูกลบออก สแปมถูกติดป้าย และ GTUBE ถูกปฏิเสธด้วย 550 ระหว่างเซสชัน SMTP

ถัดไป: [คู่มือ Postfix และ Sendmail ฉบับเต็ม](../../docs/postfix.md) พร้อม systemd unit และ `INPUT_MAIL_FILTER` ของ Sendmail
