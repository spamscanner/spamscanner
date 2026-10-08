<!-- source: f1043eb5fc58 -->

# Postfix และ Sendmail

Spam Scanner เชื่อมต่อกับ Postfix ได้สองวิธี:

* **ในรูป milter** (แนะนำ) Postfix ถาม Spam Scanner เกี่ยวกับแต่ละข้อความระหว่างเซสชัน SMTP ก่อนจะรับข้อความ สแปมจึงถูกปฏิเสธได้ด้วยรหัสตอบกลับ 4xx หรือ 5xx ทำให้เซิร์ฟเวอร์ผู้ส่งเป็นฝ่ายจัดการ ไม่ใช่เซิร์ฟเวอร์ของคุณ Sendmail ใช้โปรโตคอลเดียวกัน
* **ในรูปตัวกรองเนื้อหา** Postfix รับข้อความแล้วส่งผ่าน pipe ไปยัง `spamscanner filter` ซึ่งเพิ่มส่วนหัวแล้วส่งกลับด้วย sendmail จะไม่มีการปฏิเสธข้อความใดระหว่างเซสชัน SMTP เลย

ทั้งสองวิธีเพิ่มส่วนหัวเหล่านี้ให้ทุกข้อความ:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

ส่วนหัว `X-Spam-*` ที่มีอยู่แล้วในข้อความจะถูกลบออกก่อน ผู้ส่งจึงทำเครื่องหมายว่าอีเมลของตัวเองสะอาดไม่ได้


## Milter

### 1. รัน milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

เมื่อใช้ `--reject` ข้อความที่ถึงเกณฑ์ปฏิเสธ (15 คะแนน) จะถูกปฏิเสธด้วย `451 4.7.1 Message rejected as spam` รหัส 451 เป็นการปฏิเสธชั่วคราว: ผู้ส่งจะลองใหม่ภายหลัง และยังแก้ไขข้อผิดพลาดได้ด้วยการเปลี่ยนการตั้งค่า ใช้ `--reject-code 550` เพื่อปฏิเสธถาวรเมื่อผลลัพธ์ดูถูกต้องแล้ว เมื่อใช้ `--quarantine` สแปมจะไปอยู่ใน hold queue ของ Postfix แทน

ในรูปบริการ systemd ใน `/etc/systemd/system/spamscanner-milter.service`:

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. ชี้ Postfix ไปที่ milter

ใน `/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters` ครอบคลุมอีเมลที่เข้ามาทาง SMTP ปล่อย `non_smtpd_milters` ว่างไว้ เว้นแต่ต้องการสแกนอีเมลที่ส่งด้วยคำสั่ง `sendmail` ด้วย

### 3. ทดสอบ

[swaks](https://www.jetmore.org/john/code/swaks/) ส่งข้อความทดสอบ GTUBE เป็นสตริงทดสอบที่ตัวกรองสแปมทุกตัวถือว่าเป็นสแปม:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

หากไม่ใช้ `--reject` ข้อความจะถูกส่งถึงผู้รับพร้อม `X-Spam-Flag: YES` และหัวเรื่องที่ติดป้าย เมื่อใช้ `--reject` swaks จะแสดงรหัสตอบกลับ 451 หรือ 550


## ตัวกรองเนื้อหา

ใช้วิธีนี้เมื่ออีเมลต้องไม่ถูกปฏิเสธระหว่างเซสชัน SMTP เลย หรือสำหรับเซิร์ฟเวอร์ที่ใช้ milter ไม่ได้

ใน `/etc/postfix/master.cf` เพิ่มบริการตัวกรองแล้วใช้กับ listener ของ SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix รันตัวกรองด้วยสภาพแวดล้อมที่แทบว่างเปล่า `argv` จึงระบุ Node.js และสคริปต์ด้วยพาธเต็ม (`command -v node` และ `npm root --global` แสดงพาธเหล่านี้) จากนั้น:

```sh
sudo postfix reload
```

ตัวกรองส่งข้อความกลับด้วย `sendmail -G -i` อีเมลที่ส่งด้วยวิธีนี้ไม่ผ่าน listener `smtp` อีกครั้ง จึงไม่ถูกกรองซ้ำสองรอบ

รหัสออกบอก Postfix ว่าเกิดอะไรขึ้น: 0 ส่งแล้ว, 69 ถูกปฏิเสธ (เมื่อใช้ `--reject`: Postfix ตีกลับไปยังผู้ส่ง), 75 ล้มเหลวชั่วคราว (Postfix เก็บข้อความไว้และลองใหม่) ความล้มเหลวในการสแกนหรือการส่งใด ๆ จะเป็น 75 การตั้งค่าที่ผิดพลาดจึงไม่ทำให้อีเมลหายหรือถูกตีกลับ


## Sendmail

ใน `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` ทำให้ Sendmail ตอบด้วยความล้มเหลวชั่วคราวขณะที่ milter ใช้งานไม่ได้ หากต้องการรับอีเมลโดยไม่กรองแทน ให้ลบออก สร้าง `sendmail.cf` ใหม่แล้วรีสตาร์ต Sendmail


## คัดแยกสแปมไปยังโฟลเดอร์ Junk

การติดป้ายอย่างเดียวจะส่งสแปมไปที่กล่องจดหมายเข้า เมื่อใช้ Dovecot กฎ Sieve จะย้ายสแปมไปให้:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[เซิร์ฟเวอร์อีเมลอื่น ๆ](mail-servers.md) อธิบาย Dovecot, Exim, Haraka และ procmail และ[การฝึกโมเดล](training.md#learning-from-reports) แสดงวิธีเรียนรู้จากอีเมลที่ผู้ใช้ย้ายเข้าและออกจาก Junk


## การทดสอบ

การทดสอบแบบ end-to-end ของ repository รัน Postfix จริง: ham ถูกส่งถึงผู้รับพร้อมส่วนหัว `X-Spam-Flag` ที่ปลอมขึ้นถูกลบออก สแปมถูกติดป้าย GTUBE ถูกปฏิเสธด้วย 550 ระหว่างเซสชัน SMTP และตัวกรองเนื้อหาติดป้ายอีเมลบนพอร์ตที่สอง `scripts/e2e-postfix.sh` ตั้งค่า Postfix นั้น และ `test/e2e/postfix.test.js` ส่งอีเมล
