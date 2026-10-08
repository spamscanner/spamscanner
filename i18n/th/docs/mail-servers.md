<!-- source: 1151282f29d3 -->

# เซิร์ฟเวอร์อีเมลอื่น ๆ

Spam Scanner รองรับสี่โปรโตคอล ซอฟต์แวร์อีเมลส่วนใหญ่จึงใช้ได้โดยไม่ต้องมีปลั๊กอินเฉพาะ:

| โปรโตคอล | คำสั่ง                                   | ใช้โดย                                                                |
| -------- | ---------------------------------------- | --------------------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (ร่วมกับ filter-milter)                  |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka และซอฟต์แวร์ใดก็ได้ที่เขียนไว้สำหรับ SpamAssassin |
| HTTP     | `spamscanner http`                       | สคริปต์, webhook, MTA และบริการที่สร้างขึ้นเอง                        |
| Pipe     | `spamscanner scan`, `spamscanner filter` | pipe ของ Postfix, procmail, maildrop, งาน cron                        |

[Postfix และ Sendmail](postfix.md) มีหน้าของตัวเอง


## ใช้แทน spamd ของ SpamAssassin ได้ทันที

`spamscanner spamd` ตอบโปรโตคอล spamd ของ SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` และ `TELL` เมื่อใช้ `--allow-tell` ซอฟต์แวร์ที่เขียนไว้สำหรับ SpamAssassin ทำงานได้โดยไม่ต้องแก้ไข หยุด `spamd` แล้วเริ่ม Spam Scanner บนพอร์ตเดิม

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

ใช้กับ spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

การทดสอบแบบ end-to-end ของ repository รัน spamc ของ SpamAssassin เองกับเซิร์ฟเวอร์นี้


## Exim

เงื่อนไข ACL `spam` ของ Exim สื่อสารกับ spamd ในการตั้งค่าหลัก:

```text
spamd_address = 127.0.0.1 783
```

ใน DATA ACL (`acl_check_data` ใน exim4 ของ Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` ตอบด้วยข้อผิดพลาดชั่วคราว 4xx ผู้ส่งจึงลองใหม่ และแก้ไขข้อผิดพลาดได้ เปลี่ยนเป็น `deny` เพื่อปฏิเสธถาวรเมื่อผลลัพธ์ดูถูกต้องแล้ว


## Haraka

ปลั๊กอิน `spamassassin` ของ Haraka สื่อสารกับ spamd เปิดใช้ใน `config/plugins` แล้วตั้งค่าใน `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: โฟลเดอร์ Junk และการเรียนรู้

กฎ Sieve ย้ายอีเมลที่ติดป้ายไว้ไปที่ Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

เมื่อใช้ IMAPSieve การย้ายข้อความเข้าหรือออกจาก Junk จะสอนโมเดลได้ เริ่ม HTTP API พร้อมโทเค็นและไฟล์โมเดล:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

แล้วชี้ milter หรือเซิร์ฟเวอร์ spamd ไปที่โมเดลเดียวกันด้วย `--model /var/lib/spamscanner/model.json` (หรือ `SPAMSCANNER_MODEL`) รีสตาร์ตเป็นระยะเพื่อให้โหลดสิ่งที่เรียนรู้ไว้ สคริปต์ที่ `sieve_pipe` รันจะส่งข้อความไปด้วย POST:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

[คู่มือการรายงานสแปม](https://doc.dovecot.org/main/core/config/spam_reporting.html)ของ Dovecot แสดงการตั้งค่าส่วนที่เหลือ ซึ่งเหมือนกันสำหรับตัวกรองสแปมทุกตัวที่เรียนรู้ผ่านสคริปต์


## procmail และ maildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop:

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

`scan --headers` ออกด้วยรหัส 1 สำหรับสแปม procmail และ maildrop ใช้เอาต์พุต ไม่ใช่รหัสออก ตามกฎข้างต้น


## HTTP API

โปรแกรมใดก็ได้ที่ส่งคำขอ HTTP ได้สามารถสแกนอีเมลได้:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API](http-api.md) แสดงรายการ endpoint ทั้งหมด


## ภายในเซิร์ฟเวอร์อีเมลที่เขียนด้วย Node.js

เมื่อใช้ [smtp-server](https://nodemailer.com/extras/smtp-server/) ปลั๊กอินของ Haraka หรือเซิร์ฟเวอร์ Node.js อื่นใด ให้เรียกไลบรารีโดยตรง:

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({authentication: true});

// smtp-server's onData handler
async function onData(stream, session, callback) {
  const result = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (result.action === 'reject') {
    const error = new Error('Message rejected as spam');
    error.responseCode = 451;
    return callback(error);
  }

  // Deliver, with result.isSpam deciding the folder.
  callback();
}
```

`session.envelope` จาก smtp-server มีรูปแบบ `mailFrom` และ `rcptTo` ที่ Spam Scanner อ่านอยู่แล้ว
