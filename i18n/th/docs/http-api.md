<!-- source: faf44f093f8b -->

# HTTP API เซิร์ฟเวอร์ TCP และ spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

เซิร์ฟเวอร์รอรับการเชื่อมต่อที่ 127.0.0.1 เว้นแต่ `--host` จะกำหนดเป็นอย่างอื่น เมื่อมีโทเค็น ทุกคำขอยกเว้น `/health` ต้องมี `Authorization: Bearer <token>` ให้วางไว้หลัง reverse proxy ที่ใช้ TLS ก่อนเปิดให้เข้าถึงจากนอกเครื่อง

| เมธอดและพาธ        | เนื้อหาคำขอ | คำตอบ                                                               |
| ------------------ | ----------- | ------------------------------------------------------------------- |
| `GET /health`      |             | `{"ok": true, "version": "7.0.0"}`                                  |
| `POST /scan`       | ข้อความดิบ  | [ผลการสแกน](api.md#the-result) เป็น JSON                            |
| `POST /check`      | ข้อความดิบ  | ข้อความพร้อมส่วนหัว `X-Spam-*` ที่เพิ่มเข้าไป เป็น `message/rfc822` |
| `POST /learn/spam` | ข้อความดิบ  | `{"ok": true, "learned": "spam"}` ต้องใช้โทเค็น                     |
| `POST /learn/ham`  | ข้อความดิบ  | `{"ok": true, "learned": "ham"}` ต้องใช้โทเค็น                      |

query parameter อธิบายเซสชัน SMTP:

| พารามิเตอร์  | ความหมาย                                                 |
| ------------ | -------------------------------------------------------- |
| `ip`         | ที่อยู่ IP ของไคลเอนต์                                   |
| `hostname`   | ชื่อ reverse DNS ของไคลเอนต์ที่ยืนยันแล้ว                |
| `helo`       | ชื่อ HELO หรือ EHLO ของไคลเอนต์                          |
| `from`       | ผู้ส่งใน envelope                                        |
| `to`         | ผู้รับ ระบุซ้ำหรือคั่นหลายรายด้วยเครื่องหมายจุลภาค       |
| `verbose=1`  | `/scan`: คืนรายการคำและหัวเรื่องด้วย                     |
| `subjectTag` | `/check`: เติมคำนำหน้าหัวเรื่องของสแปม เช่น `%5BSPAM%5D` |

`/check` ยังคืน `X-Spam-Flag`, `X-Spam-Score` และ `X-Spam-Action` เป็นส่วนหัวของคำตอบด้วย ไคลเอนต์จึงตัดสินใจได้โดยไม่ต้องแยกวิเคราะห์ข้อความ

ข้อความที่ใหญ่กว่า 25 MB จะได้ `413` การสแกนที่ล้มเหลวจะได้ `500` พร้อม `{"error": "..."}`

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

เมื่อใช้ `--out model.json` สิ่งที่ `/learn` สอนจะถูกบันทึกลงไฟล์นั้นหลังแต่ละคำขอ หากไม่ใช้ การเรียนรู้จะคงอยู่จนกว่าเซิร์ฟเวอร์จะรีสตาร์ต

จาก Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

จาก Python:

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## เซิร์ฟเวอร์ TCP

```sh
spamscanner server --port 7830
```

ส่งข้อความดิบ ปิดฝั่งส่งของการเชื่อมต่อ แล้วอ่าน JSON หนึ่งบรรทัด:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

เมื่อใช้ `--verbose` คำตอบจะเป็นข้อความหนึ่งบรรทัดแทน: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` หรือ `HAM -2.5/5.0 BAYES_00`


## spamd

```sh
spamscanner spamd --port 783
```

เซิร์ฟเวอร์ที่เข้ากันได้กับ SpamAssassin สำหรับ spamc, Exim, Haraka และไคลเอนต์ SpamAssassin อื่น ๆ [การตั้งค่า Exim และ Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| คำสั่ง          | คำตอบ                                                         |
| --------------- | ------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                     |
| `SYMBOLS`       | ผลตัดสินและชื่อของการทดสอบที่ทำงาน                            |
| `REPORT`        | ผลตัดสินและตารางของการทดสอบ คะแนน และเหตุผล                   |
| `REPORT_IFSPAM` | เหมือน `REPORT` แต่รายงานว่างสำหรับ ham                       |
| `PROCESS`       | ผลตัดสินและข้อความพร้อมส่วนหัว `X-Spam-*`                     |
| `HEADERS`       | ผลตัดสินและบล็อกส่วนหัวของข้อความพร้อมส่วนหัว `X-Spam-*`      |
| `PING`          | `PONG`                                                        |
| `SKIP`          | ไม่มี                                                         |
| `TELL`          | เรียนรู้สแปมหรือ ham เมื่อใช้ `--allow-tell` บันทึกลง `--out` |

คำขอที่บีบอัด (`Compress: zlib`) จะถูกปฏิเสธ
