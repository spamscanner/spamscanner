<!-- source: 8263c06f1dab -->

# เริ่มต้นใช้งาน

Spam Scanner ต้องใช้ Node.js 18 ขึ้นไป หรือไม่ต้องใช้อะไรเลยหากใช้ไบนารีแบบสแตนด์อโลน


## ติดตั้ง

ติดตั้งเป็นเครื่องมือบรรทัดคำสั่ง:

```sh
npm install --global spamscanner
spamscanner version
```

ติดตั้งเป็นไลบรารีในโครงการ Node.js:

```sh
npm install spamscanner
```

ติดตั้งเป็นไบนารีแบบสแตนด์อโลนสำหรับ Linux หรือ macOS ที่รวม Node.js และโมเดลไว้ในตัว:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

ไบนารีสำหรับ Linux (x64 และ arm64), macOS (Intel และ Apple silicon) และ Windows แนบอยู่กับทุก [รุ่นที่เผยแพร่](https://github.com/spamscanner/spamscanner/releases)


## สแกนข้อความ

บันทึกข้อความเป็นไฟล์ (โปรแกรมอีเมลส่วนใหญ่เรียกเมนูนี้ว่า "Save as" หรือ "Show original") แล้วสแกน:

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

รหัสออกเป็น 0 สำหรับ ham 1 สำหรับสแปม และ 2 เมื่อเกิดข้อผิดพลาด สคริปต์จึงนำไปใช้ได้โดยตรง `--json` พิมพ์ผลลัพธ์ฉบับเต็ม และ `--headers` พิมพ์ข้อความพร้อมส่วนหัว `X-Spam-*` ที่เพิ่มเข้าไป

ข้อความรับมาจาก standard input ได้ด้วย:

```sh
cat message.eml | spamscanner scan -
```


## ใช้งานจาก Node.js

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJS ก็ใช้ได้:

```js
const SpamScanner = require('spamscanner');
```

`scan()` รับข้อความดิบเป็น Buffer สตริง Uint8Array หรือ readable stream สตริงจะถือเป็นเนื้อหาข้อความเสมอ: Spam Scanner จะไม่อ่านไฟล์เพียงเพราะสตริงดูเหมือนพาธ ใช้ `scanner.scanFile(path)` สำหรับไฟล์


## ให้ข้อมูลเกี่ยวกับเซสชัน SMTP

ที่อยู่ IP ของไคลเอนต์ ชื่อโฮสต์ที่ยืนยันแล้ว ชื่อ HELO และ envelope ช่วยให้ผลลัพธ์แม่นยำขึ้น: การยืนยันตัวตนต้องใช้ที่อยู่ IP และกฎการปลอมเป็นโดเมนของตัวเองต้องใช้ผู้รับ

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

แบบเดียวกันจากบรรทัดคำสั่ง:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## เปิดการตรวจเพิ่มเติม

การตรวจเหล่านี้ไม่ได้เปิดไว้โดยค่าเริ่มต้น เพราะแต่ละรายการต้องใช้บริการภายนอกหรือต้องมีการตัดสินใจ:

| การตรวจ                      | ตัวเลือกของไลบรารี                               | บรรทัดคำสั่ง                |
| ---------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC        | `authentication: true`                           | `--auth`                    |
| IP blocklist                 | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Domain blocklist สำหรับลิงก์ | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                       | `clamav: true` หรือ `clamav: {socket}`           | `--clamav [socket]`         |
| โมเดลภาษา                    | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| รายการอนุญาตและรายการปฏิเสธ  | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

โดยค่าเริ่มต้น โปรแกรมจะถาม resolver แบบกรองของ Cloudflare (1.1.1.2 สำหรับมัลแวร์ 1.1.1.3 สำหรับเนื้อหาสำหรับผู้ใหญ่) เกี่ยวกับโฮสต์ของลิงก์ ปิดได้ด้วย `phishing: {cloudflare: false}` หรือ `--no-cloudflare` [อะไรถูกส่งออกจากเครื่อง](security.md)

Spamhaus และ blocklist อื่นบางรายไม่ตอบคำขอที่ส่งผ่าน resolver สาธารณะ เช่น 8.8.8.8 หรือ 1.1.1.1 ให้ใช้ร่วมกับ caching resolver ในเครื่อง และตรวจข้อกำหนดการใช้งานของผู้ให้บริการสำหรับปริมาณอีเมลของคุณ


## ขั้นตอนถัดไป

* วางไว้หน้าเซิร์ฟเวอร์อีเมล: [Postfix และ Sendmail](postfix.md), [เซิร์ฟเวอร์อื่น ๆ](mail-servers.md)
* สอนด้วยอีเมลของคุณเอง: [การฝึกโมเดล](training.md)
* เพิ่มโมเดลภาษาสำหรับกรณีที่ตัดสินยาก: [โมเดลภาษา](llm.md)
