<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner สร้างโดย [Forward Email](https://forwardemail.net) บริการอีเมลโอเพนซอร์สที่ให้ความสำคัญกับความเป็นส่วนตัว เพื่อใช้กับเซิร์ฟเวอร์อีเมลของตัวเอง Forward Email ไม่เก็บบันทึกเนื้อหาของข้อความ บริการกรองภายนอกจึงใช้ไม่ได้: ตัวกรองต้องทำงานบนเซิร์ฟเวอร์ของตัวเอง และต้องอธิบายแต่ละการตัดสินได้โดยไม่ต้องมีคนอ่านอีเมล

หน้านี้แสดงวิธีที่เซิร์ฟเวอร์อีเมลแบบเดียวกับของ Forward Email ใช้งาน Spam Scanner และสิ่งที่เปลี่ยนไปสำหรับโค้ดที่เขียนไว้สำหรับ Spam Scanner 5 หรือ 6


## บนเซิร์ฟเวอร์อีเมลขาเข้า

Forward Email รับอีเมลด้วย [smtp-server](https://nodemailer.com/extras/smtp-server/) รูปแบบการใช้งานสำหรับเซิร์ฟเวอร์ใดก็ได้ที่สร้างบน smtp-server:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()` รับสตรีม SMTP ได้โดยตรง หากมีผลจาก [mailauth](https://github.com/postalsys/mailauth) อยู่แล้ว ให้ข้าม `authentication` และส่งเพียงที่อยู่ IP

รหัสตอบกลับ 421 หรือ 451 ทำให้เซิร์ฟเวอร์ผู้ส่งเข้าคิวข้อความไว้และลองใหม่ภายหลัง กฎการปฏิเสธใหม่จึงเริ่มด้วยรหัสชั่วคราวได้ แล้วค่อยเปลี่ยนเป็น 550 เมื่อตรวจผลแล้ว โดยไม่สูญเสียอีเมลในระหว่างนั้น


## การอัปเกรดจากเวอร์ชัน 5 หรือ 6

เวอร์ชัน 7 เขียนใหม่ทั้งหมด constructor, `scan()` และฟิลด์ของผลลัพธ์ที่โค้ดของเวอร์ชัน 5 และ 6 อ่านยังใช้ได้ ส่วนตัวจำแนก โมเดล และการตรวจเสริมด้วย TensorFlow เปลี่ยนไป

### สิ่งที่ยังเหมือนเดิม

* `new SpamScanner(options)` และ `await scanner.scan(source)`
* `require('spamscanner')` คืนคลาส และ `import SpamScanner from 'spamscanner'` ใช้ได้
* `result.isSpam`, `result.message` และ `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` และ `.idnHomographAttack`
* แต่ละรายการใน `results.phishing`, `.executables`, `.arbitrary` และ `.viruses` แปลงเป็นสตริงข้อความแบบเดียวกับเดิม (`String(item)`, template literal, `message.includes('adult-related content')`) ตอนนี้รายการเหล่านี้เป็นออบเจ็กต์ที่มี `type`, `message` และรายละเอียด
* `getTokensAndMailFromSource()`, `getClassification()` และ `getTokens()`
* ตัวเลือกเหล่านี้แมปไปยังชื่อใหม่: `clamscan` เป็น `clamav`, `enableMacroDetection: false` เป็น `macros: false`, `enableArbitraryDetection: false` เป็น `arbitrary: false`, `enableAuthentication` พร้อม `authOptions` เป็น `authentication` และ `session`, `enableReputation` พร้อม `reputationOptions.apiUrl` เป็น `reputation`, `strictIDNDetection` เป็น `phishing.homograph.strictMode` รวมถึง `allowlist` และ `denylist` ส่วน `logger` และ `memoize` ยังรับได้แต่ไม่มีผล

### สิ่งที่เปลี่ยนไป

| เดิม                                                                            | ปัจจุบัน                                                                                                                                                  |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` อ่านไฟล์                                             | สตริงคือเนื้อหาข้อความ ใช้ `scanFile(path)` หรือส่ง Buffer                                                                                                |
| โมเดล naive Bayes ของคำ (`classifier.json`) ซึ่งตอนนี้โหลดไม่ได้แล้ว            | ตัวจำแนกและรูปแบบโมเดลใหม่ ฝึกใหม่ด้วย `spamscanner train` ([การฝึกโมเดล](training.md))                                                                   |
| การตรวจเนื้อหาเป็นพิษและ NSFW โหลดโมเดล TensorFlow จากเครือข่ายเมื่อใช้ครั้งแรก | ใช้โมเดลของคุณเอง: `toxicity: {model}` และ `nsfw: {model}` รับออบเจ็กต์ใดก็ได้ที่มีเมธอด `classify()` เช่น จาก `@tensorflow-models/toxicity` และ `nsfwjs` |
| `results.arbitrary` แสดงทุกรูปแบบที่ตรงกัน                                      | แสดงเฉพาะกฎที่แรงพอจะตีว่าเป็นสแปมได้ด้วยตัวเอง กฎทั้งหมดอยู่ใน `result.tests`                                                                            |
| คำตอบแบบใช่หรือไม่ใช่                                                           | `result.score`, `result.action` (`accept`, `tag` หรือ `reject`) และ `result.tests` ซึ่งแต่ละรายการมีคะแนนและเหตุผล                                        |
| `isSpam` ตัดสินโดยตัวจำแนกหรือการตรวจใดการตรวจหนึ่ง                             | `isSpam` คือคะแนนตั้งแต่ 5 ขึ้นไป เปลี่ยนเกณฑ์และคะแนนได้                                                                                                 |
| การตรวจชื่อเสียงกับ endpoint ของ Forward Email                                  | บริการด้านชื่อเสียงทั่วไป ปิดไว้เว้นแต่จะตั้ง `reputation.apiUrl`                                                                                         |

### สิ่งใหม่

* [โมเดลภาษา](llm.md) สำหรับกรณีที่ตัดสินยาก ทั้งแบบในเครื่องและแบบโฮสต์
* SPF, DKIM, DMARC และ ARC, DNS blocklist, resolver แบบกรองของ Cloudflare
* การตรวจไฟล์แนบตามเนื้อหา: ไฟล์โปรแกรมที่อำพราง ไฟล์บีบอัด มาโคร PDF ที่ทำงานได้
* [milter, HTTP API, เซิร์ฟเวอร์ TCP และเซิร์ฟเวอร์ spamd](mail-servers.md) และ[บรรทัดคำสั่ง](cli.md)
* การฝึก การประเมินผล และการเรียนรู้จากรายงาน ผ่านบรรทัดคำสั่งหรือ API
