<!-- source: b19ea85ceb6d -->

# เอกสารอ้างอิง API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

สร้างตัวสแกนครั้งเดียวแล้วนำกลับมาใช้ซ้ำ: ตัวสแกนจะโหลดโมเดลครั้งเดียว และแคชคำตอบจาก DNS และโมเดลภาษา

มีการประกาศชนิดข้อมูล (type declarations) มาให้ในแพ็กเกจ ต้องใช้ TypeScript 4.7 ขึ้นไปเมื่อใช้ `import` และ 5.3 ขึ้นไปเมื่อใช้ `require`


## ตัวเลือก

ส่งทุกตัวเลือกให้ constructor ได้ ตัวเลือกส่วนใหญ่ส่งให้ `scan()` สำหรับข้อความเดียวได้ด้วย ซึ่งจะผสานทับค่าของ constructor ตัวเลือกที่ส่งเป็น `undefined` จะคงค่าเริ่มต้นไว้ `classifier`, `classifierOptions`, `dns`, `phishing.homograph` และ `strictIDNDetection` อ่านโดยคอนสตรักเตอร์เท่านั้น ไฟล์หรืออ็อบเจกต์โมเดลที่ให้ใน `classifier` จะถูกอ่านตอนนั้น โมเดลที่หายไปหรือเสียหายจึงทำให้เกิดข้อผิดพลาดทันที

| ตัวเลือก                | ค่าเริ่มต้น                      | ความหมาย                                                                                                                                                                        |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | คะแนนที่ข้อความถือเป็นสแปม                                                                                                                                                      |
| `rejectThreshold`       | `15`                             | คะแนนที่ `action` เป็น `reject`                                                                                                                                                 |
| `scores`                | `{}`                             | คะแนนของแต่ละการทดสอบ: ระบุด้วยคีย์การตั้งค่าหรือชื่อการทดสอบ ([การทดสอบและคะแนน](scoring.md))                                                                                  |
| `classifier`            | โมเดลที่มาพร้อมแพ็กเกจ           | `Classifier` ออบเจ็กต์โมเดล พาธไฟล์โมเดล หรือ `false`                                                                                                                           |
| `classifierOptions`     | `{}`                             | ตัวเลือกสำหรับโมเดลที่มาพร้อมแพ็กเกจ (ดู [ตัวจำแนก](#classifier))                                                                                                               |
| `allowedLanguages`      | `[]`                             | รหัส ISO 639-1 (`no` อ่านเป็น `nb`, `fil` เป็น `tl` และรหัสเก่า `iw`, `in`, `ji` เป็น `he`, `id`, `yi`) ภาษาอื่นจะได้ `LANGUAGE_NOT_ALLOWED`                                    |
| `phishing.cloudflare`   | `true`                           | ถาม resolver แบบกรองของ Cloudflare เกี่ยวกับโฮสต์ของลิงก์                                                                                                                       |
| `phishing.adult`        | `true`                           | ถาม resolver สำหรับครอบครัวซึ่งบล็อกเว็บไซต์สำหรับผู้ใหญ่ด้วย                                                                                                                   |
| `phishing.maxHosts`     | `25`                             | จำนวนโฮสต์ของลิงก์ที่ค้นหาต่อข้อความ                                                                                                                                            |
| `phishing.maxLength`    | `1000000`                        | จำนวนอักขระของข้อความที่อ่านเพื่อหาลิงก์ (HTML อ่านเป็นสองเท่า) ข้อความที่ยาวกว่านี้จะตั้งค่า `results.linksTruncated`; `Infinity` หรือค่าใดที่ไม่ใช่จำนวนบวกหมายถึงค่าเริ่มต้น |
| `phishing.homograph`    | `{}`                             | `brands` (แทนที่รายการในตัว), `extraBrands`, `allowlist` (โดเมนที่ไม่ถูกตีว่าผิดเลย), `strictMode`                                                                              |
| `dnsbl`                 | `{ip: [], domain: []}`           | โซนของ DNS blocklist สำหรับ IP ของไคลเอนต์และโดเมนของลิงก์                                                                                                                      |
| `dns`                   | `{servers: null, timeout: 3000}` | name server สำหรับการตรวจทาง DNS (ค่าเริ่มต้น: ของระบบ)                                                                                                                         |
| `attachments`           | `true`                           | ตรวจไฟล์แนบ                                                                                                                                                                     |
| `macros`                | `true`                           | ตีธงมาโคร PDF ที่ทำงานได้ และออบเจ็กต์ RTF                                                                                                                                      |
| `arbitrary`             | `true`                           | รัน[กฎ](scoring.md#rules)                                                                                                                                                       |
| `authentication`        | `false`                          | `true` หรือ `{dnsServers, timeout, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([การให้คะแนน](scoring.md#authentication))                                          |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}` คำตอบจะถูกเก็บแยกตามบริการและเฮดเดอร์ และ `cacheSize` ใช้กับตัวสแกนทั้งตัว                  |
| `allowlist`, `denylist` |                                  | ที่อยู่ IP โดเมน หรือที่อยู่อีเมล รูปย่อของ `reputation` → [รายการอนุญาตและรายการปฏิเสธ](#allowlist-and-denylist)                                                               |
| `clamav`                | `false`                          | `true` (ซ็อกเก็ตค่าเริ่มต้น), `{socket}` หรือ `{host, port}` พร้อม `timeout`: มิลลิวินาทีสำหรับไฟล์แนบทั้งหมดของข้อความหนึ่งรวมกัน (`60000`)                                    |
| `llm`                   | `null`                           | [การตั้งค่าโมเดลภาษา](llm.md#any-server-port-and-authentication) พร้อม `mode`, `minScore`, `maxScore`                                                                           |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: โมเดลที่ `classify([text])` ตอบแบบเดียวกับ `@tensorflow-models/toxicity`                                                                            |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: โมเดลที่ `classify(imageBuffer)` ตอบแบบเดียวกับ `nsfwjs`                                                                                            |
| `maxLength`             | `100000`                         | จำนวนอักขระของเนื้อหาที่อ่าน                                                                                                                                                    |
| `timeout`               | `10000`                          | เวลาที่อนุญาตเป็นมิลลิวินาทีสำหรับการตรวจทางเครือข่ายแต่ละรายการ; การยืนยันตัวตนและโมเดลรูปภาพได้เวลาเท่านี้รวมทั้งหมด (ClamAV มี `clamav.timeout` ของตัวเอง)                   |
| `session`               | `{}`                             | รายละเอียดเซสชัน SMTP ค่าเริ่มต้น                                                                                                                                               |

`scan()` รับ `session` ด้วย:

```js
await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',             // the client's IP address
    resolvedClientHostname: 'mx.example.com', // its verified reverse DNS name
    helo: 'mx.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

เซิร์ฟเวอร์ที่ตรวจ SPF, DKIM, DMARC และ ARC ไปแล้ว (ด้วย [mailauth](https://github.com/postalsys/mailauth)) ส่งผลลัพธ์มาเป็น `authenticationResults` ได้ แล้วผลเหล่านั้นจะถูกนำไปคิดคะแนนแทนการตรวจซ้ำ:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### รายการอนุญาตและรายการปฏิเสธ

รายการปฏิเสธจะจับคู่ที่อยู่ IP และชื่อโฮสต์ของไคลเอนต์ ที่อยู่ From ผู้ส่งในซอง และ Reply-To รวมถึงโดเมนของที่อยู่เหล่านั้น ไม่ว่าจะเป็นอะไรก็ตาม: ชื่อที่อยู่ใต้โดเมนในรายการปฏิเสธจะจับคู่กับโดเมนนั้นแม้จะไม่ใช่ชื่อโฮสต์ที่ถูกต้อง (เช่น `a_b!.evil.example` หรือชื่อที่มีป้ายกำกับยาวเกิน 63 อักขระ) โดยใช้ 127 ป้ายกำกับและ 253 อักขระสุดท้ายของชื่อนั้น ส่วนรายการอนุญาต และรายการอนุญาตกับแหล่งที่เชื่อถือได้ของบริการชื่อเสียง จะจับคู่เฉพาะสิ่งที่ผู้ส่งปลอมแปลงไม่ได้ ได้แก่ ที่อยู่ IP และชื่อโฮสต์ที่ตรวจสอบแล้วของไคลเอนต์ (`remoteAddress`, `resolvedClientHostname`) ที่อยู่ From เมื่อ DMARC ผ่านสำหรับโดเมนของมันหรือมีลายเซ็น DKIM ที่ผ่านและสอดคล้องกัน (และเป็นชื่อโฮสต์ที่ถูกต้อง โดยสอดคล้องแบบผ่อนปรนเหมือนใน DMARC: โดเมน From และโดเมนที่ลงนามหรือโดเมน SPF มีโดเมนที่จดทะเบียนได้เดียวกัน ซึ่ง mailauth ระบุว่าเป็นโดเมน DMARC ส่วนรายการที่ระบุโดเมนย่อย เช่น `news.example.com` จะนับเฉพาะเมื่อโดเมนนั้น โดเมนที่อยู่ใต้โดเมนนั้น หรือโดเมนแม่ของโดเมนนั้นลงนามข้อความหรือผ่าน SPF ไม่ใช่โดเมนย่อยอื่น เช่น `evil.example.com` และไม่ใช่ public suffix ส่วนการผ่าน DMARC สำหรับโดเมนที่จดทะเบียนได้โดยไม่มีรายละเอียดความสอดคล้องจาก mailauth จะนับเฉพาะรายการที่ระบุโดเมนที่จดทะเบียนได้ ส่วนเมื่อใช้ความสอดคล้องแบบเข้มงวด คือมี `adkim=s` หรือ `aspf=s` ในเรคคอร์ด DMARC ของโดเมน ไม่ว่าจะใช้ตัวพิมพ์ใหญ่เล็กหรือเว้นวรรคแบบใด จะนับเฉพาะลายเซ็นหรือการผ่าน SPF ของโดเมน From เองเท่านั้น และหากไม่มีลายเซ็นหรือการผ่านดังกล่าว DMARC จะล้มเหลว) และผู้ส่งในซองเมื่อ SPF ผ่านสำหรับโดเมนของมัน ลายเซ็น DKIM ที่ลงนามเฉพาะส่วนต้นของเนื้อความ (ความยาวเนื้อความ `l=` สั้นกว่าเนื้อความ: ใครก็เพิ่มข้อความต่อท้ายได้) ไม่นับให้สิ่งใดเลย เช่นเดียวกับการผ่าน DMARC ที่อาศัยลายเซ็นแบบนั้น และเมื่อ DMARC ล้มเหลว จะไม่นับลายเซ็นใดเลย ผลลัพธ์ที่ส่งมาใน `authenticationResults` จะนับเฉพาะเมื่อระบุโดเมนที่ผ่าน และโดเมนที่ไม่ใช่ชื่อโฮสต์ (เช่น `bank.example/x.attacker.example` ซึ่งตัวแยกวิเคราะห์ URL อ่านเป็น `bank.example`) จะไม่นับให้โดเมนใดเลย เช่นเดียวกับการผ่าน DMARC ที่อาศัยโดเมนแบบนั้น โดเมนสากลจับคู่ได้ทั้งสองรูปแบบ: `bücher.example` หรือ `xn--bcher-kva.example` Reply-To ไม่นับเลย หากต้องการอนุญาตโดเมน ให้เปิด `authentication` หรือส่ง `authenticationResults`

แต่ละรายการคือที่อยู่ IP โดเมน หรือที่อยู่อีเมลหนึ่งรายการ ซึ่งจับคู่แบบตรงทุกตัว: รายการโดเมนครอบคลุมโดเมนย่อยของโดเมนนั้นและที่อยู่ภายใต้โดเมนเหล่านั้นด้วย แต่ไม่มีช่วงที่อยู่ (`192.0.2.0/24`) ไวลด์การ์ด (`*.example.com`) หรือรูปแบบ (`@example.com`) ที่อยู่ IPv6 จับคู่ได้ในทุกรูปแบบ (`2001:0db8::0001` คือ `2001:db8::1` ซึ่งเป็นรูปแบบตาม RFC 5952) ที่อยู่ IPv4 ที่แมปไว้ใน IPv6 (`::ffff:192.0.2.1`) จะจับคู่กับที่อยู่ IPv4 นั้น และที่อยู่ IPv4 ที่แปลงเป็น IPv6 หรืออยู่ใต้คำนำหน้า NAT64 จะเขียนพร้อมคำนำหน้านั้นในรูปแบบจุด (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`) ทั้งในรายการและในที่อยู่ของไคลเอนต์


## เมธอด

| เมธอด                                | ค่าที่คืน                                                                    |
| ------------------------------------ | ---------------------------------------------------------------------------- |
| `scan(source, options)`              | ผลลัพธ์ `source` เป็น Buffer สตริง Uint8Array หรือ readable stream           |
| `scanFile(path, options)`            | ผลลัพธ์สำหรับไฟล์ข้อความ                                                     |
| `learn(source, 'spam' \| 'ham')`     | สอนตัวจำแนกด้วยข้อความหนึ่งข้อความ                                           |
| `unlearn(source, 'spam' \| 'ham')`   | ยกเลิกผลของ `learn`                                                          |
| `saveModel(path, options)`           | เขียนตัวจำแนกลงไฟล์ (`options`: `minCount`, `maxFeatures`, `metadata`)       |
| `getClassifier()`                    | `Classifier` ที่ใช้อยู่ หรือ `null`                                          |
| `getClassification(features)`        | ผลตัดสินของตัวจำแนกสำหรับคุณลักษณะจาก `getFeatures`                          |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` ของข้อความ |
| `getTokens(text, locale)`            | คำในข้อความ                                                                  |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                   |
| `parse(source)`                      | `{raw, mail}` โดย `mail` มาจาก mailparser (ดูด้านล่าง)                       |

`scan`, `parse`, `learn`, `unlearn` และ `getTokensAndMailFromSource` ล้วนอ่านข้อความด้วยวิธีเดียวกัน: ข้อความที่เกินขีดจำกัดของตัวแยกวิเคราะห์ MIME (มากกว่า 1000 ส่วน หรือเฮดเดอร์ของส่วนหนึ่งเกิน 1 MB) จะถูกอ่านเท่าที่ตัวแยกวิเคราะห์อนุญาต ข้อความที่บรรทัดแรกไม่ใช่ฟิลด์เฮดเดอร์ (`Name: value` หรือบรรทัด `From` ที่ขึ้นต้นแต่ละข้อความในไฟล์ mbox) จะถูกอ่านเป็นเนื้อความของข้อความที่ไม่มีเฮดเดอร์ `mail.text` จึงเป็นข้อความนั้น ข้อผิดพลาดอื่นจะถูกโยนออกมา

ใน `getFeatures` นั้น `text` คือข้อความที่โปรแกรมอีเมลแสดง ซึ่งเป็นที่มาของคำที่อ่าน และ `hidden` คือจำนวนอักขระของข้อความที่ HTML ซ่อนไว้ ในที่นี้ mailparser ไม่ได้แปลง HTML เป็นข้อความ: `mail.text` มีเฉพาะส่วนที่เป็นข้อความธรรมดา และว่างเปล่าสำหรับข้อความที่มีแต่ HTML ส่วนข้อความที่ HTML แสดงคือ `getFeatures(mail).text`

`scanner.metrics` เก็บ `totalScans`, `averageTime` และ `lastScanTime`


## ผลลัพธ์

```js
{
  isSpam: true,
  score: 16.25,
  threshold: 5,
  rejectThreshold: 15,
  action: 'reject',                       // 'accept', 'tag' or 'reject'
  message: 'Spam (BAYES_999, PHISHING_LOOKALIKE_DOMAIN, DECEPTIVE_LINK, FROM_NAME_BRAND)',
  tests: [
    {name: 'BAYES_999', score: 6.25, description: 'Classifier spam probability 99.9%'},
    {name: 'PHISHING_LOOKALIKE_DOMAIN', score: 5, description: '"paypa1-secure.top" imitates paypal by swapping characters'},
    // ...
  ],
  results: {
    classification: {probability, category, spam, ham, clues, coverage},
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    virusScanErrors: [], // attachments ClamAV could not scan: {filename, error}
    virusScanSkipped: [], // attachments larger than clamd accepts, not scanned: {filename, reason}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value, answers} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'], // the links checked, of the whole message up to phishing.maxLength
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser; mail.text: the plain text parts only */},
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

สิ่งที่พบใน `phishing`, `attachments`, `executables`, `macros`, `viruses` และ `arbitrary` เป็นออบเจ็กต์ที่มี `type` และ `message` และ `String(finding)` ให้ค่าเป็นข้อความใน message ไฟล์แนบของข้อความที่แนบมา (`message/rfc822`, `.eml`) จะตั้งชื่อตามข้อความนั้น เช่น `fw.eml/invoice.exe` ไวรัสที่ ClamAV พบในไฟล์แนบเช่นนี้จะถูกรายงานสำหรับไฟล์แนบนั้นเท่านั้น ไม่รายงานซ้ำสำหรับข้อความที่แนบมาซึ่งบรรจุไฟล์นั้น ส่วน `virusScanErrors` แสดงไฟล์แนบที่ ClamAV สแกนไม่ได้ในรูป `{filename, error}` ข้อความเช่นนี้อาจมีไวรัส จึงควรกักไว้แทนการส่งต่อ milter และตัวกรองเนื้อหาจะเลื่อนข้อความนั้นออกไป เว้นแต่ `onError` (`--on-error`) เป็น `accept` และเซิร์ฟเวอร์ทุกแบบจะทำเครื่องหมายข้อความเช่นนี้ที่ส่งต่อไปด้วย `X-Spam-Virus-Scan: failed` ส่วน `virusScanSkipped` แสดงไฟล์แนบที่ใหญ่กว่าที่ clamd รับได้ (`StreamMaxLength` ของ clamd) ในรูป `{filename, reason}` clamd ปฏิเสธไฟล์เหล่านี้ทุกครั้งที่ลอง จึงไม่นับเป็นความล้มเหลว เช่นเดียวกับที่ clamav-milter ข้ามไฟล์ที่เกิน `MaxFileSize` ของมัน ส่วนขีดจำกัดอื่นของ clamd (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`) ซึ่ง archive bomb จะไปถึง นับเป็นความล้มเหลว

แต่ละรายการใน `dnsbl` มี `answers` ของรายการนั้น (ที่อยู่ในช่วง 127.0.0.0/8 ซึ่งแต่ละรายการระบุความหมายไว้ในเอกสารของตน) คำตอบที่รายการต่าง ๆ ให้กับคำค้นที่ปฏิเสธหรือตอบไม่ได้ไม่ถือเป็นการขึ้นรายการ ทั้งสำหรับที่อยู่ของไคลเอนต์และสำหรับโดเมนของลิงก์ (สิ่งที่พบแบบ `uribl` ใน `phishing`): 127.255.255.x ที่ Spamhaus (เช่น 127.255.255.254 สำหรับคำค้นที่ผ่าน resolver สาธารณะ และ 127.255.255.255 สำหรับคำค้นที่มากเกินไป) 127.0.1.255 ที่ Spamhaus DBL, 127.0.0.255 ที่รายการใดก็ได้ และ 127.0.0.1 ที่ SURBL และ URIBL ซึ่งให้คำตอบนี้กับ resolver ที่ถูกบล็อก


## สิ่งที่ export

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export

import ArfParser from 'spamscanner/arf';
```

### ตัวจำแนก

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| ตัวเลือก                               | ค่าเริ่มต้น    | ความหมาย                                                                                                                                                           |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `strength`, `unknown`                  | `0.45`, `0.5`  | ค่า s และ x ของ Robinson: คุณลักษณะที่พบน้อยถูกดึงเข้าหา 0.5 แรงเพียงใด                                                                                            |
| `minDistance`                          | `0.1`          | คุณลักษณะที่ใกล้ 0.5 กว่าค่านี้จะถูกละเว้น                                                                                                                         |
| `maxClues`                             | `150`          | จำนวนคุณลักษณะที่แรงที่สุดที่รวมกันต่อข้อความ                                                                                                                      |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | ขอบเขตของช่วง `unsure`                                                                                                                                             |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | จำนวนข้อความ ham ที่ต้องมีในภาษาหนึ่งเพื่อให้มั่นใจเต็มที่ และข้อความสแปมหนึ่งในห้าของจำนวนนั้น จะน้อยกว่านี้เมื่อ `languageShare` ของ ham หรือสแปมทั้งหมดน้อยกว่า |
| `languagePrior`                        | `true`         | ชั่งน้ำหนักคำเทียบกับจำนวนนับในภาษาของคำนั้นเอง                                                                                                                    |

ยังมี `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` และ `entries()` ให้ใช้ด้วย `Classifier.fromJSON` ตรวจสอบโมเดลและโยน `TypeError` ที่ขึ้นต้นด้วย `Corrupt classifier model` เมื่อข้อมูลเสียหาย JSON ไม่มี `Infinity` ดังนั้นตัวเลือกที่เวอร์ชัน 7.0.3 บันทึกเป็น `Infinity` จะอ่านกลับมาเป็น `null` ซึ่งจะถือเป็น `Infinity` สำหรับ `maxClues`, `minDistance` และ `minLanguageExamples` เป็น `-Infinity` สำหรับ `hamCutoff` (ไม่เป็น ham เลย) และ `Infinity` สำหรับ `spamCutoff` (ไม่เป็น spam เลย) และเป็นค่าเริ่มต้นสำหรับตัวเลือกอื่น `toJSON` บันทึกเกณฑ์ที่อยู่นอกช่วง 0 ถึง 1 เป็น -1 หรือ 2 ซึ่งให้ผลเหมือนกัน `loadModel` อ่านไฟล์ใหม่เมื่อไฟล์เปลี่ยน และ `saveModel` เขียนผ่านไฟล์ชั่วคราว

### การฝึกโมเดล

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` รับรายการ `{label, features}` หรือ `readExamples(sources)` ซึ่งอ่านแหล่งข้อมูลแบบเดียวกับ `train` แล้วคืนค่าจำนวนนับ precision, recall, F1, accuracy และอัตราผลบวกลวง ผลลบลวง และไม่แน่ใจ

### เซิร์ฟเวอร์

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` ของ milter คือคำตอบเมื่อการสแกนล้มเหลวหรือ ClamAV สแกนไฟล์แนบไม่ได้: `'tempfail'` (ค่าเริ่มต้น) หรือ `'accept'` ซึ่งจะส่งต่อข้อความโดยทำเครื่องหมาย `X-Spam-Virus-Scan: failed` และตัดเฮดเดอร์ `X-Spam-*` ที่ผู้ส่งใส่มาออก

### รายงาน ARF

`spamscanner/arf` อ่านและเขียนรายงาน abuse feedback (RFC 5965) ซึ่งเป็นรูปแบบที่ผู้ให้บริการกล่องจดหมายใช้รายงานการร้องเรียนสแปม:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders?.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()` คืน `null` แทนการโยนข้อผิดพลาดสำหรับข้อความที่ไม่ใช่รายงาน และ `isArfMessage(mail)` ตรวจข้อความที่แยกวิเคราะห์แล้ว `originalHeaders` เป็น `null` สำหรับรายงานที่ไม่มีข้อความต้นฉบับ `create()` คืนสตริง หรือคืน `Buffer` เมื่อ `originalMessage` เป็นชนิดเดียวกัน เพื่อให้ไบต์ของข้อความคงเดิมไม่ว่าจะใช้ชุดอักขระใด
