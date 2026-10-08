<!-- source: b3cc9f949acd -->

# เอกสารอ้างอิง API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

สร้างตัวสแกนครั้งเดียวแล้วนำกลับมาใช้ซ้ำ: ตัวสแกนจะโหลดโมเดลครั้งเดียว และแคชคำตอบจาก DNS และโมเดลภาษา


## ตัวเลือก

ส่งทุกตัวเลือกให้ constructor ได้ ตัวเลือกส่วนใหญ่ส่งให้ `scan()` สำหรับข้อความเดียวได้ด้วย ซึ่งจะผสานทับค่าของ constructor

| ตัวเลือก                | ค่าเริ่มต้น                      | ความหมาย                                                                                              |
| ----------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | คะแนนที่ข้อความถือเป็นสแปม                                                                            |
| `rejectThreshold`       | `15`                             | คะแนนที่ `action` เป็น `reject`                                                                       |
| `scores`                | `{}`                             | คะแนนของแต่ละการทดสอบ: ระบุด้วยคีย์การตั้งค่าหรือชื่อการทดสอบ ([การทดสอบและคะแนน](scoring.md))        |
| `classifier`            | โมเดลที่มาพร้อมแพ็กเกจ           | `Classifier` ออบเจ็กต์โมเดล พาธไฟล์โมเดล หรือ `false`                                                 |
| `classifierOptions`     | `{}`                             | ตัวเลือกสำหรับโมเดลที่มาพร้อมแพ็กเกจ (ดู [ตัวจำแนก](#classifier))                                     |
| `allowedLanguages`      | `[]`                             | รหัส ISO 639-1 ภาษาอื่นจะได้ `LANGUAGE_NOT_ALLOWED`                                                   |
| `phishing.cloudflare`   | `true`                           | ถาม resolver แบบกรองของ Cloudflare เกี่ยวกับโฮสต์ของลิงก์                                             |
| `phishing.adult`        | `true`                           | ถาม resolver สำหรับครอบครัวซึ่งบล็อกเว็บไซต์สำหรับผู้ใหญ่ด้วย                                         |
| `phishing.maxHosts`     | `25`                             | จำนวนโฮสต์ของลิงก์ที่ค้นหาต่อข้อความ                                                                  |
| `phishing.homograph`    | `{}`                             | `brands` (แทนที่รายการในตัว), `extraBrands`, `allowlist` (โดเมนที่ไม่ถูกตีว่าผิดเลย), `strictMode`    |
| `dnsbl`                 | `{ip: [], domain: []}`           | โซนของ DNS blocklist สำหรับ IP ของไคลเอนต์และโดเมนของลิงก์                                            |
| `dns`                   | `{servers: null, timeout: 3000}` | name server สำหรับการตรวจทาง DNS (ค่าเริ่มต้น: ของระบบ)                                               |
| `attachments`           | `true`                           | ตรวจไฟล์แนบ                                                                                           |
| `macros`                | `true`                           | ตีธงมาโคร PDF ที่ทำงานได้ และออบเจ็กต์ RTF                                                            |
| `arbitrary`             | `true`                           | รัน[กฎ](scoring.md#rules)                                                                             |
| `authentication`        | `false`                          | `true` หรือ `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                              |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                     |
| `allowlist`, `denylist` |                                  | ที่อยู่ IP โดเมน หรือที่อยู่อีเมล รูปย่อของ `reputation`                                              |
| `clamav`                | `false`                          | `true` (ซ็อกเก็ตค่าเริ่มต้น), `{socket}` หรือ `{host, port}`                                          |
| `llm`                   | `null`                           | [การตั้งค่าโมเดลภาษา](llm.md#any-server-port-and-authentication) พร้อม `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: โมเดลที่ `classify([text])` ตอบแบบเดียวกับ `@tensorflow-models/toxicity`  |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: โมเดลที่ `classify(imageBuffer)` ตอบแบบเดียวกับ `nsfwjs`                  |
| `maxLength`             | `100000`                         | จำนวนอักขระของเนื้อหาที่อ่าน                                                                          |
| `timeout`               | `10000`                          | เวลาที่อนุญาตเป็นมิลลิวินาทีสำหรับการตรวจทางเครือข่ายแต่ละรายการ                                      |
| `session`               | `{}`                             | รายละเอียดเซสชัน SMTP ค่าเริ่มต้น                                                                     |

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


## เมธอด

| เมธอด                                | ค่าที่คืน                                                                     |
| ------------------------------------ | ----------------------------------------------------------------------------- |
| `scan(source, options)`              | ผลลัพธ์ `source` เป็น Buffer สตริง Uint8Array หรือ readable stream            |
| `scanFile(path, options)`            | ผลลัพธ์สำหรับไฟล์ข้อความ                                                      |
| `learn(source, 'spam' \| 'ham')`     | สอนตัวจำแนกด้วยข้อความหนึ่งข้อความ                                            |
| `unlearn(source, 'spam' \| 'ham')`   | ยกเลิกผลของ `learn`                                                           |
| `saveModel(path, options)`           | เขียนตัวจำแนกลงไฟล์ (`options`: `minCount`, `maxFeatures`, `metadata`)        |
| `getClassifier()`                    | `Classifier` ที่ใช้อยู่ หรือ `null`                                           |
| `getClassification(features)`        | ผลตัดสินของตัวจำแนกสำหรับคุณลักษณะจาก `getFeatures`                           |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` สำหรับข้อความที่แยกวิเคราะห์แล้ว |
| `getTokens(text, locale)`            | คำในข้อความ                                                                   |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                    |
| `parse(source)`                      | `{raw, mail}` โดย `mail` มาจาก mailparser                                     |

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
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'],
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser */},
  version: '7.0.0',
  metrics: {totalTime: 42},
}
```

สิ่งที่พบใน `phishing`, `attachments`, `executables`, `macros`, `viruses` และ `arbitrary` เป็นออบเจ็กต์ที่มี `type` และ `message` และ `String(finding)` ให้ค่าเป็นข้อความใน message


## สิ่งที่ export

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';

import ArfParser from 'spamscanner/arf';
```

### ตัวจำแนก

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| ตัวเลือก                               | ค่าเริ่มต้น    | ความหมาย                                                                |
| -------------------------------------- | -------------- | ----------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | ค่า s และ x ของ Robinson: คุณลักษณะที่พบน้อยถูกดึงเข้าหา 0.5 แรงเพียงใด |
| `minDistance`                          | `0.1`          | คุณลักษณะที่ใกล้ 0.5 กว่าค่านี้จะถูกละเว้น                              |
| `maxClues`                             | `150`          | จำนวนคุณลักษณะที่แรงที่สุดที่รวมกันต่อข้อความ                           |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | ขอบเขตของช่วง `unsure`                                                  |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | จำนวนข้อความแต่ละประเภทที่ต้องมีในภาษาหนึ่งเพื่อให้มั่นใจเต็มที่        |
| `languagePrior`                        | `true`         | ชั่งน้ำหนักคำเทียบกับจำนวนนับในภาษาของคำนั้นเอง                         |

ยังมี `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` และ `entries()` ให้ใช้ด้วย

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### รายงาน ARF

`spamscanner/arf` อ่านและเขียนรายงาน abuse feedback (RFC 5965) ซึ่งเป็นรูปแบบที่ผู้ให้บริการกล่องจดหมายใช้รายงานการร้องเรียนสแปม:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()` คืน `null` แทนการโยนข้อผิดพลาดสำหรับข้อความที่ไม่ใช่รายงาน และ `isArfMessage(mail)` ตรวจข้อความที่แยกวิเคราะห์แล้ว
