<!-- source: b3cc9f949acd -->

# Tham chiếu API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Tạo một scanner và dùng lại nó: scanner nạp mô hình một lần và lưu đệm các câu trả lời DNS cũng như của mô hình ngôn ngữ.


## Tùy chọn

Mọi tùy chọn đều có thể truyền cho hàm khởi tạo. Hầu hết cũng có thể truyền cho `scan()` cho một thư, khi đó chúng được gộp đè lên các tùy chọn của hàm khởi tạo.

| Tùy chọn                | Mặc định                         | Ý nghĩa                                                                                                                   |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Điểm mà từ đó thư là spam                                                                                                 |
| `rejectThreshold`       | `15`                             | Điểm mà từ đó `action` là `reject`                                                                                        |
| `scores`                | `{}`                             | Điểm cho mỗi phép kiểm tra: khóa thiết lập hoặc tên phép kiểm tra ([các phép kiểm tra và điểm](scoring.md))               |
| `classifier`            | mô hình đi kèm                   | Một `Classifier`, một đối tượng mô hình, đường dẫn tệp mô hình, hoặc `false`                                              |
| `classifierOptions`     | `{}`                             | Tùy chọn cho mô hình đi kèm (xem [Classifier](#classifier))                                                               |
| `allowedLanguages`      | `[]`                             | Mã ISO 639-1; các ngôn ngữ khác nhận `LANGUAGE_NOT_ALLOWED`                                                               |
| `phishing.cloudflare`   | `true`                           | Hỏi các resolver có lọc của Cloudflare về tên máy chủ của liên kết                                                        |
| `phishing.adult`        | `true`                           | Hỏi thêm resolver gia đình, resolver chặn các trang người lớn                                                             |
| `phishing.maxHosts`     | `25`                             | Số tên máy chủ của liên kết được tra cứu cho mỗi thư                                                                      |
| `phishing.homograph`    | `{}`                             | `brands` (thay danh sách tích hợp sẵn), `extraBrands`, `allowlist` (các tên miền không bao giờ bị đánh dấu), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | Các vùng danh sách chặn DNS cho IP của client và cho tên miền của liên kết                                                |
| `dns`                   | `{servers: null, timeout: 3000}` | Name server cho các phép kiểm tra DNS (mặc định: của hệ thống)                                                            |
| `attachments`           | `true`                           | Kiểm tra tệp đính kèm                                                                                                     |
| `macros`                | `true`                           | Đánh dấu macro, PDF chứa nội dung chủ động và đối tượng RTF                                                               |
| `arbitrary`             | `true`                           | Chạy các [quy tắc](scoring.md#rules)                                                                                      |
| `authentication`        | `false`                          | `true`, hoặc `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                                 |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                         |
| `allowlist`, `denylist` |                                  | Địa chỉ IP, tên miền hoặc địa chỉ; cách viết tắt cho `reputation`                                                         |
| `clamav`                | `false`                          | `true` (socket mặc định), `{socket}` hoặc `{host, port}`                                                                  |
| `llm`                   | `null`                           | [Thiết lập mô hình ngôn ngữ](llm.md#any-server-port-and-authentication), với `mode`, `minScore`, `maxScore`               |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: một mô hình có `classify([text])` trả lời giống `@tensorflow-models/toxicity`                 |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: một mô hình có `classify(imageBuffer)` trả lời giống `nsfwjs`                                 |
| `maxLength`             | `100000`                         | Số ký tự nội dung thư được đọc                                                                                            |
| `timeout`               | `10000`                          | Số mili giây cho phép với mỗi phép kiểm tra qua mạng                                                                      |
| `session`               | `{}`                             | Thông tin phiên SMTP mặc định                                                                                             |

`scan()` cũng nhận `session`:

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


## Phương thức

| Phương thức                          | Trả về                                                                     |
| ------------------------------------ | -------------------------------------------------------------------------- |
| `scan(source, options)`              | Kết quả. `source` là Buffer, chuỗi, Uint8Array hoặc readable stream        |
| `scanFile(path, options)`            | Kết quả cho một tệp thư                                                    |
| `learn(source, 'spam' \| 'ham')`     | Dạy bộ phân loại một thư                                                   |
| `unlearn(source, 'spam' \| 'ham')`   | Hoàn tác `learn`                                                           |
| `saveModel(path, options)`           | Ghi bộ phân loại ra tệp (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | `Classifier` đang dùng, hoặc `null`                                        |
| `getClassification(features)`        | Kết luận của bộ phân loại cho các đặc trưng từ `getFeatures`               |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` cho một thư đã phân tích      |
| `getTokens(text, locale)`            | Các từ của một văn bản                                                     |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                 |
| `parse(source)`                      | `{raw, mail}`, với `mail` từ mailparser                                    |

`scanner.metrics` chứa `totalScans`, `averageTime` và `lastScanTime`.


## Kết quả

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

Các phát hiện trong `phishing`, `attachments`, `executables`, `macros`, `viruses` và `arbitrary` là các đối tượng có `type` và `message`. `String(finding)` là thông báo đó.


## Export

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

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Tùy chọn                               | Mặc định       | Ý nghĩa                                                       |
| -------------------------------------- | -------------- | ------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | s và x của Robinson: mức độ các đặc trưng hiếm bị kéo về 0,5  |
| `minDistance`                          | `0.1`          | Các đặc trưng gần 0,5 hơn giá trị này bị bỏ qua               |
| `maxClues`                             | `150`          | Số đặc trưng mạnh nhất được kết hợp cho mỗi thư               |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Giới hạn của khoảng `unsure`                                  |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Số thư mỗi lớp cần có trong một ngôn ngữ để hoàn toàn tin cậy |
| `languagePrior`                        | `true`         | Cân nhắc các từ theo số đếm của chính ngôn ngữ của chúng      |

Ngoài ra còn có `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` và `entries()`.

### Huấn luyện

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` nhận các mục `{label, features}`, hoặc `readExamples(sources)`, hàm đọc cùng các nguồn như `train`, và trả về số đếm, precision, recall, F1, accuracy cùng tỷ lệ dương tính giả, âm tính giả và không chắc.

### Máy chủ

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### Báo cáo ARF

`spamscanner/arf` đọc và ghi các báo cáo phản hồi lạm dụng (RFC 5965), định dạng mà các nhà cung cấp hộp thư dùng để báo cáo khiếu nại spam:

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

`ArfParser.tryParse()` trả về `null` thay vì ném lỗi với những thư không phải báo cáo, và `isArfMessage(mail)` kiểm tra một thư đã phân tích.
