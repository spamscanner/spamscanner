<!-- source: 9134d1cd102c -->

# Tham chiếu API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Tạo một scanner và dùng lại nó: scanner nạp mô hình một lần và lưu đệm các câu trả lời DNS cũng như của mô hình ngôn ngữ.

Gói đã kèm sẵn khai báo kiểu. Chúng cần TypeScript 4.7 trở lên khi dùng `import`, và 5.3 trở lên khi dùng `require`.


## Tùy chọn

Mọi tùy chọn đều có thể truyền cho hàm khởi tạo. Hầu hết cũng có thể truyền cho `scan()` cho một thư, khi đó chúng được gộp đè lên các tùy chọn của hàm khởi tạo. Tùy chọn truyền vào là `undefined` giữ giá trị mặc định. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` và `strictIDNDetection` chỉ được hàm khởi tạo đọc; tệp hoặc đối tượng mô hình cho trong `classifier` được đọc ngay tại đó, nên mô hình bị thiếu hoặc hỏng sẽ báo lỗi ngay.

| Tùy chọn                | Mặc định                         | Ý nghĩa                                                                                                                                                                                           |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Điểm mà từ đó thư là spam                                                                                                                                                                         |
| `rejectThreshold`       | `15`                             | Điểm mà từ đó `action` là `reject`                                                                                                                                                                |
| `scores`                | `{}`                             | Điểm cho mỗi phép kiểm tra: khóa thiết lập hoặc tên phép kiểm tra ([các phép kiểm tra và điểm](scoring.md))                                                                                       |
| `classifier`            | mô hình đi kèm                   | Một `Classifier`, một đối tượng mô hình, đường dẫn tệp mô hình, hoặc `false`                                                                                                                      |
| `classifierOptions`     | `{}`                             | Tùy chọn cho mô hình đi kèm (xem [Classifier](#classifier))                                                                                                                                       |
| `allowedLanguages`      | `[]`                             | Mã ISO 639-1 (`no` được đọc là `nb`, `fil` là `tl`, và các mã cũ `iw`, `in`, `ji` là `he`, `id`, `yi`); các ngôn ngữ khác nhận `LANGUAGE_NOT_ALLOWED`                                             |
| `phishing.cloudflare`   | `true`                           | Hỏi các resolver có lọc của Cloudflare về tên máy chủ của liên kết                                                                                                                                |
| `phishing.adult`        | `true`                           | Hỏi thêm resolver gia đình, resolver chặn các trang người lớn                                                                                                                                     |
| `phishing.maxHosts`     | `25`                             | Số tên máy chủ của liên kết được tra cứu cho mỗi thư                                                                                                                                              |
| `phishing.maxLength`    | `1000000`                        | Số ký tự văn bản được đọc để tìm liên kết (gấp đôi với HTML); văn bản dài hơn sẽ đặt `results.linksTruncated`; `Infinity`, hoặc bất cứ giá trị nào không phải số dương, nghĩa là giá trị mặc định |
| `phishing.homograph`    | `{}`                             | `brands` (thay danh sách tích hợp sẵn), `extraBrands`, `allowlist` (các tên miền không bao giờ bị đánh dấu), `strictMode`                                                                         |
| `dnsbl`                 | `{ip: [], domain: []}`           | Các vùng danh sách chặn DNS cho IP của client và cho tên miền của liên kết                                                                                                                        |
| `dns`                   | `{servers: null, timeout: 3000}` | Name server cho các phép kiểm tra DNS (mặc định: của hệ thống)                                                                                                                                    |
| `attachments`           | `true`                           | Kiểm tra tệp đính kèm                                                                                                                                                                             |
| `macros`                | `true`                           | Đánh dấu macro, PDF chứa nội dung chủ động và đối tượng RTF                                                                                                                                       |
| `arbitrary`             | `true`                           | Chạy các [quy tắc](scoring.md#rules)                                                                                                                                                              |
| `authentication`        | `false`                          | `true`, hoặc `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([chấm điểm](scoring.md#authentication))                                              |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; câu trả lời được lưu riêng theo dịch vụ và header, còn `cacheSize` áp dụng cho toàn bộ bộ quét               |
| `allowlist`, `denylist` |                                  | Địa chỉ IP, tên miền hoặc địa chỉ; cách viết tắt cho `reputation` → [Danh sách cho phép và danh sách chặn](#allowlist-and-denylist)                                                               |
| `clamav`                | `false`                          | `true` (socket mặc định), `{socket}` hoặc `{host, port}`, kèm `timeout`: số mili giây cho tất cả tệp đính kèm của một thư (`60000`)                                                               |
| `llm`                   | `null`                           | [Thiết lập mô hình ngôn ngữ](llm.md#any-server-port-and-authentication), với `mode`, `minScore`, `maxScore`                                                                                       |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: một mô hình có `classify([text])` trả lời giống `@tensorflow-models/toxicity`                                                                                         |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: một mô hình có `classify(imageBuffer)` trả lời giống `nsfwjs`                                                                                                         |
| `maxLength`             | `100000`                         | Số ký tự nội dung thư được đọc                                                                                                                                                                    |
| `timeout`               | `10000`                          | Số mili giây cho phép với mỗi phép kiểm tra qua mạng; xác thực và mô hình hình ảnh có tổng cộng chừng ấy thời gian (ClamAV có `clamav.timeout` riêng)                                             |
| `session`               | `{}`                             | Thông tin phiên SMTP mặc định                                                                                                                                                                     |

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

Máy chủ đã kiểm tra SPF, DKIM, DMARC và ARC (bằng [mailauth](https://github.com/postalsys/mailauth)) có thể truyền kết quả dưới dạng `authenticationResults`, và các kết quả này được chấm điểm thay vì kiểm tra lại:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Danh sách cho phép và danh sách chặn

Danh sách chặn so khớp địa chỉ IP và tên máy chủ của máy khách, các địa chỉ From, người gửi phong bì và Reply-To, cùng tên miền của chúng, bất kể chúng là gì: một tên nằm dưới tên miền bị chặn sẽ khớp với tên miền đó ngay cả khi nó không phải là tên máy chủ hợp lệ (như `a_b!.evil.example`, hoặc một tên có nhãn dài hơn 63 ký tự), dựa trên 127 nhãn và 253 ký tự cuối cùng của nó. Danh sách cho phép, cũng như danh sách cho phép và nguồn tin cậy của dịch vụ uy tín, chỉ so khớp những gì người gửi không thể giả mạo: địa chỉ IP và tên máy chủ đã xác minh của máy khách (`remoteAddress`, `resolvedClientHostname`), địa chỉ From khi DMARC đạt cho tên miền của nó hoặc một chữ ký DKIM hợp lệ căn chỉnh với nó (và là tên máy chủ hợp lệ; căn chỉnh lỏng, như trong DMARC: tên miền From và tên miền ký hoặc tên miền SPF có cùng tên miền đăng ký được, mà mailauth gọi là tên miền DMARC; một mục ghi tên miền con, như `news.example.com`, chỉ được tính khi tên miền đó, một tên miền nằm dưới nó hoặc một tên miền cha của nó đã ký thư hoặc đạt SPF, không phải một tên miền con khác như `evil.example.com`, cũng không phải một hậu tố công cộng; một lần đạt DMARC cho tên miền đăng ký được mà không có chi tiết căn chỉnh của mailauth chỉ được tính cho mục ghi tên miền đăng ký được; khi căn chỉnh nghiêm ngặt, tức có `adkim=s` hoặc `aspf=s` trong bản ghi DMARC của tên miền, dù viết hoa hay thường, có khoảng trắng hay không, chỉ chữ ký hoặc lần đạt SPF của chính tên miền From mới được tính, và DMARC thất bại nếu không có), và người gửi phong bì khi SPF đạt cho tên miền của nó. Chữ ký DKIM chỉ ký phần đầu của thân thư (độ dài thân thư, `l=`, ngắn hơn thân thư: ai cũng có thể thêm văn bản vào sau đó) không được tính cho gì cả, một lần đạt DMARC dựa trên chữ ký như vậy cũng thế, và không chữ ký nào được tính khi DMARC thất bại, cũng như cho một trường From quá dài để đọc trọn (`mail.from.truncated`). Kết quả truyền vào `authenticationResults` chỉ được tính khi chúng nêu tên miền mà chúng đã đạt, và một tên miền không phải là tên máy chủ (như `bank.example/x.attacker.example`, mà các trình phân tích URL đọc thành `bank.example`) không được tính cho tên miền nào, một lần đạt DMARC dựa trên tên miền như vậy cũng thế. Tên miền quốc tế khớp ở cả hai dạng: `bücher.example` hoặc `xn--bcher-kva.example`. Reply-To không bao giờ được tính. Để cho phép một tên miền, hãy bật `authentication` hoặc truyền `authenticationResults`.

Mỗi mục là một địa chỉ IP, tên miền hoặc địa chỉ email, được so khớp chính xác: mục tên miền cũng bao gồm các tên miền con của nó và các địa chỉ thuộc chúng, nhưng không có dải địa chỉ (`192.0.2.0/24`), ký tự đại diện (`*.example.com`) hay mẫu (`@example.com`). Địa chỉ IPv6 khớp ở mọi dạng (`2001:0db8::0001` là `2001:db8::1`, dạng của RFC 5952), một địa chỉ IPv4 được ánh xạ vào IPv6 (`::ffff:192.0.2.1`) khớp với địa chỉ IPv4 đó, và một địa chỉ IPv4 được chuyển dịch sang IPv6 hoặc nằm dưới tiền tố NAT64 được viết cùng tiền tố đó ở dạng thập phân có dấu chấm (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), trong các mục cũng như trong địa chỉ máy khách.


## Phương thức

| Phương thức                          | Trả về                                                                        |
| ------------------------------------ | ----------------------------------------------------------------------------- |
| `scan(source, options)`              | Kết quả. `source` là Buffer, chuỗi, Uint8Array hoặc readable stream           |
| `scanFile(path, options)`            | Kết quả cho một tệp thư                                                       |
| `learn(source, 'spam' \| 'ham')`     | Dạy bộ phân loại một thư                                                      |
| `unlearn(source, 'spam' \| 'ham')`   | Hoàn tác `learn`                                                              |
| `saveModel(path, options)`           | Ghi bộ phân loại ra tệp (`options`: `minCount`, `maxFeatures`, `metadata`)    |
| `getClassifier()`                    | `Classifier` đang dùng, hoặc `null`                                           |
| `getClassification(features)`        | Kết luận của bộ phân loại cho các đặc trưng từ `getFeatures`                  |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` của một thư |
| `getTokens(text, locale)`            | Các từ của một văn bản                                                        |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                    |
| `parse(source)`                      | `{raw, mail, error}`, với `mail` từ mailparser (xem bên dưới)                 |

`scan`, `parse`, `learn`, `unlearn` và `getTokensAndMailFromSource` đều đọc thư theo cùng một cách: thư vượt quá giới hạn của trình phân tích MIME (hơn 1000 phần, header của một phần quá 1 MB) được đọc đến mức trình phân tích cho phép. Các trường địa chỉ (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To và List-\*) của thư, các phần của nó và các thư được đính kèm được đọc tối đa 16 KB mỗi trường, 2000 dấu phẩy và dấu chấm phẩy và 16 nhóm lồng nhau, và tổng cộng 64 KB cho mỗi thư, luôn đến hết một địa chỉ trọn vẹn, nên không đọc ra địa chỉ nào mà trường không đưa ra; trường bị cắt được đánh dấu `truncated` (`mail.to.truncated`), và trường From bị cắt không được cộng điểm gì cho xác thực của người gửi. Văn bản có dòng đầu tiên không phải là một trường header (`Name: value`, hoặc dòng `From` mở đầu mỗi thư trong tệp mbox) được đọc như thân của một thư không có header, nên `mail.text` là văn bản đó. Các lỗi khác được ném ra. `parse` trả về giới hạn của trình phân tích mà một thư vượt quá trong `error`, giống như `scan` trả về nó trong `parseError`, và null cho thư được đọc trọn vẹn.

Trong `getFeatures`, `text` là văn bản mà ứng dụng thư hiển thị, cũng là nơi các từ được đọc ra, còn `hidden` là số ký tự văn bản mà HTML ẩn đi. mailparser ở đây không tạo văn bản từ HTML: `mail.text` chỉ chứa các phần văn bản thuần, và trống với thư chỉ có HTML; văn bản mà HTML của thư hiển thị là `getFeatures(mail).text`.

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
    unopenedAttachments: [], // attached messages not opened, past the limits they are read within: {filename, reason}
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

Các phát hiện trong `phishing`, `attachments`, `executables`, `macros`, `viruses` và `arbitrary` là các đối tượng có `type` và `message`. `String(finding)` là thông báo đó. Tệp đính kèm của một thư được đính kèm (`message/rfc822`, `message/global`, `.eml`, `.u8msg`) được đặt tên theo thư đó: `fw.eml/invoice.exe`. Virus mà ClamAV tìm thấy trong tệp đính kèm như vậy chỉ được báo cho riêng tệp đó, không báo lại cho thư được đính kèm chứa nó. `virusScanErrors` liệt kê các tệp đính kèm mà ClamAV không quét được, dưới dạng `{filename, error}`: thư như vậy có thể chứa virus, nên hãy giữ lại thay vì chuyển đi. Milter và content filter hoãn thư đó, trừ khi `onError` (`--on-error`) là `accept`, và mọi máy chủ đều đánh dấu thư như vậy mà nó chuyển tiếp bằng `X-Spam-Virus-Scan: failed`. `virusScanSkipped` liệt kê các tệp lớn hơn mức clamd chấp nhận (`StreamMaxLength` của nó), dưới dạng `{filename, reason}`: clamd từ chối chúng ở mọi lần thử, nên, giống như clamav-milter bỏ qua tệp vượt quá `MaxFileSize` của nó, chúng không bị coi là lỗi. Các giới hạn khác của clamd (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), mà một bom nén sẽ chạm tới, thì bị coi là lỗi. Thư đính kèm được mở sâu tối đa ba cấp, với tối đa 100 tệp đính kèm bên trong và tổng cộng 25 MB; `unopenedAttachments` liệt kê những thư không được mở do vượt các giới hạn này, dưới dạng `{filename, reason}`, mà tệp đính kèm của chúng chưa được kiểm tra. Nó không được tính điểm, vì thư chuyển tiếp có thể lồng nhau như vậy, nhưng bên gọi cần thư được đọc trọn vẹn, chẳng hạn để chặn một chương trình mà thư mang theo, có thể từ chối thư có bất kỳ mục nào như vậy. Tổng cộng mở tối đa 100 thư đính kèm.

Mỗi mục `dnsbl` mang `answers` của danh sách (các địa chỉ trong 127.0.0.0/8, mà ý nghĩa do từng danh sách ghi trong tài liệu của mình). Những câu trả lời mà các danh sách đưa ra cho truy vấn chúng từ chối hoặc không thể trả lời không phải là việc bị liệt kê, dù cho địa chỉ của máy khách hay cho tên miền của liên kết (các phát hiện `uribl` trong `phishing`): 127.255.255.x ở Spamhaus (như 127.255.255.254 cho truy vấn qua một resolver công cộng, và 127.255.255.255 khi có quá nhiều truy vấn), 127.0.1.255 ở Spamhaus DBL, 127.0.0.255 ở bất kỳ danh sách nào, và 127.0.0.1 ở SURBL và URIBL, vốn trả lời như vậy cho các resolver mà chúng chặn.


## Export

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, unwrapLink, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export
// unwrapLink(address): the URL a link goes to, through Safe Links and
// Proofpoint URL Defense, as the scanner reads it (null for no URL)

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Tùy chọn                               | Mặc định       | Ý nghĩa                                                                                                                                                           |
| -------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | s và x của Robinson: mức độ các đặc trưng hiếm bị kéo về 0,5                                                                                                      |
| `minDistance`                          | `0.1`          | Các đặc trưng gần 0,5 hơn giá trị này bị bỏ qua                                                                                                                   |
| `maxClues`                             | `150`          | Số đặc trưng mạnh nhất được kết hợp cho mỗi thư                                                                                                                   |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Giới hạn của khoảng `unsure`                                                                                                                                      |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Số thư ham cần có trong một ngôn ngữ để hoàn toàn tin cậy, cùng số thư spam bằng một phần năm số đó; ít hơn khi `languageShare` của toàn bộ ham hoặc spam nhỏ hơn |
| `languagePrior`                        | `true`         | Cân nhắc các từ theo số đếm của chính ngôn ngữ của chúng                                                                                                          |

Ngoài ra còn có `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` và `entries()`. `Classifier.fromJSON` kiểm tra mô hình và ném `TypeError` bắt đầu bằng `Corrupt classifier model` khi dữ liệu bị hỏng. JSON không có `Infinity`, nên một tùy chọn được phiên bản 7.0.3 lưu là `Infinity` sẽ được đọc lại thành `null`: nó được hiểu là `Infinity` cho `maxClues`, `minDistance` và `minLanguageExamples`, là `-Infinity` cho `hamCutoff` (không bao giờ là ham) và `Infinity` cho `spamCutoff` (không bao giờ là spam), và là giá trị mặc định cho các tùy chọn còn lại. `toJSON` lưu một ngưỡng nằm ngoài 0 và 1 thành -1 hoặc 2, có tác dụng như nhau. `loadModel` đọc lại tệp khi tệp thay đổi, và `saveModel` ghi qua một tệp tạm mới, được đẩy xuống đĩa trước khi thay thế mô hình, và mô hình vẫn giữ nguyên quyền truy cập của nó.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` của milter là câu trả lời của nó khi một lần quét thất bại hoặc ClamAV không quét được một tệp đính kèm: `'tempfail'` (mặc định) hoặc `'accept'`, giá trị này chuyển tiếp thư có đánh dấu `X-Spam-Virus-Scan: failed`, không kèm các header `X-Spam-*` mà người gửi đã thêm.

### Báo cáo ARF

`spamscanner/arf` đọc và ghi các báo cáo phản hồi lạm dụng (RFC 5965), định dạng mà các nhà cung cấp hộp thư dùng để báo cáo khiếu nại spam:

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

`parse()` nhận một Buffer, Uint8Array hoặc chuỗi. `ArfParser.tryParse()` trả về `null` thay vì ném lỗi với những thư không phải báo cáo, và `isArfMessage(mail)` kiểm tra một thư đã phân tích. `originalHeaders` là `null` với báo cáo không kèm thư gốc. `create()` trả về một chuỗi, hoặc một `Buffer` khi `originalMessage` cũng là kiểu đó, để giữ nguyên các byte của nó bất kể bộ ký tự.
