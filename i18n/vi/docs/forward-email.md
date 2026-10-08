<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner được xây dựng bởi [Forward Email](https://forwardemail.net), dịch vụ email mã nguồn mở chú trọng quyền riêng tư, cho chính các máy chủ thư của mình. Forward Email không lưu nhật ký nội dung thư, nên không dịch vụ lọc bên ngoài nào phù hợp: bộ lọc phải chạy trên máy chủ của chính họ, và phải giải thích từng quyết định mà không cần ai đọc thư.

Trang này cho thấy một máy chủ thư như của Forward Email sử dụng nó ra sao, và những gì đã thay đổi đối với mã viết cho Spam Scanner 5 hoặc 6.


## Trên máy chủ nhận thư

Forward Email nhận thư bằng [smtp-server](https://nodemailer.com/extras/smtp-server/). Mẫu dưới đây áp dụng cho mọi máy chủ xây dựng trên nó:

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

`scanner.scan()` nhận trực tiếp luồng SMTP. Nếu đã có sẵn kết quả từ [mailauth](https://github.com/postalsys/mailauth), hãy bỏ qua `authentication` và chỉ truyền địa chỉ IP.

Phản hồi 421 hoặc 451 khiến máy chủ gửi đưa thư vào hàng đợi và thử lại sau. Các quy tắc từ chối mới có thể bắt đầu với mã tạm thời và chuyển sang 550 khi kết quả của chúng đã được kiểm tra, mà không mất thư trong thời gian đó.


## Nâng cấp từ phiên bản 5 hoặc 6

Phiên bản 7 được viết lại hoàn toàn. Hàm khởi tạo, `scan()` và các trường kết quả mà mã của phiên bản 5 và 6 đọc vẫn hoạt động; bộ phân loại, mô hình và các phép kiểm tra TensorFlow tùy chọn đã thay đổi.

### Vẫn giữ nguyên

* `new SpamScanner(options)` và `await scanner.scan(source)`.
* `require('spamscanner')` trả về lớp, và `import SpamScanner from 'spamscanner'` vẫn hoạt động.
* `result.isSpam`, `result.message`, và `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` và `.idnHomographAttack`.
* Mỗi mục trong `results.phishing`, `.executables`, `.arbitrary` và `.viruses` chuyển thành cùng loại chuỗi thông báo như trước (`String(item)`, template literal, `message.includes('adult-related content')`). Giờ đây chúng là các đối tượng có `type`, `message` và thông tin chi tiết.
* `getTokensAndMailFromSource()`, `getClassification()` và `getTokens()`.
* Các tùy chọn sau được ánh xạ sang tên mới: `clamscan` thành `clamav`, `enableMacroDetection: false` thành `macros: false`, `enableArbitraryDetection: false` thành `arbitrary: false`, `enableAuthentication` cùng `authOptions` thành `authentication` và `session`, `enableReputation` cùng `reputationOptions.apiUrl` thành `reputation`, `strictIDNDetection` thành `phishing.homograph.strictMode`, cùng `allowlist` và `denylist`. `logger` và `memoize` được chấp nhận nhưng bị bỏ qua.

### Đã thay đổi

| Trước đây                                                                       | Hiện nay                                                                                                                                                              |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` đọc tệp                                              | Một chuỗi là nội dung thư. Dùng `scanFile(path)` hoặc truyền một Buffer                                                                                               |
| Mô hình naive Bayes dựa trên từ (`classifier.json`), giờ không tải được         | Bộ phân loại và định dạng mô hình mới; huấn luyện lại bằng `spamscanner train` ([huấn luyện](training.md))                                                            |
| Các phép kiểm tra độc hại và NSFW tải mô hình TensorFlow từ mạng ở lần dùng đầu | Tự cung cấp mô hình: `toxicity: {model}` và `nsfw: {model}` nhận bất kỳ đối tượng nào có phương thức `classify()`, ví dụ từ `@tensorflow-models/toxicity` và `nsfwjs` |
| `results.arbitrary` liệt kê mọi mẫu khớp                                        | Nó liệt kê các quy tắc đủ mạnh để tự đánh dấu spam; tất cả quy tắc nằm trong `result.tests`                                                                           |
| Câu trả lời có hoặc không                                                       | `result.score`, `result.action` (`accept`, `tag` hoặc `reject`) và `result.tests`, mỗi mục kèm điểm và lý do                                                          |
| `isSpam` do bộ phân loại hoặc bất kỳ phép kiểm tra đơn lẻ nào quyết định        | `isSpam` là điểm từ 5 trở lên; có thể thay đổi ngưỡng và điểm                                                                                                         |
| Kiểm tra uy tín với một endpoint của Forward Email                              | Một dịch vụ uy tín chung, tắt trừ khi đặt `reputation.apiUrl`                                                                                                         |

### Mới

* [Mô hình ngôn ngữ](llm.md) cho các trường hợp sát nút, cục bộ hoặc trên đám mây.
* SPF, DKIM, DMARC và ARC; danh sách chặn DNS; các resolver có lọc của Cloudflare.
* Kiểm tra tệp đính kèm theo nội dung: tệp thực thi ngụy trang, tệp nén, macro, PDF chứa nội dung chủ động.
* [Milter, HTTP API, máy chủ TCP và máy chủ spamd](mail-servers.md), cùng [dòng lệnh](cli.md).
* Huấn luyện, đánh giá và học từ các báo cáo, từ dòng lệnh hoặc API.
