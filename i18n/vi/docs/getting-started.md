<!-- source: 8263c06f1dab -->

# Bắt đầu

Spam Scanner cần Node.js 18 trở lên, hoặc không cần gì cả nếu dùng tệp nhị phân độc lập.


## Cài đặt

Dưới dạng công cụ dòng lệnh:

```sh
npm install --global spamscanner
spamscanner version
```

Dưới dạng thư viện trong một dự án Node.js:

```sh
npm install spamscanner
```

Dưới dạng tệp nhị phân độc lập cho Linux hoặc macOS, đã tích hợp sẵn Node.js và mô hình:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Tệp nhị phân cho Linux (x64 và arm64), macOS (Intel và Apple silicon) và Windows được đính kèm trong mỗi [bản phát hành](https://github.com/spamscanner/spamscanner/releases).


## Quét một thư

Lưu thư thành tệp (hầu hết các chương trình thư gọi là “Lưu thành” hoặc “Hiện bản gốc”) rồi quét:

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

Mã thoát là 0 cho thư hợp lệ (ham), 1 cho spam và 2 khi có lỗi, nên script có thể dùng trực tiếp. `--json` in toàn bộ kết quả và `--headers` in thư kèm các header `X-Spam-*` được thêm vào.

Thư cũng có thể đến từ đầu vào chuẩn:

```sh
cat message.eml | spamscanner scan -
```


## Dùng từ Node.js

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

CommonJS cũng hoạt động:

```js
const SpamScanner = require('spamscanner');
```

`scan()` nhận thư thô dưới dạng Buffer, chuỗi, Uint8Array hoặc readable stream. Một chuỗi luôn được coi là nội dung thư: Spam Scanner không bao giờ đọc tệp chỉ vì chuỗi trông giống đường dẫn. Dùng `scanner.scanFile(path)` cho tệp.


## Cung cấp thông tin về phiên SMTP

Địa chỉ IP của client, tên máy chủ đã xác minh, tên HELO và envelope giúp kết quả chính xác hơn: xác thực cần địa chỉ IP, và quy tắc tự giả mạo cần danh sách người nhận.

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

Tương tự từ dòng lệnh:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Bật thêm các phép kiểm tra

Không phép nào trong số này được bật mặc định, vì mỗi phép cần một dịch vụ hoặc một quyết định:

| Phép kiểm tra                        | Tùy chọn thư viện                                | Dòng lệnh                   |
| ------------------------------------ | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC                | `authentication: true`                           | `--auth`                    |
| Danh sách chặn IP                    | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Danh sách chặn tên miền cho liên kết | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                               | `clamav: true` hoặc `clamav: {socket}`           | `--clamav [socket]`         |
| Mô hình ngôn ngữ                     | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Danh sách cho phép và từ chối        | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Các resolver có lọc của Cloudflare (1.1.1.2 cho mã độc, 1.1.1.3 cho nội dung người lớn) được hỏi về tên máy chủ của liên kết theo mặc định. Tắt điều này bằng `phishing: {cloudflare: false}` hoặc `--no-cloudflare`. [Những gì rời khỏi máy](security.md)

Spamhaus và một số danh sách chặn khác không trả lời truy vấn gửi qua các resolver công cộng như 8.8.8.8 hoặc 1.1.1.1. Hãy dùng chúng với một resolver lưu đệm cục bộ, và kiểm tra điều khoản sử dụng của chúng cho lưu lượng của bạn.


## Bước tiếp theo

* Đặt nó trước máy chủ thư: [Postfix và Sendmail](postfix.md), [các máy chủ khác](mail-servers.md).
* Dạy nó bằng thư của chính bạn: [huấn luyện](training.md).
* Thêm mô hình ngôn ngữ cho các trường hợp sát nút: [mô hình ngôn ngữ](llm.md).
