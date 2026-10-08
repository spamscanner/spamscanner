<!-- source: a59bc5927d86 -->

# Dòng lệnh

```text
spamscanner <command> [options]
```

| Lệnh                                       | Chức năng                                                                    |
| ------------------------------------------ | ---------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Quét một thư từ tệp hoặc đầu vào chuẩn                                       |
| `filter -f <sender> -- <recipients...>`    | Content filter cho Postfix: quét đầu vào chuẩn, thêm header, chuyển tiếp thư |
| `milter`                                   | Milter cho Postfix và Sendmail, cổng 7831                                    |
| `http`                                     | HTTP API, cổng 7832                                                          |
| `server`                                   | Máy chủ TCP thuần, cổng 7830                                                 |
| `spamd`                                    | Máy chủ spamd tương thích SpamAssassin, cổng 783                             |
| `train`                                    | Huấn luyện mô hình từ tệp mbox, Maildir, thư mục hoặc bộ dữ liệu             |
| `eval`                                     | Đo lường mô hình trên tập thư có gắn nhãn                                    |
| `learn spam\|ham [file\|-] --model <file>` | Dạy mô hình một thư                                                          |
| `llm-test`                                 | Kiểm tra thiết lập mô hình ngôn ngữ bằng ba thư mẫu                          |
| `models`                                   | Liệt kê các mô hình mở được đề xuất                                          |
| `version`, `help`                          |                                                                              |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Tùy chọn                   | Ý nghĩa                                                                |
| -------------------------- | ---------------------------------------------------------------------- |
| `--json`                   | In toàn bộ kết quả dưới dạng JSON                                      |
| `--headers`                | In thư kèm các header `X-Spam-*` được thêm vào                         |
| `--subject-tag <tag>`      | Thêm tiền tố vào tiêu đề của spam                                      |
| `--verbose`                | Hiển thị mọi phép kiểm tra, và các dấu hiệu mạnh nhất của bộ phân loại |
| `--threshold <n>`          | Điểm mà từ đó thư là spam (mặc định 5)                                 |
| `--reject-threshold <n>`   | Điểm mà từ đó thư bị từ chối (mặc định 15)                             |
| `--model <file>`           | Một tệp mô hình thay cho mô hình đi kèm                                |
| `--no-classifier`          | Không dùng bộ phân loại                                                |
| `--config <file>`          | Một tệp JSON chứa [tùy chọn thư viện](api.md#options)                  |
| `--allow-language <codes>` | Các ngôn ngữ được chấp nhận, ví dụ `en,de,fr`                          |

Mã thoát: 0 là ham, 1 là spam, 2 là lỗi.

### Phiên SMTP

| Tùy chọn            | Ý nghĩa                                                 |
| ------------------- | ------------------------------------------------------- |
| `--ip <address>`    | Địa chỉ IP của client đã gửi thư                        |
| `--hostname <name>` | Tên DNS ngược đã xác minh của client                    |
| `--helo <name>`     | Tên mà client đưa ra trong HELO hoặc EHLO               |
| `--from <address>`  | Người gửi trong envelope (MAIL FROM)                    |
| `--to <address>`    | Người nhận trong envelope; lặp lại cho nhiều người nhận |

### Phép kiểm tra

| Tùy chọn              | Ý nghĩa                                                                        |
| --------------------- | ------------------------------------------------------------------------------ |
| `--auth`              | Kiểm tra SPF, DKIM, DMARC và ARC (cần `--ip`)                                  |
| `--dnsbl <zone>`      | Danh sách chặn IP, ví dụ `zen.spamhaus.org`; có thể lặp lại                    |
| `--uribl <zone>`      | Danh sách chặn tên miền cho liên kết, ví dụ `dbl.spamhaus.org`; có thể lặp lại |
| `--dns-server <ip>`   | Name server cho các phép kiểm tra DNS; có thể lặp lại                          |
| `--no-cloudflare`     | Không hỏi các resolver có lọc của Cloudflare về liên kết                       |
| `--clamav [socket]`   | Quét tệp đính kèm bằng clamd, qua socket mặc định hoặc socket được chỉ định    |
| `--allowlist <value>` | Luôn chấp nhận địa chỉ IP, tên miền hoặc địa chỉ này; có thể lặp lại           |
| `--denylist <value>`  | Luôn từ chối địa chỉ IP, tên miền hoặc địa chỉ này; có thể lặp lại             |

### Mô hình ngôn ngữ

| Tùy chọn                                                   | Ý nghĩa                                                                                            |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` và các nhà cung cấp khác ([danh sách](llm.md#providers)) |
| `--llm-model <name>`                                       | Mô hình, ví dụ `qwen3.5:4b` hoặc `claude-haiku-4-5`                                                |
| `--llm-url <url>`                                          | URL gốc, ví dụ `http://10.0.0.5:11434`                                                             |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Thay đổi một phần URL của nhà cung cấp                                                             |
| `--llm-api-key <key>`                                      | Khóa API; xem thêm các biến môi trường bên dưới                                                    |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` hoặc `none`                                    |
| `--llm-auth-header <name>`                                 | Header chứa khóa, dùng với `--llm-auth header`                                                     |
| `--llm-username`, `--llm-password`                         | Dùng cho `--llm-auth basic`                                                                        |
| `--llm-header "Name: value"`                               | Header bổ sung cho yêu cầu; có thể lặp lại                                                         |
| `--llm-mode <mode>`                                        | `auto` (chỉ các trường hợp sát nút, mặc định) hoặc `always`                                        |
| `--llm-timeout <ms>`                                       | Mặc định 30000                                                                                     |
| `--llm-policy <text>`                                      | Quy tắc bổ sung cho mô hình, ví dụ “Chúng tôi không bao giờ gửi hóa đơn”                           |
| `--llm-redact`, `--no-llm-redact`                          | Xóa dữ liệu cá nhân trước; mặc định bật với các nhà cung cấp từ xa                                 |


## filter

Một [content filter cho Postfix](postfix.md#content-filter). Nó đọc thư từ đầu vào chuẩn, thêm các header `X-Spam-*` rồi chuyển thư cho sendmail với cùng envelope.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Tùy chọn              | Ý nghĩa                                            |
| --------------------- | -------------------------------------------------- |
| `--sendmail <path>`   | Mặc định `/usr/sbin/sendmail`                      |
| `--subject-tag <tag>` | Thêm tiền tố vào tiêu đề của spam                  |
| `--reject`            | Trả lại thư đạt ngưỡng từ chối thay vì chuyển tiếp |
| `--discard`           | Bỏ thư đạt ngưỡng từ chối thay vì chuyển tiếp      |

Mã thoát tuân theo quy ước của sendmail, mà Postfix đọc được: 0 là đã chuyển (hoặc đã bỏ), 64 là không có người nhận, 69 là bị từ chối vì spam (Postfix trả thư về), 75 là mọi lỗi, khi đó Postfix giữ thư và thử lại sau.


## milter, http, server và spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Cổng 783 là cổng mà các client SpamAssassin dùng mặc định. Các cổng dưới 1024 cần quyền root hoặc capability `CAP_NET_BIND_SERVICE`; hãy dùng cổng khác, như `--port 7833`, và báo cho client biết.

| Tùy chọn              | Ý nghĩa                                                                      |
| --------------------- | ---------------------------------------------------------------------------- |
| `--port <n>`          | Cổng TCP                                                                     |
| `--host <ip>`         | Địa chỉ để lắng nghe (mặc định 127.0.0.1)                                    |
| `--socket <path>`     | Lắng nghe trên một Unix socket thay vào đó                                   |
| `--reject`            | Milter: từ chối thư đạt ngưỡng từ chối                                       |
| `--reject-code <n>`   | Milter: 451, thử lại sau (mặc định), hoặc 550                                |
| `--quarantine`        | Milter: giữ spam trong khu cách ly của máy chủ thư                           |
| `--name <hostname>`   | Milter: tên của máy chủ này trong Authentication-Results                     |
| `--token <secret>`    | HTTP: yêu cầu `Authorization: Bearer <secret>`; cần cho `/learn`             |
| `--allow-tell`        | spamd: chấp nhận yêu cầu TELL (`spamc -L spam`) để học                       |
| `--out <file>`        | HTTP và spamd: lưu những gì đã học vào tệp mô hình này                       |
| `--subject-tag <tag>` | Milter và spamd: thêm tiền tố vào tiêu đề của spam                           |
| `--verbose`           | Milter: ghi nhật ký mọi lần quét. Máy chủ TCP: trả lời bằng một dòng văn bản |

Các tùy chọn quét ở trên cũng áp dụng cho các máy chủ. [Milter](postfix.md#milter), [HTTP API, máy chủ TCP và spamd](http-api.md).


## train, eval và learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Tùy chọn                                        | Ý nghĩa                                                                          |
| ----------------------------------------------- | -------------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: một tệp mbox, một Maildir hoặc một thư mục chứa tệp `.eml`; có thể lặp lại |
| `--ham <path>`                                  | Ham, tương tự; có thể lặp lại                                                    |
| `--dataset <file>`                              | Một tệp CSV hoặc JSON Lines có cột văn bản và cột nhãn; có thể lặp lại           |
| `--text-column <name>`, `--label-column <name>` | Tên cột, khi không được tự động nhận diện                                        |
| `--out <file>`                                  | Nơi ghi mô hình (mặc định `spamscanner-model.json`)                              |
| `--merge`                                       | Bắt đầu từ mô hình đi kèm (hoặc `--model`) thay vì một mô hình trống             |

`learn` cập nhật trực tiếp tệp mô hình, và tạo tệp từ mô hình đi kèm ở lần đầu. [Huấn luyện](training.md)


## llm-test và models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` gửi một thư bình thường và hai thư lừa đảo, bằng tiếng Anh và tiếng Ý, đến mô hình, in ra các kết luận và chỉ thoát với mã 0 nếu cả ba đều đúng.


## Tệp cấu hình

`--config file.json` (hoặc biến môi trường `SPAMSCANNER_CONFIG`) nạp các [tùy chọn thư viện](api.md#options). Tùy chọn dòng lệnh ghi đè tệp này.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Biến môi trường

| Biến                                                                                                                                                                                                                                                 | Ý nghĩa                                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | Tệp cấu hình                                   |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | Tệp mô hình dùng thay cho mô hình đi kèm       |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | Token cho HTTP API                             |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | Khóa API cho mọi nhà cung cấp mô hình ngôn ngữ |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Khóa riêng của từng nhà cung cấp               |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | Ghi nhật ký gỡ lỗi                             |
