<!-- source: 988243aec4f3 -->

<!--
label: Bộ lọc spam tự lưu trữ
title: Bộ lọc spam tự lưu trữ cho máy chủ thư của riêng bạn
description: Bộ lọc spam trên máy chủ của bạn. Spam Scanner giữ thư trên máy, có sẵn mô hình trong gói, không gửi dữ liệu đo lường và kết nối với Postfix hoặc Exim.
keywords: bộ lọc spam tự lưu trữ, bộ lọc spam tại chỗ, bộ lọc spam riêng tư, bộ lọc spam cục bộ, bộ lọc spam cho máy chủ thư, bộ lọc spam không cần đám mây
-->

# Bộ lọc spam tự lưu trữ

Spam Scanner chạy trên máy chủ của riêng bạn và giữ thư ở đó. Mô hình của bộ phân loại nằm sẵn trong gói, không có dữ liệu đo lường hay kiểm tra cập nhật, và theo mặc định thứ duy nhất nó gửi đi là một truy vấn DNS cho tên máy chủ của mỗi liên kết.


## Những gì rời khỏi máy chủ

Theo mặc định, chỉ có tên máy chủ của các liên kết trong thư. Chúng được tra cứu trên các trình phân giải có lọc của Cloudflare (1.1.1.2 và 1.1.1.3) bằng truy vấn DNS thông thường, và không phần nào của thư hay địa chỉ của nó được gửi đi. `--no-cloudflare` tắt cả việc này.

Mọi kiểm tra khác có dùng mạng đều tắt cho đến khi bạn bật:

| Kiểm tra              | Bật bằng             | Gửi gì                                                                    |
| --------------------- | -------------------- | ------------------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | Truy vấn DNS cho các bản ghi của người gửi                                |
| Danh sách chặn DNS    | `--dnsbl`, `--uribl` | Địa chỉ IP của máy khách và tên miền của liên kết, dưới dạng truy vấn DNS |
| ClamAV                | `--clamav`           | Tệp đính kèm, tới clamd của chính bạn                                     |
| Mô hình ngôn ngữ      | `--llm`              | Bản tóm tắt thư, tới máy chủ bạn chỉ định                                 |

Các lần quét không được ghi nhật ký hay lưu lại. [Bảo mật và quyền riêng tư](../../docs/security.md)


## Cài trên máy chủ

```sh
npm install --global spamscanner
```

Hoặc tệp nhị phân độc lập, có sẵn Node.js và mô hình:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Tập lệnh cài đặt kiểm tra tệp nhị phân với tệp `SHA256SUMS` của bản phát hành trước khi cài, và mỗi tệp nhị phân có chứng thực nguồn gốc bản dựng đã ký mà `gh attestation verify` kiểm tra. Có tệp nhị phân cho Linux (x64 và arm64), macOS và Windows. Tệp nhị phân Linux cần glibc, vì vậy trên Alpine hãy cài bằng npm. [Bắt đầu](../../docs/getting-started.md)

Không có kiểm tra cập nhật. Để cập nhật, hãy chạy lại lệnh cài đặt: cả hai lệnh đều cài bản phát hành mới nhất.


## Chạy như một dịch vụ

Các máy chủ milter, HTTP, TCP và spamd lắng nghe trên 127.0.0.1 trừ khi `--host` chỉ định khác. Hãy chạy chúng bằng người dùng không có đặc quyền, ví dụ dưới systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

[Unit đầy đủ và cách thiết lập](../../docs/postfix.md#1-run-the-milter) nằm trong hướng dẫn Postfix. Không máy chủ nào dùng TLS, vì vậy để truy cập từ máy khác, hãy dùng mạng riêng, đường hầm SSH hoặc reverse proxy có TLS.


## Kết nối máy chủ thư của bạn

| Máy chủ thư                        | Lệnh                                      | Cổng     |
| ---------------------------------- | ----------------------------------------- | -------- |
| Postfix hoặc Sendmail              | `spamscanner milter`                      | 7831     |
| Postfix, không bao giờ từ chối thư | `spamscanner filter`, một bộ lọc nội dung | không có |
| Exim, Haraka hoặc spamc            | `spamscanner spamd`                       | 783      |
| Bất cứ thứ gì dùng HTTP            | `spamscanner http`                        | 7832     |
| Một máy khách TCP đơn giản         | `spamscanner server`                      | 7830     |
| Máy chủ thư viết bằng Node.js      | `import SpamScanner from 'spamscanner'`   | không có |

Các máy chủ có thể thêm tiêu đề `X-Spam-Flag`, `X-Spam-Score` và `X-Spam-Status` vào thư, còn thư viện trả về điểm và mọi phép thử đã kích hoạt. Hướng dẫn: [bộ lọc spam cho Postfix](/postfix-spam-filter/), [các máy chủ thư khác](../../docs/mail-servers.md) và [API HTTP](../../docs/http-api.md).


## Giữ mô hình ngôn ngữ ở cục bộ

Mô hình ngôn ngữ là tùy chọn và chỉ đọc các trường hợp khó phân định: spam rõ ràng và ham rõ ràng không bao giờ tới được nó. Với Ollama, mô hình chạy trên cùng máy chủ, nên không thư nào rời khỏi máy chủ:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` chạy trên CPU. Nếu dùng nhà cung cấp được lưu trữ, dữ liệu cá nhân sẽ bị xóa khỏi thư trước khi gửi. [Mô hình ngôn ngữ](../../docs/llm.md)


## Huấn luyện bằng thư của chính bạn

Mô hình đi kèm được huấn luyện trên các bộ dữ liệu công khai. Mô hình được huấn luyện bằng thư mà máy chủ của bạn nhận được sẽ làm tốt hơn, và nó ở lại trên máy chủ đó:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Tệp mô hình chứa số đếm đặc trưng đã băm, không chứa từ hay nội dung thư. [Huấn luyện](../../docs/training.md)


## Yêu cầu

Node.js 18 trở lên trên Linux, macOS hoặc Windows, hoặc không cần gì với tệp nhị phân độc lập. ClamAV và Ollama là tùy chọn và chạy như các dịch vụ riêng.
