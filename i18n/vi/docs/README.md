<!-- source: c56969e779c4 -->

# Tài liệu Spam Scanner

Spam Scanner là bộ lọc spam cho Node.js và dòng lệnh, với mã nguồn trên GitHub. Nó đọc một thư email thô và quyết định thư đó có phải spam, phishing, lừa đảo hay chứa mã độc không, bằng bất kỳ ngôn ngữ nào. Nó chạy dưới dạng thư viện, công cụ dòng lệnh, milter cho Postfix hoặc Sendmail, content filter cho Postfix, máy chủ spamd tương thích SpamAssassin, HTTP API hoặc máy chủ TCP.

Nó được [Forward Email](https://forwardemail.net) xây dựng cho chính các máy chủ thư của mình.


## Cách một thư được đánh giá

Mỗi phép kiểm tra cộng hoặc trừ điểm. Tổng điểm quyết định kết quả:

| Điểm          | Hành động | Máy chủ thư làm gì              |
| ------------- | --------- | ------------------------------- |
| Dưới 5        | `accept`  | Chuyển thư đến người nhận       |
| Từ 5 đến 14,9 | `tag`     | Chuyển thư kèm đánh dấu là spam |
| Từ 15 trở lên | `reject`  | Từ chối thư trong phiên SMTP    |

Có thể thay đổi cả hai ngưỡng. Mỗi kết quả liệt kê các phép kiểm tra đã kích hoạt, kèm điểm và lý do, nên mọi quyết định đều có thể giải thích được.

Các phép kiểm tra:

* **Bộ phân loại đã huấn luyện** đọc các từ của thư bằng bất kỳ hệ chữ viết nào, hình dạng các liên kết, người gửi và tệp đính kèm. Nó được phát hành sẵn với dữ liệu huấn luyện từ các bộ dữ liệu công khai và học từ thư của chính bạn. [Cách bộ phân loại hoạt động](how-it-works.md#the-classifier)
* **Kiểm tra phishing** phát hiện tên miền giả mạo (`paypa1.com`, `pаypal.com` với chữ а Kirin), liên kết có văn bản hiện một địa chỉ còn đích đến là địa chỉ khác, và tên hiển thị tự nhận là một thương hiệu. [Phishing](how-it-works.md#phishing)
* **Kiểm tra tệp đính kèm** tìm tệp thực thi, tệp thực thi đổi tên thành tài liệu, đuôi tệp kép, thủ thuật tên tệp viết từ phải sang trái, tệp thực thi trong tệp ZIP, macro Office và nội dung chủ động trong PDF. ClamAV có thể quét virus trong tệp đính kèm. [Tệp đính kèm](how-it-works.md#attachments)
* **Xác thực**: SPF, DKIM, DMARC và ARC, khi biết địa chỉ IP của client. [Xác thực](how-it-works.md#authentication)
* **Danh sách chặn DNS** cho địa chỉ IP của client và các tên miền trong liên kết, cùng các resolver có lọc của Cloudflare cho các trang mã độc và người lớn đã biết. [Danh sách chặn](how-it-works.md#blocklists)
* **Quy tắc** cho các mẫu mà không bộ phân loại nào cần học: chuỗi kiểm thử GTUBE, tiêu đề tống tiền tình dục (sextortion), lừa đảo hóa đơn PayPal, tự giả mạo tên miền và các chỉ dẫn giấu cho bộ lọc AI. [Quy tắc](scoring.md#rules)
* **Mô hình ngôn ngữ**, tùy chọn, đưa ra ý kiến thứ hai cho các trường hợp sát nút: một mô hình cục bộ qua Ollama hoặc bất kỳ máy chủ tương thích OpenAI nào, hoặc Claude, ChatGPT, Gemini và các mô hình khác. [Mô hình ngôn ngữ](llm.md)


## Bắt đầu từ đâu

* [Bắt đầu](getting-started.md): cài đặt và quét thư đầu tiên.
* [Dòng lệnh](cli.md): mọi lệnh và tùy chọn.
* [Postfix và Sendmail](postfix.md): lọc thư cho máy chủ thư bằng milter hoặc content filter.
* [Các máy chủ thư khác](mail-servers.md): Exim, Haraka, Dovecot, procmail và mọi thứ có thể gọi HTTP API.
* [Huấn luyện](training.md): dạy nó bằng thư của chính bạn và đo lường kết quả.
* [Mô hình ngôn ngữ](llm.md): nhà cung cấp, các mô hình mở được đề xuất, quyền riêng tư và prompt injection.
* [Ngôn ngữ](languages.md): cách nó đọc tiếng Trung, tiếng Ả Rập, tiếng Thái và mọi hệ chữ viết khác.
* [Forward Email](forward-email.md): cách Forward Email sử dụng nó, và nâng cấp từ phiên bản 5 hoặc 6.
* [Tham chiếu API](api.md) và [các phép kiểm tra và điểm](scoring.md).
* [Bảo mật và quyền riêng tư](security.md): những gì rời khỏi máy, và cách ngăn chặn.
