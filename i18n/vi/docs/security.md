<!-- source: 60f00f92b5aa -->

# Bảo mật và quyền riêng tư

Spam Scanner đọc thư, vốn là thông tin riêng tư, từ những người gửi có thể có ý đồ xấu. Trang này liệt kê những gì nó gửi đi bất kỳ đâu, và cách nó xử lý những gì nó đọc.


## Những gì rời khỏi máy

Theo mặc định, chỉ một thứ: **tên máy chủ của các liên kết** trong thư được tra cứu trên các resolver có lọc của Cloudflare, 1.1.1.2 và 1.0.0.2 (mã độc và phishing) và 1.1.1.3 và 1.0.0.3 (thêm cả nội dung người lớn). Đây là các truy vấn DNS thông thường cho các tên như `example.com`; không phần nào của thư hay các địa chỉ trong đó được gửi đi. Tắt chúng bằng `phishing: {cloudflare: false}` hoặc `--no-cloudflare`, hoặc chỉ tắt kiểm tra nội dung người lớn bằng `phishing: {adult: false}`.

Mọi thứ khác đều tắt cho đến khi được cấu hình:

| Phép kiểm tra       | Gửi gì                                                                             | Đến đâu                                                                     |
| ------------------- | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `authentication`    | Truy vấn DNS cho các bản ghi SPF, DKIM, DMARC và ARC của người gửi                 | Resolver của bạn, hoặc `dnsServers`                                         |
| `dnsbl`             | Địa chỉ IP của client, đảo ngược, và tên miền của liên kết, dưới dạng truy vấn DNS | Name server của các danh sách chặn, qua resolver của bạn hoặc `dns.servers` |
| `llm`               | Bản tóm tắt thư, đã xóa dữ liệu cá nhân với các nhà cung cấp từ xa                 | Máy chủ mô hình ngôn ngữ do bạn chỉ định ([quyền riêng tư](llm.md#privacy)) |
| `reputation.apiUrl` | Địa chỉ IP, tên miền và địa chỉ của người gửi                                      | Dịch vụ do bạn chỉ định                                                     |
| `clamav`            | Tệp đính kèm                                                                       | clamd của bạn, qua socket của nó                                            |

Không thu thập dữ liệu sử dụng (telemetry), không kiểm tra cập nhật và không tải gì về khi chạy. Mô hình được đóng gói sẵn trong gói.


## Những gì nó lưu giữ

Không gì cả, trừ khi được yêu cầu. Các lần quét không được ghi nhật ký hay lưu trữ. `learn()` thay đổi bộ phân loại trong bộ nhớ; nó chỉ được ghi ra đĩa bởi `saveModel()`, `spamscanner learn`, hoặc tùy chọn `--out` của các máy chủ. Tệp mô hình chứa số đếm đặc trưng đã băm, không chứa từ ngữ hay nội dung thư.

Câu trả lời của mô hình ngôn ngữ được lưu đệm trong bộ nhớ, với khóa là giá trị băm của những gì đã gửi, nên các bản sao lặp lại của cùng một thư chỉ được hỏi một lần. Câu trả lời DNS được lưu đệm trong bộ nhớ trong mười phút.


## Đầu vào có ý đồ xấu

* Tệp đính kèm được nhận diện qua các byte của chúng, không bao giờ được thực thi hay mở bằng chương trình khác. Tệp nén ZIP được đọc từ central directory, có giới hạn số mục; tệp nén lồng nhau không được giải nén.
* Nội dung thư được đọc tối đa `maxLength` (100.000 ký tự) và các máy chủ chấp nhận thư tối đa 25 MB.
* Mọi phép kiểm tra qua mạng đều có thời gian chờ (`timeout`, mặc định 10 giây). Phép kiểm tra thất bại hoặc hết thời gian chờ sẽ bị bỏ qua và lần quét hoàn tất mà không có nó.
* Các header `X-Spam-*` đã có sẵn trong thư bị xóa bởi milter, content filter và `--headers`, nên người gửi không thể tự đánh dấu thư của mình là sạch.
* Các header kết luận spam của Microsoft chỉ được tin cậy khi thư đến trực tiếp từ máy chủ của Microsoft, và header Received không bao giờ được dùng để xác định thư đến từ đâu.
* Văn bản nhắm vào bộ lọc AI được chấm điểm là spam, và mô hình ngôn ngữ được báo rằng thư là dữ liệu, không phải chỉ dẫn. [Prompt injection](llm.md#prompt-injection)


## Máy chủ

Các máy chủ milter, HTTP, TCP và spamd lắng nghe trên 127.0.0.1 trừ khi `--host` chỉ định khác. HTTP API so sánh token trong thời gian không đổi và từ chối `/learn` khi không có token. Không máy chủ nào hỗ trợ TLS: để truy cập chúng qua mạng, hãy dùng mạng riêng, đường hầm SSH hoặc reverse proxy có TLS.

Chạy chúng bằng một người dùng không có đặc quyền. [Unit systemd trong hướng dẫn Postfix](postfix.md#1-run-the-milter) bổ sung các biện pháp gia cố thông thường.


## Báo cáo lỗ hổng

Báo cáo các vấn đề bảo mật một cách riêng tư qua [tính năng báo cáo lỗ hổng của GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), không đăng trong issue công khai.
