<!-- source: 1d7373f991c2 -->

# Bảo mật và quyền riêng tư

Spam Scanner đọc thư, vốn là thông tin riêng tư, từ những người gửi có thể có ý đồ xấu. Trang này liệt kê những gì nó gửi đi bất kỳ đâu, và cách nó xử lý những gì nó đọc.


## Những gì rời khỏi máy

Theo mặc định, chỉ một thứ: **tên máy chủ của các liên kết** trong thư được tra cứu trên các resolver có lọc của Cloudflare, 1.1.1.2 và 1.0.0.2 (mã độc và phishing) và 1.1.1.3 và 1.0.0.3 (thêm cả nội dung người lớn). Đây là các truy vấn DNS thông thường cho các tên như `example.com`; không phần nào của thư hay các địa chỉ trong đó được gửi đi. Tắt chúng bằng `phishing: {cloudflare: false}` hoặc `--no-cloudflare`, hoặc chỉ tắt kiểm tra nội dung người lớn bằng `phishing: {adult: false}`.

Mọi thứ khác đều tắt cho đến khi được cấu hình:

| Phép kiểm tra       | Gửi gì                                                                                                                            | Đến đâu                                                                     |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `authentication`    | Truy vấn DNS cho các bản ghi SPF, DKIM, DMARC và ARC của người gửi                                                                | Resolver của bạn, hoặc `dnsServers`                                         |
| `dnsbl`             | Địa chỉ IP của client, đảo ngược, và tên miền của liên kết, dưới dạng truy vấn DNS                                                | Name server của các danh sách chặn, qua resolver của bạn hoặc `dns.servers` |
| `llm`               | Bản tóm tắt thư, đã xóa dữ liệu cá nhân với các nhà cung cấp từ xa                                                                | Máy chủ mô hình ngôn ngữ do bạn chỉ định ([quyền riêng tư](llm.md#privacy)) |
| `reputation.apiUrl` | Địa chỉ IP và tên máy chủ đã xác minh của máy khách, cùng các địa chỉ From, người gửi phong bì và Reply-To kèm tên miền của chúng | Dịch vụ do bạn chỉ định                                                     |
| `clamav`            | Tệp đính kèm                                                                                                                      | clamd của bạn, qua socket của nó                                            |

Không thu thập dữ liệu sử dụng (telemetry), không kiểm tra cập nhật và không tải gì về khi chạy. Mô hình được đóng gói sẵn trong gói.


## Những gì nó lưu giữ

Không gì cả, trừ khi được yêu cầu. Các lần quét không được ghi nhật ký hay lưu trữ. `learn()` thay đổi bộ phân loại trong bộ nhớ; nó chỉ được ghi ra đĩa bởi `saveModel()`, `spamscanner learn`, hoặc tùy chọn `--out` của các máy chủ. Tệp mô hình chứa số đếm đặc trưng đã băm, không chứa từ ngữ hay nội dung thư.

Câu trả lời của mô hình ngôn ngữ được lưu đệm trong bộ nhớ, với khóa là giá trị băm của những gì đã gửi, nên các bản sao lặp lại của cùng một thư chỉ được hỏi một lần. Câu trả lời DNS được lưu đệm trong bộ nhớ trong mười phút, và câu trả lời của dịch vụ uy tín trong năm phút (`reputation.cacheTtl`; yêu cầu thất bại trong một phút).


## Đầu vào có ý đồ xấu

* Tệp đính kèm được nhận diện qua các byte của chúng, không bao giờ được thực thi hay mở bằng chương trình khác. Tệp nén ZIP được đọc từ central directory, có giới hạn số mục (2000) và số byte của tên các mục (1 MiB; tên quá 1 KiB giữ lại 512 byte đầu và 512 byte cuối, và các phát hiện hiển thị tối đa 100 ký tự của một tên), mỗi mục chỉ được đọc một lần dù có bao nhiêu mục thư mục trỏ tới nó; không gì được giải nén, nên các chương trình bên trong tệp nén lồng nhau hoặc đã nén không được nhìn thấy. Thư được đính kèm (`message/rfc822`, hoặc tệp đính kèm có tên tệp kết thúc bằng `.eml`) được mở sâu tối đa ba cấp, cho tối đa 100 tệp đính kèm của chúng và tổng cộng 25 MB thư được đính kèm; các tệp đính kèm của chính thư luôn được kiểm tra hết. Thư vượt quá giới hạn của trình phân tích MIME (hơn 1000 phần, hoặc header của một phần quá 1 MB) được đọc đến mức trình phân tích cho phép (các phần đầu tiên, với header quá lớn được cắt bớt để người gửi vẫn được tính) và nhận `MIME_TOO_COMPLEX`, điểm mà không khoản trừ nào bù lại được; ClamAV đọc toàn bộ thư. Thư được đính kèm mà trình phân tích không đọc được cũng nhận điểm này, và không bao giờ làm lần quét thất bại. Các trường địa chỉ được đọc tối đa 16 KB mỗi trường (2000 địa chỉ, 16 nhóm lồng nhau) và tổng cộng 64 KB cho mỗi thư, chỉ cắt ở cuối một địa chỉ trọn vẹn, vì trình phân tích địa chỉ tốn thời gian tăng theo bình phương số địa chỉ; mailauth cũng đọc From và Return-Path trong giới hạn như vậy (các trường khác thì đọc nguyên trạng, để chữ ký trên chúng vẫn hợp lệ), và đọc header mà nó sẽ mất hơn thời gian tuyến tính để đọc (hàng nghìn dòng gập, hoặc chữ ký nêu tên hàng nghìn trường) ở dạng đã cắt bớt. Trường From bị cắt làm DMARC thất bại và không cho phép gì cả. HTML được đọc bằng trình phân tích riêng của Spam Scanner, trong thời gian tuyến tính, dù lồng sâu đến đâu.
* Nội dung thư được đọc tối đa `maxLength` (100.000 ký tự) và các máy chủ chấp nhận thư tối đa 25 MB. Liên kết được đọc tối đa `phishing.maxLength` (1.000.000 ký tự).
* Mọi phép kiểm tra qua mạng đều có thời gian chờ (`timeout`, mặc định 10 giây). Phép kiểm tra thất bại hoặc hết thời gian chờ sẽ bị bỏ qua và lần quét hoàn tất mà không có nó. Xác thực và mô hình hình ảnh (10 hình đầu tiên) đều hoàn tất toàn bộ trong thời hạn này: xác thực không gửi truy vấn DNS nào sau thời hạn đó, cũng không quá 300 truy vấn cho một thư (đủ chỗ cho SPF ở các giới hạn của RFC 7208, cùng DKIM, ARC, DMARC và BIMI), và chỉ kiểm tra 8 chữ ký DKIM đầu tiên của một thư (bản thân mailauth đọc tối đa 50 bộ ARC). Header `Authentication-Results` mà milter thêm vào chứa tối đa 8 KiB kết quả. ClamAV (bốn tệp đính kèm mỗi lần) có giới hạn riêng cho tất cả tệp đính kèm của một thư (`clamav.timeout`, 60 giây), và các tệp đính kèm nó không quét được được liệt kê trong `results.virusScanErrors`. Mô hình ngôn ngữ có thời hạn riêng (`llm.timeout`).
* Danh sách cho phép chỉ tin những gì người gửi không thể giả mạo: địa chỉ và tên máy chủ đã xác minh của máy khách, và tên miền người gửi được xác thực xác nhận. [Danh sách cho phép và danh sách chặn](api.md#allowlist-and-denylist)
* Các header `X-Spam-*` đã có sẵn trong thư bị xóa bởi milter, content filter và `--headers`, nên người gửi không thể tự đánh dấu thư của mình là sạch.
* Các header kết luận spam của Microsoft chỉ được tin cậy khi thư đến trực tiếp từ máy chủ của Microsoft, và header Received không bao giờ được dùng để xác định thư đến từ đâu.
* Văn bản nhắm vào bộ lọc AI được chấm điểm là spam, và mô hình ngôn ngữ được báo rằng thư là dữ liệu, không phải chỉ dẫn. [Prompt injection](llm.md#prompt-injection)


## Máy chủ

Các máy chủ milter, HTTP, TCP và spamd lắng nghe trên 127.0.0.1 trừ khi `--host` chỉ định khác. HTTP API so sánh token trong thời gian không đổi và từ chối `/learn` khi không có token. Không máy chủ nào hỗ trợ TLS: để truy cập chúng qua mạng, hãy dùng mạng riêng, đường hầm SSH hoặc reverse proxy có TLS.

Chạy chúng bằng một người dùng không có đặc quyền. [Unit systemd trong hướng dẫn Postfix](postfix.md#1-run-the-milter) bổ sung các biện pháp gia cố thông thường.


## Báo cáo lỗ hổng

Báo cáo các vấn đề bảo mật một cách riêng tư qua [tính năng báo cáo lỗ hổng của GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), không đăng trong issue công khai.
