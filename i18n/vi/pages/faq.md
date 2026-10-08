<!-- source: c93fa1a3f9c7 -->

<!--
label: Câu hỏi thường gặp
title: Câu hỏi thường gặp
description: Giải đáp về Spam Scanner: độ chính xác, các ngôn ngữ hỗ trợ, những gì nó gửi qua mạng, mô hình ngôn ngữ, SpamAssassin và Forward Email.
keywords: Spam Scanner câu hỏi thường gặp, câu hỏi về bộ lọc spam, độ chính xác lọc spam, quyền riêng tư bộ lọc spam
-->

# Câu hỏi thường gặp


## Spam Scanner là gì?

Một bộ lọc spam cho Node.js, dòng lệnh và máy chủ thư. Nó đọc một thư email thô và quyết định thư đó có phải spam, phishing, lừa đảo hay chứa mã độc không, kèm một điểm số và danh sách các phép kiểm tra đã quyết định. Nó chạy dưới dạng thư viện, milter cho Postfix và Sendmail, máy chủ spamd tương thích SpamAssassin, content filter cho Postfix, HTTP API hoặc máy chủ TCP.


## Nó có miễn phí không?

[Giấy phép](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) của nó, Business Source License 1.1, cho phép mọi cách sử dụng trừ việc cung cấp tính năng phát hiện spam như một dịch vụ cho người khác, và nêu ngày giấy phép chuyển thành Apache License 2.0.


## Nó chính xác đến mức nào?

Trên các thư tiếng Anh được giữ lại từ dữ liệu huấn luyện, chỉ riêng bộ phân loại đi kèm không đánh dấu nhầm thư hợp lệ (ham) nào là spam và bắt được 97% spam; số liệu đầy đủ theo từng ngôn ngữ có trong [hướng dẫn huấn luyện](../../docs/training.md#the-bundled-model). Liên kết, tệp đính kèm, xác thực, danh sách chặn và mô hình ngôn ngữ bổ sung thêm vào đó. Thư của chính bạn mới là phép thử thật: `spamscanner eval` đo bất kỳ mô hình nào trên bất kỳ tập thư có gắn nhãn nào.


## Nó hỗ trợ những ngôn ngữ nào?

Tất cả. Nó tách từ theo quy tắc Unicode, kể cả tiếng Trung, tiếng Nhật và tiếng Thái, vốn không có khoảng trắng. Với ngôn ngữ mà mô hình đi kèm ít thấy thư, nó giữ trạng thái không chắc thay vì đánh dấu, và một mô hình ngôn ngữ hoặc việc huấn luyện của chính bạn sẽ quyết định. [Ngôn ngữ](../../docs/languages.md)


## Nó có gửi thư của tôi đi đâu không?

Không. Mặc định, nó tra cứu tên máy chủ của các liên kết trên các DNS resolver có lọc của Cloudflare, và ngoài ra không có gì rời khỏi máy. Xác thực, danh sách chặn, mô hình ngôn ngữ và dịch vụ uy tín đều tắt cho đến khi được cấu hình, và dữ liệu cá nhân được xóa trước khi thư được gửi đến một mô hình ngôn ngữ trên đám mây. [Bảo mật và quyền riêng tư](../../docs/security.md)


## Tôi có cần mô hình ngôn ngữ không?

Không. Nó là ý kiến thứ hai cho các trường hợp sát nút. Không có mô hình, những thư đó được quyết định chỉ bằng điểm số.


## Nên dùng mô hình ngôn ngữ nào?

`qwen3.5:4b` qua Ollama trên CPU, hoặc `qwen3.5:9b` với GPU. Cả hai đều theo giấy phép Apache và đọc được 201 ngôn ngữ. Các mô hình trên đám mây của Anthropic, OpenAI, Google và các bên khác cũng hoạt động. [Các mô hình được đề xuất](../../docs/llm.md#recommended-open-models)


## Nó có thay thế được SpamAssassin không?

Với hầu hết các cấu hình, có: nó dùng giao thức của spamd, nên spamc, Exim và Haraka hoạt động mà không cần thay đổi, và nó ghi cùng các header `X-Spam-*`. Nó không chạy các tệp quy tắc của SpamAssassin. [Thay thế SpamAssassin](/spamassassin-alternative/)


## Nó có từ chối thư hợp lệ không?

Việc từ chối thư mặc định là tắt: milter chỉ gắn nhãn. Với `--reject`, chỉ những thư đạt 15 điểm trở lên mới bị từ chối, bằng lỗi tạm thời 451, nên người gửi sẽ thử lại và có thể sửa sai bằng cách thay đổi một thiết lập. Content filter không bao giờ từ chối trong phiên SMTP.


## Làm sao huấn luyện nó trên thư của tôi?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, sau đó dùng `--model model.json`. Tệp mbox, Maildir, thư mục chứa tệp `.eml` và bộ dữ liệu CSV hoặc JSON Lines đều dùng được. [Huấn luyện](../../docs/training.md)


## Nó có chạy được mà không cần Node.js không?

Có: các tệp nhị phân độc lập cho Linux, macOS và Windows đã bao gồm Node.js và mô hình. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Ai phát triển nó?

[Forward Email](https://forwardemail.net), cho chính các máy chủ thư của mình.
