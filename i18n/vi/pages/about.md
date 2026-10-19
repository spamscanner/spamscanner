<!-- source: 599bd320e55a -->

<!--
label: Giới thiệu
title: Giới thiệu Spam Scanner, giấy phép và quyền riêng tư
description: Ai làm ra Spam Scanner, cách báo lỗi hoặc lỗ hổng, giấy phép của nó và trang web này thu thập gì: không cookie, không phân tích.
keywords: giới thiệu Spam Scanner, Forward Email, giấy phép Spam Scanner, BUSL-1.1, liên hệ Spam Scanner, quyền riêng tư Spam Scanner
-->

# Giới thiệu Spam Scanner

Spam Scanner là bộ lọc spam cho email do [Forward Email](https://forwardemail.net), dịch vụ email chú trọng quyền riêng tư, tạo ra cho các máy chủ thư của chính họ. Mã nguồn, issue và các bản phát hành nằm trên [GitHub](https://github.com/spamscanner/spamscanner), còn gói nằm trên [npm](https://www.npmjs.com/package/spamscanner).


## Ai làm ra nó

Đội ngũ Forward Email viết và duy trì Spam Scanner. Forward Email không lưu nhật ký nội dung thư, nên không thể gửi thư tới một dịch vụ lọc bên ngoài: bộ lọc phải chạy trên máy chủ của họ và giải thích mọi quyết định mà không cần ai đọc thư. [Forward Email dùng nó như thế nào](../../docs/forward-email.md)

Forward Email cũng là mã nguồn mở, tại [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Người sáng lập từng là một trong những nhân viên đầu tiên của DuckDuckGo.


## Liên hệ

* **Câu hỏi, lỗi và đề xuất tính năng:** mở một issue trên [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Lỗ hổng bảo mật:** báo riêng qua [tính năng báo cáo lỗ hổng của GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), không đăng trong issue công khai. Địa chỉ này cũng có trong [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Giấy phép khác:** liên hệ [Forward Email](https://forwardemail.net).


## Điều khoản giấy phép

[Giấy phép](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) của Spam Scanner là Business Source License 1.1, với Apache License 2.0 là Change License. Change Date ghi trong giấy phép đã qua, và từ ngày đó giấy phép trao cho bạn các quyền theo Apache License 2.0.


## Quyền riêng tư

Trang web này không đặt cookie và không tải công cụ phân tích, trình theo dõi, quảng cáo, phông chữ hay tập lệnh từ trang khác. Mọi tệp đều đến từ spamscanner.net.

* Giao diện, ngôn ngữ bạn chọn và máy chủ Mastodon bạn chia sẻ tới được lưu trong bộ nhớ cục bộ của trình duyệt và không được gửi đi đâu.
* Video chỉ tải khi bạn phát nó.
* Các liên kết chia sẻ là liên kết thường, nên không có gì từ các mạng đó được tải cho đến khi bạn mở một liên kết.
* Trang web được lưu trữ trên GitHub Pages, và GitHub ghi lại địa chỉ IP của mỗi khách truy cập vì mục đích bảo mật. Xem [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) và [Tuyên bố quyền riêng tư của GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Phần mềm gửi đi những gì

Spam Scanner không gửi dữ liệu đo lường và không kiểm tra cập nhật. Theo mặc định, nó tra cứu tên máy chủ của các liên kết trong thư trên các trình phân giải DNS có lọc của Cloudflare, và không có gì khác rời khỏi máy. Các kiểm tra mạng khác đều tắt cho đến khi bạn bật. [Bảo mật và quyền riêng tư](../../docs/security.md)


## Bản phát hành

GitHub Actions dựng các tệp nhị phân độc lập từ kho mã công khai. Mỗi bản phát hành liệt kê mã băm của chúng trong tệp `SHA256SUMS`, được tập lệnh cài đặt kiểm tra, và mỗi tệp nhị phân mang chứng thực nguồn gốc bản dựng đã ký. Các bản phát hành và ghi chú nằm trên [GitHub](https://github.com/spamscanner/spamscanner/releases).
