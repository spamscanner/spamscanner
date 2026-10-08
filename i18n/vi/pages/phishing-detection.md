<!-- source: 0378a5e0f12b -->

<!--
label: Phát hiện phishing
title: Phát hiện phishing email: tên miền giả, liên kết lừa, mạo danh
description: Cách Spam Scanner phát hiện phishing: tên miền giả Unicode, liên kết hiện địa chỉ này nhưng dẫn tới nơi khác, tên thương hiệu, resolver Cloudflare, DMARC.
keywords: phát hiện phishing, lọc email lừa đảo, email lừa đảo, tấn công homograph, IDN homograph, phát hiện tên miền giả mạo, liên kết lừa đảo, giả mạo thương hiệu email
-->

# Phát hiện phishing trong email

Phishing hoạt động bằng cách giả làm người khác. Spam Scanner kiểm tra những chỗ mà lớp ngụy trang lộ ra.


## Tên miền giả mạo

Mỗi tên miền trong liên kết được rút gọn thành một bộ khung bằng bảng ký tự dễ nhầm lẫn (confusables) của Unicode và được so sánh với gần 100 thương hiệu thường bị mạo danh:

| Tên miền                            | Bị phát hiện là                               |
| ----------------------------------- | --------------------------------------------- |
| `pаypal.com` (chữ а Kirin)          | Ký tự dễ nhầm lẫn                             |
| `paypa1-secure.top`                 | Ký tự bị tráo                                 |
| `xn--pple-43d.com`                  | Punycode của `аpple.com`                      |
| `paypal.com.account-verify.example` | Thương hiệu nằm trong tên miền của người khác |
| `paypall.com`                       | Chỉ khác một chữ cái                          |

Có thể thêm thương hiệu, và có thể đưa các tên miền của bạn vào danh sách cho phép.


## Liên kết lừa đảo

Một liên kết HTML có văn bản là một địa chỉ còn đích đến là địa chỉ khác, như văn bản `https://www.paypal.com/signin` nhưng trỏ tới `http://paypa1-secure.top/login`, cộng 3 điểm.


## Tên hiển thị và giả mạo

* Tên hiển thị chứa một thương hiệu (“PayPal Security”) từ một địa chỉ thuộc tên miền khác.
* Tên hiển thị chứa một địa chỉ email khác.
* Thư tự nhận đến từ chính tên miền của người nhận nhưng không qua được SPF, DKIM và DMARC.


## Các trang độc hại đã biết

Tên máy chủ trong liên kết được tra cứu trên resolver 1.1.1.2 của Cloudflare, vốn chặn các trang mã độc và phishing đã biết, và tùy chọn trên các danh sách chặn tên miền như Spamhaus DBL.


## Tệp đính kèm

Phishing cũng đến dưới dạng tệp đính kèm HTML hiển thị một trang đăng nhập giả ngay trên máy, không cần mạng, và dưới dạng tệp thực thi bị đổi tên thành `.pdf`. Cả hai đều được phát hiện qua nội dung của chúng.

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

[Cách các phép kiểm tra hoạt động](../../docs/how-it-works.md#phishing)
