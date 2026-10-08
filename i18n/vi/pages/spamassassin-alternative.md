<!-- source: 1562b843d858 -->

<!--
label: Thay thế SpamAssassin
title: Giải pháp thay thế SpamAssassin hỗ trợ giao thức spamd
description: Thay spamd của SpamAssassin bằng Spam Scanner. spamc, Exim và Haraka vẫn hoạt động, các header X-Spam giữ nguyên tên, và mọi ngôn ngữ đều được hỗ trợ.
keywords: thay thế SpamAssassin, giải pháp thay thế SpamAssassin, thay thế spamd, spamc, bộ lọc spam Exim, Haraka spamassassin, thay thế rspamd, X-Spam-Status
-->

# Giải pháp thay thế SpamAssassin hỗ trợ giao thức spamd

Spam Scanner trả lời theo giao thức spamd của SpamAssassin, nên phần mềm viết cho SpamAssassin dùng được nó mà không cần thay đổi: spamc, điều kiện `spam` của Exim, plugin `spamassassin` của Haraka và các phần mềm khác.


## Thay thế vào

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

Nó trả lời `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` và, với `--allow-tell`, cả `TELL` để học. Các bài kiểm thử đầu cuối của dự án chạy chính spamc của SpamAssassin với nó.


## Những gì giữ nguyên

* Các header: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` và `X-Spam-Status` theo định dạng của SpamAssassin, nên các quy tắc Sieve, procmail và quy tắc của ứng dụng thư hiện có vẫn hoạt động.
* Một điểm số với ngưỡng 5, gồm các phép kiểm tra có tên và điểm: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` và các phép khác.
* Có thể thay đổi điểm của từng phép kiểm tra theo tên.


## Những gì khác biệt

* **Ngôn ngữ.** Từ được tách theo quy tắc Unicode, nên tiếng Trung, tiếng Nhật và tiếng Thái được đọc thành từng từ thay vì một chuỗi dài, và các kiểu ngụy trang như ký tự vô hình hoặc chữ Kirin trong từ Latin được hoàn nguyên trước.
* **Phishing.** Tên miền giả mạo, liên kết lừa đảo và tên thương hiệu trong tên hiển thị được kiểm tra mà không cần thêm quy tắc.
* **Tệp đính kèm** được nhận diện qua các byte của chúng: một tệp thực thi bị đổi tên thành `.pdf` vẫn là tệp thực thi.
* **Mô hình ngôn ngữ.** Các trường hợp sát nút có thể được chuyển cho một mô hình cục bộ qua Ollama hoặc một mô hình trên đám mây.
* **Node.js.** Một lệnh `npm install`, hoặc một tệp nhị phân độc lập; không có module Perl hay bản cập nhật quy tắc nào phải quản lý.

Spam Scanner không chạy các tệp quy tắc của SpamAssassin, và định dạng cơ sở dữ liệu Bayes của nó là riêng: hãy huấn luyện nó từ cùng tập thư bằng `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot và procmail](../../docs/mail-servers.md)
