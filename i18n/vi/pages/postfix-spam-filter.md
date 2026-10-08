<!-- source: f33722183f00 -->

<!--
label: Bộ lọc spam Postfix
title: Bộ lọc spam Postfix với milter hoặc content filter
description: Lọc spam trên máy chủ Postfix bằng milter hoặc content filter của Spam Scanner: cài đặt, unit systemd, từ chối bằng mã 4xx hoặc 5xx, và thư mục Junk.
keywords: bộ lọc spam Postfix, lọc thư rác Postfix, Postfix milter, smtpd_milters, Postfix content filter, chống spam Postfix, từ chối spam Postfix
-->

# Bộ lọc spam Postfix

Spam Scanner lọc thư cho một máy chủ Postfix sau khoảng năm phút thiết lập. Nó chạy dưới dạng milter, nên Postfix hỏi nó về từng thư trong phiên SMTP và có thể từ chối spam trước khi chấp nhận.


## Cài đặt và chạy

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` kiểm tra SPF, DKIM, DMARC và ARC; `--subject-tag` đánh dấu spam trong tiêu đề thư. Mỗi thư đều nhận các header `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` và `X-Spam-Action`, và mọi header `X-Spam-*` do người gửi chèn vào sẽ bị xóa trước.


## Kết nối Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` cho thư đi qua mà không lọc nếu milter ngừng hoạt động; `tempfail` thì yêu cầu người gửi thử lại.


## Từ chối spam trong phiên SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

Thư đạt ngưỡng từ chối (15 điểm) bị từ chối với `451 4.7.1 Message rejected as spam`. Mã 451 là tạm thời: người gửi giữ lại thư và thử lại, nên một quyết định sai chỉ gây chậm trễ chứ không làm mất thư. Khi kết quả đã ổn, `--reject-code 550` biến việc từ chối thành vĩnh viễn.


## Không dùng milter

Content filter chạy sau khi Postfix chấp nhận thư: Postfix chuyển thư qua `spamscanner filter`, công cụ này thêm header rồi trả thư lại. Không có gì bị từ chối trong phiên, và khi có lỗi thì việc chuyển thư luôn được hoãn lại chứ không bị trả về. [Thiết lập content filter](../../docs/postfix.md#content-filter)


## Đưa spam vào Junk

Với Dovecot, một quy tắc Sieve chuyển thư đã gắn nhãn vào thư mục:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Được kiểm thử với Postfix thật

Các bài kiểm thử đầu cuối của dự án chạy Postfix với milter và content filter: thư hợp lệ được chuyển đến kèm header và `X-Spam-Flag` giả mạo bị xóa, spam được gắn nhãn, và GTUBE bị từ chối bằng mã 550 trong phiên SMTP.

Tiếp theo: [hướng dẫn đầy đủ cho Postfix và Sendmail](../../docs/postfix.md), với một unit systemd và `INPUT_MAIL_FILTER` của Sendmail.
