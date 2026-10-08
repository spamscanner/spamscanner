<!-- source: f1043eb5fc58 -->

# Postfix và Sendmail

Spam Scanner kết nối với Postfix theo hai cách:

* **Dưới dạng milter** (khuyến nghị). Postfix hỏi nó về từng thư trong phiên SMTP, trước khi chấp nhận thư. Spam có thể bị từ chối bằng phản hồi 4xx hoặc 5xx, nên máy chủ gửi, chứ không phải máy chủ của bạn, phải xử lý nó. Sendmail dùng cùng giao thức này.
* **Dưới dạng content filter.** Postfix chấp nhận thư, chuyển nó qua `spamscanner filter`, công cụ này thêm header rồi trả thư lại bằng sendmail. Không có gì bị từ chối trong phiên SMTP.

Cả hai đều thêm các header sau vào mọi thư:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Các header `X-Spam-*` đã có sẵn trong thư bị xóa trước, nên người gửi không thể tự đánh dấu thư của mình là sạch.


## Milter

### 1. Chạy milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Với `--reject`, thư đạt ngưỡng từ chối (15 điểm) bị từ chối với `451 4.7.1 Message rejected as spam`. Mã 451 là tạm thời: người gửi thử lại sau và vẫn có thể sửa sai bằng cách thay đổi một thiết lập. Dùng `--reject-code 550` để từ chối vĩnh viễn khi kết quả đã ổn. Với `--quarantine`, spam được đưa vào hold queue của Postfix.

Dưới dạng dịch vụ systemd, trong `/etc/systemd/system/spamscanner-milter.service`:

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. Trỏ Postfix đến milter

Trong `/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters` áp dụng cho thư đến qua SMTP. Để trống `non_smtpd_milters` trừ khi thư gửi bằng lệnh `sendmail` cũng cần được quét.

### 3. Kiểm tra

[swaks](https://www.jetmore.org/john/code/swaks/) gửi thư kiểm thử. GTUBE là chuỗi kiểm thử mà mọi bộ lọc spam coi là spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Không có `--reject`, thư được chuyển đến kèm `X-Spam-Flag: YES` và tiêu đề đã gắn nhãn. Với `--reject`, swaks hiển thị phản hồi 451 hoặc 550.


## Content filter

Dùng cách này khi thư không bao giờ được phép bị từ chối trong phiên SMTP, hoặc cho máy chủ không dùng được milter.

Trong `/etc/postfix/master.cf`, thêm một dịch vụ lọc và dùng nó trên listener SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix chạy bộ lọc với môi trường gần như trống, nên `argv` ghi Node.js và script bằng đường dẫn đầy đủ (`command -v node` và `npm root --global` cho biết các đường dẫn này). Sau đó:

```sh
sudo postfix reload
```

Bộ lọc trả thư lại bằng `sendmail -G -i`. Thư gửi theo cách này không đi qua listener `smtp` lần nữa, nên không bị lọc hai lần.

Mã thoát cho Postfix biết điều gì đã xảy ra: 0 là đã chuyển, 69 là bị từ chối (với `--reject`: Postfix trả thư về cho người gửi), 75 là lỗi tạm thời (Postfix giữ thư và thử lại). Mọi lỗi khi quét hoặc chuyển thư đều là 75, nên một thiết lập sai không bao giờ làm mất hay trả thư về.


## Sendmail

Trong `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` khiến Sendmail trả lời bằng lỗi tạm thời khi milter không khả dụng; bỏ nó đi để chấp nhận thư mà không lọc. Tạo lại `sendmail.cf` và khởi động lại Sendmail.


## Chuyển spam vào thư mục Junk

Chỉ gắn nhãn thì spam vẫn được chuyển vào hộp thư đến. Với Dovecot, một quy tắc Sieve sẽ di chuyển nó:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Các máy chủ thư khác](mail-servers.md) trình bày Dovecot, Exim, Haraka và procmail, và [huấn luyện](training.md#learning-from-reports) cho thấy cách học từ những thư mà người dùng chuyển vào và ra khỏi Junk.


## Đã kiểm thử

Các bài kiểm thử đầu cuối của kho mã chạy một Postfix thật: thư hợp lệ được chuyển đến kèm header, `X-Spam-Flag` giả mạo bị xóa, spam được gắn nhãn, GTUBE bị từ chối bằng mã 550 trong phiên SMTP, và content filter gắn nhãn thư trên cổng thứ hai. `scripts/e2e-postfix.sh` thiết lập Postfix đó và `test/e2e/postfix.test.js` gửi thư.
