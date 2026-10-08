<!-- source: 1151282f29d3 -->

# Các máy chủ thư khác

Spam Scanner hỗ trợ bốn giao thức, nên hầu hết phần mềm thư có thể dùng nó mà không cần plugin riêng:

| Giao thức | Lệnh                                     | Được dùng bởi                                              |
| --------- | ---------------------------------------- | ---------------------------------------------------------- |
| Milter    | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (với filter-milter)           |
| spamd     | `spamscanner spamd`                      | spamc, Exim, Haraka, và mọi phần mềm viết cho SpamAssassin |
| HTTP      | `spamscanner http`                       | Script, webhook, MTA và dịch vụ tùy biến                   |
| Pipe      | `spamscanner scan`, `spamscanner filter` | Pipe của Postfix, procmail, maildrop, cron job             |

[Postfix và Sendmail](postfix.md) có trang riêng.


## Thay thế trực tiếp cho spamd của SpamAssassin

`spamscanner spamd` trả lời theo giao thức spamd của SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` và, với `--allow-tell`, cả `TELL`. Phần mềm viết cho SpamAssassin hoạt động mà không cần thay đổi; hãy dừng `spamd` và khởi động Spam Scanner trên cùng cổng.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Với spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Các bài kiểm thử đầu cuối của kho mã chạy chính spamc của SpamAssassin với nó.


## Exim

Điều kiện ACL `spam` của Exim giao tiếp với spamd. Trong cấu hình chính:

```text
spamd_address = 127.0.0.1 783
```

Trong DATA ACL (`acl_check_data` trong exim4 của Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` trả lời bằng lỗi tạm thời 4xx, nên người gửi sẽ thử lại và có thể sửa sai. Đổi thành `deny` để từ chối vĩnh viễn khi kết quả đã ổn.


## Haraka

Plugin `spamassassin` của Haraka giao tiếp với spamd. Bật nó trong `config/plugins` và đặt các giá trị sau trong `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: thư mục Junk và học

Một quy tắc Sieve chuyển thư đã gắn nhãn vào Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Với IMAPSieve, việc chuyển thư vào hoặc ra khỏi Junk có thể dạy mô hình. Khởi động HTTP API với một token và một tệp mô hình:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

rồi trỏ máy chủ milter hoặc spamd đến cùng mô hình đó bằng `--model /var/lib/spamscanner/model.json` (hoặc `SPAMSCANNER_MODEL`). Thỉnh thoảng khởi động lại nó để nạp những gì đã học. Một script được `sieve_pipe` chạy sẽ gửi thư lên:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

[Hướng dẫn báo cáo spam](https://doc.dovecot.org/main/core/config/spam_reporting.html) của Dovecot trình bày phần còn lại của thiết lập, giống nhau cho mọi bộ lọc spam học từ script.


## procmail và maildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop:

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

`scan --headers` thoát với mã 1 cho spam. Với các quy tắc trên, procmail và maildrop dùng đầu ra chứ không dùng mã thoát.


## HTTP API

Bất kỳ chương trình nào có thể gửi yêu cầu HTTP đều có thể quét thư:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API](http-api.md) liệt kê mọi endpoint.


## Bên trong một máy chủ thư Node.js

Với [smtp-server](https://nodemailer.com/extras/smtp-server/), plugin Haraka hoặc bất kỳ máy chủ Node.js nào khác, hãy gọi thư viện trực tiếp:

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({authentication: true});

// smtp-server's onData handler
async function onData(stream, session, callback) {
  const result = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (result.action === 'reject') {
    const error = new Error('Message rejected as spam');
    error.responseCode = 451;
    return callback(error);
  }

  // Deliver, with result.isSpam deciding the folder.
  callback();
}
```

`session.envelope` từ smtp-server đã có sẵn cấu trúc `mailFrom` và `rcptTo` mà Spam Scanner đọc.
