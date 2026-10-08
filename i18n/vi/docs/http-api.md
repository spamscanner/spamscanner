<!-- source: faf44f093f8b -->

# HTTP API, máy chủ TCP và spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Nó lắng nghe trên 127.0.0.1 trừ khi `--host` chỉ định khác. Khi có token, mọi yêu cầu trừ `/health` đều cần `Authorization: Bearer <token>`. Hãy đặt nó sau một reverse proxy có TLS trước khi mở ra ngoài máy.

| Phương thức và đường dẫn | Nội dung yêu cầu | Phản hồi                                                                |
| ------------------------ | ---------------- | ----------------------------------------------------------------------- |
| `GET /health`            |                  | `{"ok": true, "version": "7.0.0"}`                                      |
| `POST /scan`             | Thư thô          | [Kết quả quét](api.md#the-result) dưới dạng JSON                        |
| `POST /check`            | Thư thô          | Thư kèm các header `X-Spam-*` được thêm vào, dưới dạng `message/rfc822` |
| `POST /learn/spam`       | Thư thô          | `{"ok": true, "learned": "spam"}`; cần token                            |
| `POST /learn/ham`        | Thư thô          | `{"ok": true, "learned": "ham"}`; cần token                             |

Tham số truy vấn mô tả phiên SMTP:

| Tham số      | Ý nghĩa                                                                  |
| ------------ | ------------------------------------------------------------------------ |
| `ip`         | Địa chỉ IP của client                                                    |
| `hostname`   | Tên DNS ngược đã xác minh của client                                     |
| `helo`       | Tên HELO hoặc EHLO của client                                            |
| `from`       | Người gửi trong envelope                                                 |
| `to`         | Một người nhận; lặp lại tham số hoặc phân tách nhiều người bằng dấu phẩy |
| `verbose=1`  | `/scan`: trả về thêm danh sách từ và tiêu đề thư                         |
| `subjectTag` | `/check`: thêm tiền tố vào tiêu đề của spam, ví dụ `%5BSPAM%5D`          |

`/check` cũng trả về `X-Spam-Flag`, `X-Spam-Score` và `X-Spam-Action` dưới dạng header phản hồi, nên client có thể quyết định mà không cần phân tích thư.

Thư lớn hơn 25 MB nhận `413`. Lần quét thất bại nhận `500` với `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Với `--out model.json`, những gì `/learn` dạy được lưu vào tệp đó sau mỗi yêu cầu. Nếu không có, việc học chỉ kéo dài đến khi máy chủ khởi động lại.

Từ Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Từ Python:

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## Máy chủ TCP

```sh
spamscanner server --port 7830
```

Gửi thư thô, đóng chiều gửi của kết nối, rồi đọc một dòng JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Với `--verbose`, câu trả lời thay vào đó là một dòng văn bản: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` hoặc `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Một máy chủ tương thích SpamAssassin cho spamc, Exim, Haraka và các client SpamAssassin khác. [Thiết lập Exim và Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Lệnh            | Phản hồi                                                  |
| --------------- | --------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                 |
| `SYMBOLS`       | Kết luận và tên các phép kiểm tra đã kích hoạt            |
| `REPORT`        | Kết luận và bảng các phép kiểm tra, điểm và lý do         |
| `REPORT_IFSPAM` | Như `REPORT`, với báo cáo rỗng cho thư hợp lệ             |
| `PROCESS`       | Kết luận và thư kèm các header `X-Spam-*`                 |
| `HEADERS`       | Kết luận và khối header của thư kèm các header `X-Spam-*` |
| `PING`          | `PONG`                                                    |
| `SKIP`          | Không có gì                                               |
| `TELL`          | Học spam hoặc ham, với `--allow-tell`; lưu vào `--out`    |

Yêu cầu nén (`Compress: zlib`) bị từ chối.
