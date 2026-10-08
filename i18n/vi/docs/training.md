<!-- source: 7cc30ff4ad91 -->

# Huấn luyện

Mô hình đi kèm dùng được ngay. Một mô hình được huấn luyện trên thư của chính bạn hoạt động tốt hơn, vì nó học được thư hợp lệ (ham) của bạn trông như thế nào: các bản tin bạn nhận, cách viết của đồng nghiệp, các ngôn ngữ bạn nhận thư.


## Huấn luyện một mô hình

Trỏ `train` đến các thư mục chứa spam và ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Nguồn có thể là:

* tệp **mbox**, kể cả dạng nén gzip (`.mbox.gz`),
* một **Maildir** (các thư mục `cur` và `new` được đọc, `tmp` bị bỏ qua),
* một **thư mục** chứa tệp `.eml`, được đọc đệ quy,
* một **bộ dữ liệu**: tệp CSV hoặc JSON Lines có một cột văn bản và một cột nhãn (`--dataset`). Các cột tên `text`, `message`, `body`, `email` hoặc `content`, và `label`, `category`, `class`, `spam` hoặc `is_spam`, được tự động nhận diện; nếu không, dùng `--text-column` và `--label-column`. Các nhãn như `spam`, `1`, `phishing` và `ham`, `0`, `not_spam`, `legitimate` đều được hiểu.

Thư trùng lặp chỉ được tính một lần. Để xây dựng tiếp trên mô hình đi kèm thay vì bắt đầu từ đầu, thêm `--merge`.

Dùng mô hình:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Bao nhiêu thư là đủ: vài trăm thư mỗi loại cho một mô hình hữu ích, vài nghìn thư cho một mô hình tốt. Giữ hai loại xấp xỉ cân bằng, và đưa những thư bạn không muốn bị lọc (đặt lại mật khẩu, hóa đơn từ nhà cung cấp của bạn) vào phần ham.


## Đo lường

Giữ lại một phần thư không dùng để huấn luyện và đo lường trên đó:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Mô hình đi kèm trên tin nhắn SMS bằng 21 ngôn ngữ mà nó chưa từng thấy, phần lớn là những ngôn ngữ nó hầu như không biết:

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

Precision (độ chính xác) là tỷ lệ những gì nó gọi là spam thực sự là spam; recall (độ phủ) là tỷ lệ spam mà nó bắt được. Ở đây thư không chắc được tính là spam bị bỏ sót, dù khi quét thật, các phép kiểm tra khác và mô hình ngôn ngữ vẫn có thể bắt được chúng. Con số cần theo dõi là dương tính giả: ham bị đánh dấu là spam. Trong lần chạy trên, mô hình không chắc về phần lớn các thư này chứ không phán đoán sai, đúng như hành vi mong muốn với những ngôn ngữ nó có ít thư.

`--json` cho cùng các con số đó để dùng trong script.


## Học từ báo cáo

Khi người dùng chuyển thư vào hoặc ra khỏi thư mục Junk, hãy dạy mô hình từng thư một:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Lệnh `learn` đầu tiên tạo tệp từ mô hình đi kèm. Qua HTTP, `POST /learn/spam` và `/learn/ham` trên [HTTP API](http-api.md) làm điều tương tự, và `spamc -L spam` hoạt động với [máy chủ spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) khi có `--allow-tell`. [IMAPSieve của Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) có thể gọi một trong hai khi thư được di chuyển.

Từ Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Một thư được báo cáo là phân loại sai nên được gỡ học khỏi lớp sai trước khi được học vào lớp đúng, nếu trước đó nó đã được học.


## Mô hình đi kèm

`model/classifier.json` được tạo bởi `npm run model:train` từ các bộ dữ liệu công khai sau trên Hugging Face, tất cả đều theo giấy phép mở:

| Bộ dữ liệu                                                                                                                                                                                                                                                                                                                 | Giấy phép                         | Nội dung                           |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | ---------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                        | Tin nhắn và email bằng 43 ngôn ngữ |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Kho ngữ liệu nghiên cứu công khai | Kho ngữ liệu Enron-Spam            |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                           | Tin nhắn Telegram tiếng Nga        |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                               | Tin nhắn tổng hợp                  |

Nó học từ 62.480 thư spam và 76.489 thư ham. Script giữ lại mỗi thư thứ mười, huấn luyện trên phần còn lại và đo lường riêng bộ phân loại, không có các phép kiểm tra khác:

| Tập kiểm tra giữ lại | Số thư | Precision | Recall | Dương tính giả | Không chắc |
| -------------------- | -----: | --------: | -----: | -------------: | ---------: |
| Tiếng Anh            |  6.564 |    100,0% |  97,0% |           0,0% |       2,4% |
| Tiếng Nga            |  1.682 |    100,0% |  97,4% |           0,0% |       2,2% |
| Tiếng Ý              |  1.389 |     98,1% |  85,3% |           1,8% |      10,9% |
| Tiếng Đức            |  1.309 |     97,7% |  76,1% |           2,2% |      20,7% |
| Tiếng Tây Ban Nha    |  1.281 |     97,5% |  82,5% |           2,6% |      16,8% |
| Enron-Spam           |  2.888 |    100,0% |  93,1% |           0,0% |       4,5% |
| all-scam-spam        |  4.236 |    100,0% |  88,8% |           0,0% |      11,2% |
| Tất cả               | 13.840 |     99,2% |  85,1% |           0,5% |      12,4% |

Ở đây spam nghĩa là bộ phân loại cho xác suất từ 99% trở lên, mức mà riêng bộ phân loại đạt ngưỡng spam. Khi quét thật, spam mà nó kém chắc chắn hơn vẫn nhận điểm, và các phép kiểm tra khác cộng thêm điểm của chúng.

Kết quả tiếng Đức, tiếng Tây Ban Nha và tiếng Ý đến từ các bộ dữ liệu tổng hợp, vốn chứa những thư gần như giống hệt nhau nhưng được gắn nhãn cả spam lẫn ham: một phần sai số đó nằm ở nhãn, không phải ở mô hình. Thư bằng chính các ngôn ngữ của bạn là cách khắc phục tốt nhất. Các con số, với mọi ngôn ngữ và bộ dữ liệu, có trong `metadata.metrics` của mô hình.

### Thêm ngôn ngữ

`npm run model:train -- --with multilingual-sms` bổ sung [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection được dịch máy sang 21 ngôn ngữ. Bộ này không được đưa vào mô hình đi kèm vì thẻ mô tả của nó ghi giấy phép GPL; hãy kiểm tra xem giấy phép đó có phù hợp với cách bạn chia sẻ mô hình không. Khi huấn luyện có bộ này, kết quả trên tập giữ lại cho các ngôn ngữ mà mô hình đi kèm hầu như không biết là:

| Ngôn ngữ         | Số thư | Precision | Recall | Dương tính giả |
| ---------------- | -----: | --------: | -----: | -------------: |
| Tiếng Trung      |    430 |    100,0% |  82,3% |           0,0% |
| Tiếng Ả Rập      |    430 |    100,0% |  84,6% |           0,0% |
| Tiếng Hàn        |    412 |    100,0% |  80,4% |           0,0% |
| Tiếng Nhật       |    486 |     96,0% |  85,7% |           0,5% |
| Tiếng Hindi      |    412 |    100,0% |  63,9% |           0,0% |
| Tiếng Pháp       |    480 |     98,6% |  94,2% |           0,6% |
| Tiếng Thổ Nhĩ Kỳ |    220 |    100,0% |  73,1% |           0,0% |

### Huấn luyện lại

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Tệp mô hình

Mô hình là một tệp JSON: số thư spam và ham đã học, và với mỗi đặc trưng đã băm, số thư spam và ham chứa đặc trưng đó, được sắp xếp và mã hóa base64. Nó không chứa từ ngữ hay nội dung thư nào. `--max-features` chỉ giữ các đặc trưng xuất hiện nhiều nhất và `--min-count` loại bỏ các đặc trưng hiếm, đánh đổi độ chính xác lấy kích thước; mô hình đi kèm giữ 400.000 đặc trưng trong khoảng 6 MB.

Không thể tải các mô hình từ Spam Scanner 6 trở về trước: chúng băm các đặc trưng khác. Hãy huấn luyện một mô hình mới từ cùng tập thư.
