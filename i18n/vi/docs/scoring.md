<!-- source: 6f6b765c5fc1 -->

# Các phép kiểm tra và điểm

Thư là spam khi đạt 5 điểm và bị từ chối khi đạt 15 điểm. Mỗi phép kiểm tra dưới đây cộng hoặc trừ điểm; kết quả liệt kê các phép đã kích hoạt.

Thay đổi ngưỡng bằng `threshold` và `rejectThreshold`. Thay đổi điểm bằng `scores`, theo khóa thiết lập (`scores: {deceptiveLink: 4}`) hoặc theo tên phép kiểm tra, cách này cố định điểm của phép kiểm tra đó (`scores: {FROM_NAME_BRAND: 4}`).


## Bộ phân loại

| Phép kiểm tra              | Điểm           | Ý nghĩa                                                                                                                                                                                                                                                                                                                                         |
| -------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` đến `BAYES_999` | -2,5 đến +6,25 | Xác suất spam của bộ phân loại, theo thang log-odds: 2,4 điểm ở 90%, 5 ở 99% và 6,25 ở 99,9%, nên bộ phân loại chỉ tự đánh dấu spam khi nó chắc chắn ít nhất 99%. Tên cho biết khoảng: `BAYES_999` là từ 99,9% trở lên, `BAYES_99` từ 99% đến 99,9%, `BAYES_50` từ 40% đến 60%. Các khóa thiết lập `bayesHam` và `bayesSpam` đặt hai đầu thang. |


## Phishing và liên kết

| Phép kiểm tra               | Điểm | Khóa thiết lập      | Ý nghĩa                                                                             |
| --------------------------- | ---: | ------------------- | ----------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |    5 | `homograph`         | Tên miền của liên kết bắt chước một thương hiệu bằng ký tự trông giống hoặc bị tráo |
| `MIXED_SCRIPT_DOMAIN`       |    3 | `mixedScriptDomain` | Một nhãn tên miền trộn nhiều bảng chữ cái                                           |
| `BRAND_IN_DOMAIN`           |  1,5 | `brandInDomain`     | Tên thương hiệu nằm trong tên miền của người khác                                   |
| `TYPO_DOMAIN`               |    1 | `typoDomain`        | Chỉ khác tên miền của một thương hiệu một chữ cái                                   |
| `DECEPTIVE_LINK`            |    3 | `deceptiveLink`     | Liên kết hiển thị một địa chỉ nhưng dẫn tới địa chỉ khác                            |
| `MALICIOUS_DOMAIN`          |    6 | `maliciousDomain`   | Resolver chặn mã độc của Cloudflare chặn một tên miền được liên kết                 |
| `ADULT_DOMAIN`              |    2 | `adultDomain`       | Resolver gia đình của Cloudflare chặn một tên miền được liên kết                    |
| `URIBL_<LIST>`              |    5 | `uriblListed`       | Một tên miền được liên kết nằm trong danh sách chặn tên miền, ví dụ `URIBL_DBL`     |


## Tệp đính kèm

| Phép kiểm tra           |     Điểm | Khóa thiết lập                           | Ý nghĩa                                                   |
| ----------------------- | -------: | ---------------------------------------- | --------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |       10 | `executable`                             | Một chương trình hoặc script                              |
| `DISGUISED_EXECUTABLE`  |       12 | `disguisedExecutable`                    | Một chương trình được đặt tên như tài liệu hoặc hình ảnh  |
| `DOUBLE_EXTENSION`      |        6 | `doubleExtension`                        | Một tên như `invoice.pdf.exe`                             |
| `RTL_OVERRIDE_FILENAME` |        6 | `rtlOverride`                            | Ký tự ghi đè hướng phải sang trái che giấu đuôi tệp thật  |
| `EXECUTABLE_IN_ARCHIVE` |        8 | `executableInArchive`                    | Một chương trình bên trong tệp ZIP                        |
| `ENCRYPTED_ARCHIVE`     |        2 | `encryptedArchive`                       | Một tệp nén mà trình quét không mở được                   |
| `MACRO_ATTACHMENT`      |        4 | `macro`                                  | Một tệp Office có macro                                   |
| `PDF_ACTIVE_CONTENT`    |        3 | `pdfActive`                              | Một PDF có JavaScript, hành động khởi chạy hoặc tệp nhúng |
| `RTF_EMBEDDED_OBJECT`   |        4 | `rtfObject`                              | Một tệp RTF có đối tượng nhúng                            |
| `HTML_ATTACHMENT`       | 1 hoặc 3 | `htmlAttachment`, `activeHtmlAttachment` | Một tệp HTML; 3 khi có script hoặc biểu mẫu               |
| `VIRUS`                 |      100 | `virus`                                  | ClamAV phát hiện virus                                    |


## Quy tắc

| Phép kiểm tra             | Điểm | Ý nghĩa                                                                                                |
| ------------------------- | ---: | ------------------------------------------------------------------------------------------------------ |
| `GTUBE`                   | 1000 | Chuỗi kiểm thử GTUBE                                                                                   |
| `SEXTORTION_SUBJECT`      |    6 | Tiêu đề dùng trong các vụ lừa đảo tống tiền tình dục (sextortion) và chiếm đoạt tài khoản              |
| `PAYPAL_INVOICE`          |    6 | Hóa đơn hoặc yêu cầu chuyển tiền PayPal, một kênh bị lạm dụng để lừa đảo                               |
| `MICROSOFT_SPAM_VERDICT`  |    5 | Microsoft đã đánh dấu thư là spam trước khi chuyển tiếp (chỉ tin cậy khi đến từ máy chủ của Microsoft) |
| `MICROSOFT_HIGH_SCL`      |    3 | Microsoft gán cho thư mức độ tin cậy spam (SCL) cao (tương tự)                                         |
| `PROMPT_INJECTION`        |    3 | Văn bản nhắm vào bộ lọc AI                                                                             |
| `SELF_SPOOF`              |    3 | Tự nhận đến từ chính tên miền của người nhận và không qua xác thực                                     |
| `FROM_NAME_OTHER_ADDRESS` |  2,5 | Tên hiển thị chứa một địa chỉ email khác                                                               |
| `FROM_NAME_BRAND`         |    2 | Tên hiển thị tự nhận là một thương hiệu mà địa chỉ không thuộc về                                      |
| `DATE_IN_FUTURE`          |    1 | Ngày ghi trên thư ở tương lai, quá hiện tại hơn một ngày                                               |
| `MISSING_DATE`            |  0,5 | Không có header Date                                                                                   |
| `MISSING_MESSAGE_ID`      |  0,5 | Không có header Message-ID                                                                             |

Các quy tắc có điểm ít nhất bằng ngưỡng spam cũng xuất hiện trong `results.arbitrary`, như ở các phiên bản trước.


## Làm rối và ngôn ngữ

| Phép kiểm tra          | Điểm | Khóa thiết lập        | Ý nghĩa                                                      |
| ---------------------- | ---: | --------------------- | ------------------------------------------------------------ |
| `INVISIBLE_CHARACTERS` |    2 | `invisibleCharacters` | Từ ba ký tự vô hình trở lên bên trong văn bản                |
| `MIXED_SCRIPT_WORDS`   |  2,5 | `mixedScriptWords`    | Từ hai từ trở lên trộn chữ cái từ các bảng chữ cái khác nhau |
| `STYLED_LETTERS`       |  1,5 | `styledLetters`       | Chữ cái toán học hoặc chữ trong khung giả làm văn bản thường |
| `LANGUAGE_NOT_ALLOWED` |    3 | `languageNotAllowed`  | Không thuộc `allowedLanguages`                               |


## Xác thực

Cần địa chỉ IP của client và `authentication: true`.

| Phép kiểm tra  | Điểm | Khóa thiết lập (trong `authentication.weights`) |
| -------------- | ---: | ----------------------------------------------- |
| `SPF_PASS`     | -0,5 | `spfPass`                                       |
| `SPF_FAIL`     |    2 | `spfFail`                                       |
| `SPF_SOFTFAIL` |    1 | `spfSoftfail`                                   |
| `DKIM_PASS`    | -0,5 | `dkimPass`                                      |
| `DKIM_FAIL`    |    1 | `dkimFail`                                      |
| `DMARC_PASS`   | -1,5 | `dmarcPass`                                     |
| `DMARC_FAIL`   |  3,5 | `dmarcFail`                                     |
| `ARC_PASS`     | -0,5 | `arcPass`                                       |
| `ARC_FAIL`     |    1 | `arcFail`                                       |


## Uy tín và danh sách chặn

| Phép kiểm tra  | Điểm | Khóa thiết lập | Ý nghĩa                                                                     |
| -------------- | ---: | -------------- | --------------------------------------------------------------------------- |
| `DENYLISTED`   |  100 | `denylisted`   | Địa chỉ IP, tên miền hoặc địa chỉ của người gửi nằm trong danh sách từ chối |
| `ALLOWLISTED`  |  -20 | `allowlisted`  | Nằm trong danh sách cho phép                                                |
| `TRUTH_SOURCE` |   -5 | `truthSource`  | Một dịch vụ uy tín đánh dấu người gửi là đáng tin cậy                       |
| `RBL_<LIST>`   |    4 | `rblListed`    | Địa chỉ IP của client nằm trong một danh sách chặn, ví dụ `RBL_ZEN`         |


## Mô hình ngôn ngữ và các mô hình tùy chọn

| Phép kiểm tra                                         | Điểm         | Khóa thiết lập | Ý nghĩa                                                                    |
| ----------------------------------------------------- | ------------ | -------------- | -------------------------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | tối đa +6    | `llmSpam`      | Kết luận của mô hình, nhân với độ tin cậy                                  |
| `LLM_HAM`                                             | tối thiểu -3 | `llmHam`       | Tương tự                                                                   |
| `TOXIC_CONTENT`                                       | 3            | `toxicity`     | Một mô hình phát hiện nội dung độc hại do bạn cung cấp đã đánh dấu văn bản |
| `NSFW_IMAGE`                                          | 3            | `nsfw`         | Một mô hình hình ảnh do bạn cung cấp đã đánh dấu một hình ảnh              |
