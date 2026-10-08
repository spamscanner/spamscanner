<!-- source: 0ad167ddd34e -->

<!--
label: Bộ lọc spam đa ngôn ngữ
title: Lọc spam đa ngôn ngữ: tiếng Trung, Ả Rập, Nga và mọi chữ viết
description: Cách Spam Scanner lọc spam bằng mọi ngôn ngữ: tách từ theo Unicode, hoàn nguyên ngụy trang, và không đánh dấu ngôn ngữ mà mô hình ít biết.
keywords: bộ lọc spam đa ngôn ngữ, lọc thư rác tiếng Việt, lọc spam tiếng Trung, lọc spam tiếng Ả Rập, lọc spam tiếng Nga, lọc spam tiếng Nhật, phát hiện spam Unicode, spam homoglyph
-->

# Bộ lọc spam đa ngôn ngữ

Nhiều bộ lọc spam được xây dựng cho tiếng Anh. Spam bằng ngôn ngữ khác lọt qua chúng, còn thư bình thường bằng ngôn ngữ khác lại bị đánh dấu chỉ vì chữ viết. Spam Scanner được xây dựng để tránh cả hai.


## Đọc từ ngữ

Từ được tách bằng `Intl.Segmenter`, tức các quy tắc ranh giới từ của Unicode kèm từ điển cho tiếng Trung, tiếng Nhật, tiếng Thái, tiếng Lào, tiếng Khmer và tiếng Miến Điện. Một câu tiếng Trung trở thành các từ như 恭喜, 获得 và 大奖, chứ không phải một chuỗi dài không bao giờ lặp lại.

Các kiểu ngụy trang được hoàn nguyên trước khi đếm: ký tự vô hình bên trong từ, chữ Kirin hoặc chữ Hy Lạp bên trong từ Latin (`pаypal`), chữ số thay cho chữ cái (`v1agra`), và chữ cái toán học hoặc chữ trong khung (𝐅𝐑𝐄𝐄). Bản thân mỗi kiểu ngụy trang cũng là một dấu hiệu.


## Không đánh dấu những gì nó không biết

Các bộ dữ liệu spam công khai chứa nhiều spam tiếng nước ngoài hơn hẳn thư hợp lệ (ham) tiếng nước ngoài, nên một bộ phân loại ngây thơ sẽ học rằng bản thân văn bản tiếng Ả Rập hay tiếng Hàn là spam. Spam Scanner không bao giờ dùng ngôn ngữ làm dấu hiệu, cân nhắc mỗi từ theo số lượng spam và ham của chính ngôn ngữ đó, và giữ trạng thái “không chắc” tỷ lệ với lượng ham ít ỏi mà nó đã thấy trong một ngôn ngữ.

Trong một thử nghiệm trên tin nhắn SMS bằng 21 ngôn ngữ mà mô hình đi kèm chưa từng thấy, cách này đưa số dương tính giả ở tiếng Trung, tiếng Ả Rập, tiếng Hàn, tiếng Nhật, tiếng Hindi, tiếng Bengal, tiếng Urdu, tiếng Thổ Nhĩ Kỳ, tiếng Ukraina và tiếng Thụy Điển về không.


## Bắt spam bằng mọi ngôn ngữ

* **Các phép kiểm tra không đọc từ ngữ:** tên miền giả mạo, liên kết đánh lừa, tệp thực thi, macro, SPF, DKIM, DMARC và danh sách chặn.
* **Mô hình ngôn ngữ** cho các thư không chắc. Các mô hình mở như Qwen 3.5 và Gemma 4 đọc được từ 140 đến 200 ngôn ngữ; các bài kiểm thử đầu cuối kiểm tra spam và ham bằng tiếng Trung, tiếng Ả Rập, tiếng Hàn, tiếng Hindi và tiếng Thái với một mô hình thật.
* **Thư của chính bạn.** Vài trăm thư mỗi loại trong một ngôn ngữ giúp mô hình được huấn luyện trên thư của bạn hoàn toàn tự tin ở ngôn ngữ đó.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Để chỉ chấp nhận một số ngôn ngữ, `--allow-language en,de` cộng điểm cho thư được nhận diện chắc chắn là thuộc bất kỳ ngôn ngữ nào khác.

[Chi tiết về ngôn ngữ](../../docs/languages.md)
