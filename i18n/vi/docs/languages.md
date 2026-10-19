<!-- source: 5d22e36f3f16 -->

# Ngôn ngữ

Spam đến bằng mọi ngôn ngữ, và thư bình thường cũng vậy. Spam Scanner đọc cả hai, và nó thận trọng với những ngôn ngữ nó ít biết: một bộ lọc spam đánh dấu mọi thư tiếng Ả Rập hay tiếng Trung còn tệ hơn không có bộ lọc nào.


## Đọc mọi hệ chữ viết

* **Từ.** Văn bản được tách bằng `Intl.Segmenter`, công cụ tuân theo quy tắc ranh giới từ của Unicode và dùng từ điển cho tiếng Trung, tiếng Nhật, tiếng Thái, tiếng Lào, tiếng Khmer và tiếng Miến Điện, những hệ chữ viết không có khoảng trắng. Văn bản dài được chia thành từng đoạn trước, vì bộ tách từ trong Node.js 18 chậm lại với các chuỗi rất dài.
* **Chuẩn hóa.** Unicode NFKC biến chữ cái toàn độ rộng và hầu hết chữ cái cách điệu (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) thành chữ thường gặp. Văn bản được chuyển thành chữ thường theo quy tắc Unicode.
* **Ngụy trang.** Ký tự vô hình bên trong từ (`free` với một khoảng trắng độ rộng bằng không giữa hai chữ cái, hoặc `v1agra` với các ký tự đó quanh số 1) bị xóa và được đếm, nhưng điều này không áp dụng cho các ký tự nằm giữa các chữ số, thứ người gửi chèn vào các con số để điện thoại không biến chúng thành liên kết, cũng như khoảng trắng độ rộng bằng không giữa các chữ cái tiếng Thái, Lào, Khmer, Miến Điện hoặc Tạng, thứ người viết các chữ viết đó đặt ở chỗ kết thúc một từ. Các ký tự nối (U+200C, U+200D), mà tiếng Ba Tư, các chữ viết Ấn Độ và emoji cần, chỉ được đếm khi nằm giữa các chữ Latin. Dấu gạch nối mềm, cùng các dấu chỉ hướng, ký tự nhúng và ký tự cô lập mà văn bản tiếng Hebrew và tiếng Ả Rập cần, bị xóa mà không được đếm; các ký tự ghi đè hiển thị chữ cái theo thứ tự khác (U+202D, U+202E) được tính trong mọi văn bản. Các từ trộn bảng chữ cái, như `pаypal` với chữ а Kirin, được ánh xạ về bảng chữ cái mà phần lớn chữ cái của chúng thuộc về và được đếm; đuôi cách tiếng Nga sau tên thương hiệu và dấu nháy đơn (`iPhone'ы`) không trộn gì cả. Chữ số dùng thay chữ cái (`v1agra`) được quy đổi. Mỗi kiểu ngụy trang là một đặc trưng riêng, và từ ba ký tự vô hình trở lên, hoặc từ hai từ trộn chữ trở lên, cũng cộng thêm điểm.


## Nhận diện ngôn ngữ

Ngôn ngữ của mỗi thư được nhận diện từ hệ chữ viết và, với các hệ chữ viết được nhiều ngôn ngữ dùng chung, từ các chữ cái:

* Hangul là tiếng Hàn; Hiragana và Katakana nghĩa là tiếng Nhật; chữ Thái, Hy Lạp, Do Thái, Armenia, Gruzia, Bengal, Tamil và các hệ chữ viết khác chỉ một ngôn ngữ sử dụng thì trực tiếp xác định ngôn ngữ đó.
* Các chữ Kirin chỉ có trong một ngôn ngữ giúp phân biệt tiếng Ukraina (і, ї, є, ґ), tiếng Belarus (ў), tiếng Serbia (ђ, ћ, џ), tiếng Macedonia (ѓ, ќ, ѕ) và tiếng Nga (ы, э, ё) trong các từ không phải là tên (các từ viết hoa chữ cái đầu ở vị trí khác ngoài đầu câu hoặc đầu dòng, không phải các từ viết hoa toàn bộ, mà chữ cái của chúng chỉ được tính trong một văn bản quá ngắn đối với bộ phát hiện thống kê: một văn bản tiếng Bulgaria có nhắc đến "господин Рыскулов" là tiếng Bulgaria), trừ khi văn bản còn có chữ cái của tiếng Kazakh, Uzbek, Kyrgyz, Tajik, Tatar, Bashkir hoặc Mông Cổ (ә, ө, ү, ұ, қ, ғ, ң, һ, ҳ, ҷ và các chữ khác), những bảng chữ cái có chung một số chữ cái đó: khi ấy bộ phát hiện thống kê sẽ quyết định, và khi nó trả lời là một ngôn ngữ Slav (một văn bản tiếng Nga hoặc tiếng Bulgaria có một tên hoặc từ tiếng Kazakh trong đó), các từ không có những chữ cái đó, ngoài tên, sẽ quyết định như trên.
* Văn bản bằng các hệ chữ viết được nhiều ngôn ngữ dùng chung (Latin, Kirin, Ả Rập, Devanagari và các hệ khác), khi đủ dài để đánh giá, được chuyển cho [franc](https://github.com/wooorm/franc), giới hạn ở các ngôn ngữ phổ biến trong email để thư ngắn không bị gán nhãn là ngôn ngữ hiếm.

Ngôn ngữ được báo cáo qua `result.language`, và `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) cộng 3 điểm cho thư được nhận diện chắc chắn là thuộc bất kỳ ngôn ngữ nào khác.


## Ngôn ngữ mà mô hình ít biết

Bộ phân loại học từ các ví dụ. Các bộ dữ liệu spam công khai chứa nhiều spam tiếng nước ngoài hơn hẳn thư hợp lệ (ham) tiếng nước ngoài, nên một bộ phân loại ngây thơ sẽ học rằng bản thân văn bản tiếng Trung hay tiếng Ả Rập nghĩa là spam. Spam Scanner hiệu chỉnh điều này theo ba cách:

1. **Ngôn ngữ không bao giờ là bằng chứng.** Ngôn ngữ và hệ chữ viết được nhận diện không được dùng làm dấu hiệu.
2. **Từ được cân nhắc trong phạm vi ngôn ngữ của nó.** Xác suất spam của một từ được tính dựa trên số thư spam và ham mà bộ phân loại đã thấy trong ngôn ngữ của thư, không phải trong mọi ngôn ngữ. Một từ thông dụng tiếng Bồ Đào Nha trong một mô hình chủ yếu thấy spam tiếng Bồ Đào Nha vẫn giữ trung tính.
3. **Độ tin cậy theo độ bao phủ.** Kết quả bị kéo về phía “không chắc” tỷ lệ với số thư mỗi loại mà bộ phân loại đã thấy trong ngôn ngữ đó: để hoàn toàn tin cậy cần 1.000 thư mỗi loại (hoặc 2% của lớp nhỏ hơn, với các mô hình cá nhân nhỏ). Ngôn ngữ không có ham trong dữ liệu huấn luyện luôn nhận kết quả “không chắc”.

Mô hình đi kèm chưa từng thấy [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), tập tin nhắn SMS được dịch máy sang 21 ngôn ngữ. Trước khi có các quy tắc này, nó đánh dấu 5,7% số ham đó là spam, gồm 55% ham tiếng Bồ Đào Nha và 41% ham tiếng Pháp. Với các quy tắc này, con số là 0,18%: không thư nào ở tiếng Trung, tiếng Ả Rập, tiếng Hàn, tiếng Nhật, tiếng Hindi, tiếng Bồ Đào Nha, tiếng Pháp hay 13 ngôn ngữ khác, và 0,27% ở tiếng Anh.


## Bắt spam trong các ngôn ngữ đó

“Không chắc” thì an toàn, nhưng không bắt được spam. Có ba thứ làm được điều đó:

* **Các phép kiểm tra khác** không phụ thuộc vào ngôn ngữ: tên miền giả mạo, liên kết lừa đảo, tệp thực thi, macro, xác thực, danh sách chặn, các quy tắc.
* **Mô hình ngôn ngữ.** Các mô hình mở hiện đại đọc được từ 100 đến 200 ngôn ngữ, và Spam Scanner hỏi một mô hình mỗi khi bộ phân loại không chắc. Các bài kiểm thử đầu cuối kiểm tra rằng `qwen3.5:4b` bắt được spam và cho ham đi qua bằng tiếng Trung, tiếng Ả Rập, tiếng Hàn, tiếng Hindi và tiếng Thái. [Mô hình ngôn ngữ](llm.md)
* **Huấn luyện trên thư của bạn.** Trong một mô hình được huấn luyện trên thư của chính bạn, vài trăm thư mỗi loại trong một ngôn ngữ giúp bộ phân loại hoàn toàn tin cậy ở ngôn ngữ đó. [Huấn luyện](training.md), và [một bộ dữ liệu tùy chọn](training.md#more-languages) bổ sung 21 ngôn ngữ.
