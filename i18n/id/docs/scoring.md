<!-- source: 6f6b765c5fc1 -->

# Tes dan skor

Sebuah pesan dianggap spam pada 5 poin dan ditolak pada 15. Setiap tes di bawah ini menambahkan atau mengurangi poin; hasilnya mencantumkan tes yang terpicu.

Ubah ambang batas dengan `threshold` dan `rejectThreshold`. Ubah poin dengan `scores`, baik melalui kunci pengaturan (`scores: {deceptiveLink: 4}`) maupun melalui nama tes, yang menetapkan poin tes tersebut (`scores: {FROM_NAME_BRAND: 4}`).


## Pengklasifikasi

| Tes                           | Poin              | Arti                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `BAYES_00` sampai `BAYES_999` | -2,5 sampai +6,25 | Probabilitas spam dari pengklasifikasi, pada skala log-odds: 2,4 poin pada 90%, 5 pada 99%, dan 6,25 pada 99,9%, sehingga pengklasifikasi hanya menandai spam seorang diri jika keyakinannya minimal 99%. Namanya menunjukkan rentangnya: `BAYES_999` berarti 99,9% atau lebih, `BAYES_99` 99% sampai 99,9%, `BAYES_50` 40% sampai 60%. Kunci pengaturan `bayesHam` dan `bayesSpam` mengatur kedua ujungnya. |


## Phishing dan tautan

| Tes                         | Poin | Kunci pengaturan    | Arti                                                                     |
| --------------------------- | ---: | ------------------- | ------------------------------------------------------------------------ |
| `PHISHING_LOOKALIKE_DOMAIN` |    5 | `homograph`         | Domain tautan meniru suatu merek dengan karakter yang mirip atau ditukar |
| `MIXED_SCRIPT_DOMAIN`       |    3 | `mixedScriptDomain` | Label domain mencampur alfabet                                           |
| `BRAND_IN_DOMAIN`           |  1,5 | `brandInDomain`     | Nama merek di dalam domain milik pihak lain                              |
| `TYPO_DOMAIN`               |    1 | `typoDomain`        | Selisih satu huruf dari domain suatu merek                               |
| `DECEPTIVE_LINK`            |    3 | `deceptiveLink`     | Tautan menampilkan satu alamat dan menuju alamat lain                    |
| `MALICIOUS_DOMAIN`          |    6 | `maliciousDomain`   | Resolver malware Cloudflare memblokir domain yang ditautkan              |
| `ADULT_DOMAIN`              |    2 | `adultDomain`       | Resolver keluarga Cloudflare memblokir domain yang ditautkan             |
| `URIBL_<LIST>`              |    5 | `uriblListed`       | Domain yang ditautkan ada di daftar blokir domain, misalnya `URIBL_DBL`  |


## Lampiran

| Tes                     |     Poin | Kunci pengaturan                         | Arti                                                      |
| ----------------------- | -------: | ---------------------------------------- | --------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |       10 | `executable`                             | Program atau skrip                                        |
| `DISGUISED_EXECUTABLE`  |       12 | `disguisedExecutable`                    | Program yang dinamai seperti dokumen atau gambar          |
| `DOUBLE_EXTENSION`      |        6 | `doubleExtension`                        | Nama seperti `invoice.pdf.exe`                            |
| `RTL_OVERRIDE_FILENAME` |        6 | `rtlOverride`                            | Right-to-left override menyembunyikan ekstensi sebenarnya |
| `EXECUTABLE_IN_ARCHIVE` |        8 | `executableInArchive`                    | Program di dalam file ZIP                                 |
| `ENCRYPTED_ARCHIVE`     |        2 | `encryptedArchive`                       | Arsip yang tidak dapat dibuka pemindai                    |
| `MACRO_ATTACHMENT`      |        4 | `macro`                                  | File Office dengan makro                                  |
| `PDF_ACTIVE_CONTENT`    |        3 | `pdfActive`                              | PDF dengan JavaScript, aksi launch, atau file tertanam    |
| `RTF_EMBEDDED_OBJECT`   |        4 | `rtfObject`                              | File RTF dengan objek tertanam                            |
| `HTML_ATTACHMENT`       | 1 atau 3 | `htmlAttachment`, `activeHtmlAttachment` | File HTML; 3 jika memuat skrip atau formulir              |
| `VIRUS`                 |      100 | `virus`                                  | ClamAV menemukan virus                                    |


## Aturan

| Tes                       | Poin | Arti                                                                                                |
| ------------------------- | ---: | --------------------------------------------------------------------------------------------------- |
| `GTUBE`                   | 1000 | String tes GTUBE                                                                                    |
| `SEXTORTION_SUBJECT`      |    6 | Subjek yang dipakai penipuan sekstorsi dan pengambilalihan akun                                     |
| `PAYPAL_INVOICE`          |    6 | Tagihan atau permintaan uang PayPal, saluran yang disalahgunakan untuk penipuan                     |
| `MICROSOFT_SPAM_VERDICT`  |    5 | Microsoft menandai pesan sebagai spam sebelum meneruskannya (hanya dipercaya dari server Microsoft) |
| `MICROSOFT_HIGH_SCL`      |    3 | Microsoft memberinya tingkat keyakinan spam yang tinggi (sama seperti di atas)                      |
| `PROMPT_INJECTION`        |    3 | Teks yang ditujukan kepada filter AI                                                                |
| `SELF_SPOOF`              |    3 | Mengaku berasal dari domain penerima sendiri dan tidak terautentikasi                               |
| `FROM_NAME_OTHER_ADDRESS` |  2,5 | Nama tampilan memuat alamat email yang berbeda                                                      |
| `FROM_NAME_BRAND`         |    2 | Nama tampilan mengaku sebagai merek yang bukan pemilik alamat tersebut                              |
| `DATE_IN_FUTURE`          |    1 | Bertanggal lebih dari satu hari ke depan                                                            |
| `MISSING_DATE`            |  0,5 | Tidak ada header Date                                                                               |
| `MISSING_MESSAGE_ID`      |  0,5 | Tidak ada header Message-ID                                                                         |

Aturan yang bernilai setidaknya sebesar ambang spam juga muncul di `results.arbitrary`, seperti pada versi sebelumnya.


## Obfuskasi dan bahasa

| Tes                    | Poin | Kunci pengaturan      | Arti                                                             |
| ---------------------- | ---: | --------------------- | ---------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |    2 | `invisibleCharacters` | Tiga atau lebih karakter tak terlihat di dalam teks              |
| `MIXED_SCRIPT_WORDS`   |  2,5 | `mixedScriptWords`    | Dua atau lebih kata mencampur huruf dari alfabet berbeda         |
| `STYLED_LETTERS`       |  1,5 | `styledLetters`       | Huruf matematis atau berbingkai yang menyamar sebagai teks biasa |
| `LANGUAGE_NOT_ALLOWED` |    3 | `languageNotAllowed`  | Tidak ada di `allowedLanguages`                                  |


## Autentikasi

Memerlukan alamat IP klien dan `authentication: true`.

| Tes            | Poin | Kunci pengaturan (di `authentication.weights`) |
| -------------- | ---: | ---------------------------------------------- |
| `SPF_PASS`     | -0,5 | `spfPass`                                      |
| `SPF_FAIL`     |    2 | `spfFail`                                      |
| `SPF_SOFTFAIL` |    1 | `spfSoftfail`                                  |
| `DKIM_PASS`    | -0,5 | `dkimPass`                                     |
| `DKIM_FAIL`    |    1 | `dkimFail`                                     |
| `DMARC_PASS`   | -1,5 | `dmarcPass`                                    |
| `DMARC_FAIL`   |  3,5 | `dmarcFail`                                    |
| `ARC_PASS`     | -0,5 | `arcPass`                                      |
| `ARC_FAIL`     |    1 | `arcFail`                                      |


## Reputasi dan daftar blokir

| Tes            | Poin | Kunci pengaturan | Arti                                                        |
| -------------- | ---: | ---------------- | ----------------------------------------------------------- |
| `DENYLISTED`   |  100 | `denylisted`     | Alamat IP, domain, atau alamat pengirim ada di daftar tolak |
| `ALLOWLISTED`  |  -20 | `allowlisted`    | Ada di daftar izin                                          |
| `TRUTH_SOURCE` |   -5 | `truthSource`    | Layanan reputasi menandai pengirim sebagai tepercaya        |
| `RBL_<LIST>`   |    4 | `rblListed`      | Alamat IP klien ada di daftar blokir, misalnya `RBL_ZEN`    |


## Model bahasa dan model opsional

| Tes                                                   | Poin      | Kunci pengaturan | Arti                                                   |
| ----------------------------------------------------- | --------- | ---------------- | ------------------------------------------------------ |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | hingga +6 | `llmSpam`        | Vonis model, dikalikan tingkat keyakinannya            |
| `LLM_HAM`                                             | hingga -3 | `llmHam`         | Sama seperti di atas                                   |
| `TOXIC_CONTENT`                                       | 3         | `toxicity`       | Model toksisitas yang Anda sediakan menandai teks      |
| `NSFW_IMAGE`                                          | 3         | `nsfw`           | Model gambar yang Anda sediakan menandai sebuah gambar |
