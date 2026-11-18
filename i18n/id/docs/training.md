<!-- source: 6f344039ec5d -->

# Pelatihan

Model bawaan langsung dapat digunakan. Model yang dilatih dengan email Anda sendiri bekerja lebih baik, karena model itu mempelajari seperti apa ham Anda: newsletter Anda, gaya tulisan rekan kerja Anda, bahasa yang Anda terima.


## Latih model

Arahkan `train` ke folder spam dan ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Sumber dapat berupa:

* file **mbox**, juga yang dikompresi gzip (`.mbox.gz`; file `.gz` lainnya dilewati),
* sebuah **Maildir** (folder `cur` dan `new` dibaca, `tmp` dilewati),
* sebuah **folder** berisi file `.eml`, dibaca secara rekursif,
* sebuah **dataset**: file CSV atau JSON Lines dengan kolom teks dan kolom label (`--dataset`). Kolom, atau bidang JSON, bernama `text`, `message`, `body`, `email text`, `email`, `content`, `sms`, atau `v2`, dan `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1`, atau `labels`, dalam huruf besar maupun kecil, dikenali secara otomatis (dalam JSON Lines, `label_text` sebelum `label`); jika tidak, gunakan `--text-column` dan `--label-column`. Baris JSON yang bukan objek dilewati. Label seperti `spam`, `1`, `phishing` dan `ham`, `0`, `not_spam`, `legitimate` dapat dipahami.

Pesan duplikat dihitung sekali. Pesan yang ada di sumber spam sekaligus sumber ham disimpan sebagai spam, karena sumber spam dibaca lebih dulu. Untuk membangun di atas model bawaan alih-alih mulai dari kosong, tambahkan `--merge`.

Gunakan model:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Berapa banyak email yang cukup: beberapa ratus pesan dari setiap jenis menghasilkan model yang berguna, beberapa ribu menghasilkan model yang baik. Jaga keduanya kurang lebih seimbang, dan masukkan email yang tidak ingin Anda saring (reset kata sandi, tagihan dari pemasok Anda sendiri) ke dalam ham.


## Ukur hasilnya

Sisihkan sebagian email dari pelatihan dan ukur hasilnya pada email tersebut:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Model bawaan pada pesan SMS dalam 21 bahasa yang belum pernah dilihatnya, sebagian besar dalam bahasa yang hampir tidak dikenalnya:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Presisi adalah seberapa banyak dari yang disebut spam memang spam; recall, seberapa banyak spam yang tertangkap. Di sini pesan yang ragu dihitung sebagai spam yang terlewat, meskipun dalam pemindaian pemeriksaan lain dan model bahasa masih dapat menangkapnya. Angka yang perlu diperhatikan adalah positif palsu: ham yang ditandai sebagai spam. Dalam hasil di atas, model ragu terhadap sebagian besar pesan ini alih-alih salah menilainya, dan itulah perilaku yang diharapkan untuk bahasa yang jarang muncul dalam emailnya.

`--json` memberikan angka yang sama untuk skrip.


## Belajar dari laporan

Ketika pengguna memindahkan email ke dalam atau keluar dari folder Junk, ajari model satu pesan demi satu pesan:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

`learn` yang pertama membuat file dari model bawaan. Melalui HTTP, `POST /learn/spam` dan `/learn/ham` pada [HTTP API](http-api.md) melakukan hal yang sama, dan `spamc -L spam` berfungsi terhadap [server spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) dengan `--allow-tell`. [IMAPSieve milik Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) dapat memanggil salah satunya ketika sebuah pesan dipindahkan.

Dari Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Pesan yang dilaporkan salah klasifikasi sebaiknya dihapus pembelajarannya dari kelas yang salah sebelum dipelajari di kelas yang benar, jika sebelumnya sudah pernah dipelajari.


## Model bawaan

`model/classifier.json` dibangun oleh `npm run model:train` dari dataset publik berikut di Hugging Face, semuanya berlisensi terbuka:

| Dataset                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Lisensi                    | Isi                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | Pesan dan email dalam 43 bahasa                                           |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Korpus riset publik        | Korpus Enron-Spam                                                         |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | Pesan Telegram berbahasa Rusia                                            |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Pesan sintetis                                                            |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Milis, buletin, spam, phishing, dan email penipuan                        |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Pesan dalam 14 bahasa India                                               |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | Email berbahasa Indonesia menurut kategori                                |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | Surat sebuah perusahaan dalam bahasa Spanyol                              |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | Surat biasa: tagihan, pemesanan, buletin, promosi, dan pemberitahuan akun |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Apa yang orang minta kepada asisten, dalam 20 bahasa                      |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                  | Surat sebuah perusahaan rekaan dalam bahasa Prancis                       |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Bersama proyek ini         | Surat sehari-hari dan penipuan dalam 23 bahasa, ditulis untuk proyek ini  |

Ham mencakup surat bisnis dan toko yang biasa (faktur, pemberitahuan pesanan dan akun, buletin, promosi), sehingga surat seperti itu saja tidak terbaca sebagai spam.

Pesan pentalan (bounce) dalam dataset tidak diikutkan: pesan itu hanya ada di antara spam, sehingga akan mengajari pengklasifikasi bahwa setiap pesan pentalan adalah spam.

Tiga baris terakhir adalah teks biasa dalam bahasa-bahasa yang di dataset lain kebanyakan berupa spam (Prancis, Portugis, Belanda, bahasa-bahasa Nordik, Polandia, Turki, Arab, Jepang, Korea, Mandarin, dan lainnya), yang tanpa itu setiap kata biasa akan terbaca sebagai spam. Dari 10.000 teks biasa dalam 20 bahasa yang tidak dipakai melatih model, 1,4% mendapat probabilitas 80% atau lebih (4,8% tanpa baris-baris ini) dan 0,1% mendapat 99% atau lebih. Teks ini bukan surat sungguhan, dan penipuan yang ditulis untuk tiap bahasa hanya sedikit: pengklasifikasi menjadi lebih yakin akan surat biasa dalam bahasa-bahasa ini, dan hanya menangkap sedikit lebih banyak spamnya.

Model ini belajar dari 81.254 pesan spam dan 133.317 pesan ham. Skripnya menyisihkan setiap pesan kesepuluh, melatih dengan sisanya, dan mengukur pengklasifikasi saja, tanpa pemeriksaan lain:

| Tes yang disisihkan |  Pesan | Presisi | Recall | Positif palsu |  Ragu |
| ------------------- | -----: | ------: | -----: | ------------: | ----: |
| Inggris             |  8.481 |  100,0% |  96,3% |          0,0% |  2,6% |
| Rusia               |  1.680 |  100,0% |  97,4% |          0,0% |  2,2% |
| Italia              |  1.392 |   99,0% |  81,0% |          0,9% | 12,6% |
| Jerman              |  1.314 |   97,9% |  71,4% |          1,9% | 22,3% |
| Spanyol             |  2.088 |   98,7% |  53,3% |          0,4% | 16,2% |
| Enron-Spam          |  2.870 |  100,0% |  95,2% |          0,0% |  2,6% |
| all-scam-spam       |  4.222 |   99,9% |  92,2% |          0,0% |  9,1% |
| Semua               | 21.329 |   99,6% |  76,6% |          0,2% | 14,2% |

Spam di sini berarti probabilitas pengklasifikasi 99% atau lebih, titik saat pengklasifikasi seorang diri mencapai ambang spam. Dalam pemindaian, spam yang kurang diyakininya tetap mendapat poin, dan pemeriksaan lain menambahkan poinnya masing-masing.

Hasil bahasa Jerman, Spanyol, dan Italia berasal dari dataset sintetis, yang berisi pesan yang nyaris identik dengan label spam sekaligus ham: sebagian kesalahan itu ada pada labelnya, bukan pada model. Email dalam bahasa Anda sendiri adalah solusi terbaik. Angka-angkanya, untuk setiap bahasa dan dataset, ada di `metadata.metrics` milik model.

### Bahasa lainnya

`npm run model:train -- --with multilingual-sms` menambahkan [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection yang diterjemahkan mesin ke 21 bahasa. Dataset ini tidak dimasukkan ke model bawaan karena kartunya mencantumkan lisensi GPL; periksa apakah lisensi itu sesuai dengan cara Anda membagikan model. Jika dilatih dengannya, hasil tes yang disisihkan untuk bahasa yang hampir tidak dikenal model bawaan adalah:

| Bahasa   | Pesan | Presisi | Recall | Positif palsu |
| -------- | ----: | ------: | -----: | ------------: |
| Tionghoa |   432 |  100,0% |  86,1% |          0,0% |
| Arab     |   432 |  100,0% |  83,1% |          0,0% |
| Korea    |   412 |  100,0% |  78,3% |          0,0% |
| Jepang   |   486 |   96,1% |  87,5% |          0,5% |
| Hindi    |   494 |  100,0% |  76,2% |          0,0% |
| Prancis  |   511 |   98,7% |  88,6% |          0,6% |
| Turki    |   222 |  100,0% |  70,4% |          0,0% |

### Latih ulang

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## File model

Model adalah file JSON: jumlah pesan spam dan ham yang dipelajari, dan untuk setiap fitur yang di-hash, berapa banyak pesan spam dan ham yang memuatnya, diurutkan dan dikodekan dengan base64. File ini tidak berisi kata maupun teks pesan. `--max-features` hanya menyimpan fitur yang paling sering muncul dan `--min-count` membuang fitur yang jarang, dengan mengorbankan akurasi demi ukuran; model bawaan menyimpan 400.000 fitur dalam sekitar 6 MB.

Model dari Spam Scanner 6 dan sebelumnya tidak dapat dimuat: model tersebut meng-hash fitur yang berbeda. Latih model baru dari email yang sama.
