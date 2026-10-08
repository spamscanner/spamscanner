<!-- source: 7cc30ff4ad91 -->

# Pelatihan

Model bawaan langsung dapat digunakan. Model yang dilatih dengan email Anda sendiri bekerja lebih baik, karena model itu mempelajari seperti apa ham Anda: newsletter Anda, gaya tulisan rekan kerja Anda, bahasa yang Anda terima.


## Latih model

Arahkan `train` ke folder spam dan ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Sumber dapat berupa:

* file **mbox**, juga yang dikompresi gzip (`.mbox.gz`),
* sebuah **Maildir** (folder `cur` dan `new` dibaca, `tmp` dilewati),
* sebuah **folder** berisi file `.eml`, dibaca secara rekursif,
* sebuah **dataset**: file CSV atau JSON Lines dengan kolom teks dan kolom label (`--dataset`). Kolom bernama `text`, `message`, `body`, `email`, atau `content`, dan `label`, `category`, `class`, `spam`, atau `is_spam` dikenali secara otomatis; jika tidak, gunakan `--text-column` dan `--label-column`. Label seperti `spam`, `1`, `phishing` dan `ham`, `0`, `not_spam`, `legitimate` dapat dipahami.

Pesan duplikat dihitung sekali. Untuk membangun di atas model bawaan alih-alih mulai dari kosong, tambahkan `--merge`.

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
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
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

| Dataset                                                                                                                                                                                                                                                                                                                    | Lisensi             | Isi                             |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0          | Pesan dan email dalam 43 bahasa |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Korpus riset publik | Korpus Enron-Spam               |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0             | Pesan Telegram berbahasa Rusia  |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                 | Pesan sintetis                  |

Model ini belajar dari 62.480 pesan spam dan 76.489 pesan ham. Skripnya menyisihkan setiap pesan kesepuluh, melatih dengan sisanya, dan mengukur pengklasifikasi saja, tanpa pemeriksaan lain:

| Tes yang disisihkan |  Pesan | Presisi | Recall | Positif palsu |  Ragu |
| ------------------- | -----: | ------: | -----: | ------------: | ----: |
| Inggris             |  6.564 |  100,0% |  97,0% |          0,0% |  2,4% |
| Rusia               |  1.682 |  100,0% |  97,4% |          0,0% |  2,2% |
| Italia              |  1.389 |   98,1% |  85,3% |          1,8% | 10,9% |
| Jerman              |  1.309 |   97,7% |  76,1% |          2,2% | 20,7% |
| Spanyol             |  1.281 |   97,5% |  82,5% |          2,6% | 16,8% |
| Enron-Spam          |  2.888 |  100,0% |  93,1% |          0,0% |  4,5% |
| all-scam-spam       |  4.236 |  100,0% |  88,8% |          0,0% | 11,2% |
| Semua               | 13.840 |   99,2% |  85,1% |          0,5% | 12,4% |

Spam di sini berarti probabilitas pengklasifikasi 99% atau lebih, titik saat pengklasifikasi seorang diri mencapai ambang spam. Dalam pemindaian, spam yang kurang diyakininya tetap mendapat poin, dan pemeriksaan lain menambahkan poinnya masing-masing.

Hasil bahasa Jerman, Spanyol, dan Italia berasal dari dataset sintetis, yang berisi pesan yang nyaris identik dengan label spam sekaligus ham: sebagian kesalahan itu ada pada labelnya, bukan pada model. Email dalam bahasa Anda sendiri adalah solusi terbaik. Angka-angkanya, untuk setiap bahasa dan dataset, ada di `metadata.metrics` milik model.

### Bahasa lainnya

`npm run model:train -- --with multilingual-sms` menambahkan [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection yang diterjemahkan mesin ke 21 bahasa. Dataset ini tidak dimasukkan ke model bawaan karena kartunya mencantumkan lisensi GPL; periksa apakah lisensi itu sesuai dengan cara Anda membagikan model. Jika dilatih dengannya, hasil tes yang disisihkan untuk bahasa yang hampir tidak dikenal model bawaan adalah:

| Bahasa   | Pesan | Presisi | Recall | Positif palsu |
| -------- | ----: | ------: | -----: | ------------: |
| Tionghoa |   430 |  100,0% |  82,3% |          0,0% |
| Arab     |   430 |  100,0% |  84,6% |          0,0% |
| Korea    |   412 |  100,0% |  80,4% |          0,0% |
| Jepang   |   486 |   96,0% |  85,7% |          0,5% |
| Hindi    |   412 |  100,0% |  63,9% |          0,0% |
| Prancis  |   480 |   98,6% |  94,2% |          0,6% |
| Turki    |   220 |  100,0% |  73,1% |          0,0% |

### Latih ulang

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## File model

Model adalah file JSON: jumlah pesan spam dan ham yang dipelajari, dan untuk setiap fitur yang di-hash, berapa banyak pesan spam dan ham yang memuatnya, diurutkan dan dikodekan dengan base64. File ini tidak berisi kata maupun teks pesan. `--max-features` hanya menyimpan fitur yang paling sering muncul dan `--min-count` membuang fitur yang jarang, dengan mengorbankan akurasi demi ukuran; model bawaan menyimpan 400.000 fitur dalam sekitar 6 MB.

Model dari Spam Scanner 6 dan sebelumnya tidak dapat dimuat: model tersebut meng-hash fitur yang berbeda. Latih model baru dari email yang sama.
