<!-- source: 9537a0e62eb0 -->

# Bahasa

Spam datang dalam setiap bahasa, begitu pula email biasa. Spam Scanner membaca keduanya, dan berhati-hati dengan bahasa yang kurang dikenalnya: filter spam yang menandai setiap pesan berbahasa Arab atau Tionghoa lebih buruk daripada tidak ada filter sama sekali.


## Membaca setiap aksara

* **Kata.** Teks dipecah dengan `Intl.Segmenter`, yang mengikuti aturan batas kata Unicode dan memakai kamus untuk bahasa Tionghoa, Jepang, Thai, Laos, Khmer, dan Burma, aksara yang ditulis tanpa spasi. Teks panjang dipecah menjadi beberapa bagian terlebih dahulu, karena segmenter di Node.js 18 melambat pada string yang sangat panjang.
* **Normalisasi.** Unicode NFKC mengubah huruf lebar penuh dan sebagian besar huruf bergaya (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) menjadi huruf biasa. Teks diubah ke huruf kecil dengan aturan Unicode.
* **Penyamaran.** Karakter tak terlihat di dalam kata (`free` dengan spasi lebar nol di antara dua huruf, tanda hubung lunak) dihapus dan dihitung. Kata yang mencampur alfabet, seperti `pаypal` dengan а Sirilik, dipetakan kembali ke satu alfabet dan dihitung. Angka yang dipakai sebagai huruf (`v1agra`) diseragamkan. Setiap penyamaran adalah fitur tersendiri, dan tiga atau lebih karakter tak terlihat, atau dua atau lebih kata campuran, juga menambahkan poin.


## Mendeteksi bahasa

Bahasa setiap pesan dideteksi dari aksaranya dan, untuk aksara yang dipakai banyak bahasa, dari hurufnya:

* Hangul berarti bahasa Korea; Hiragana dan Katakana berarti bahasa Jepang; Thai, Yunani, Ibrani, Armenia, Georgia, Bengali, Tamil, dan aksara lain yang dipakai oleh satu bahasa langsung menunjukkan bahasanya.
* Huruf Sirilik yang hanya ada dalam satu bahasa menentukan pilihan antara bahasa Ukraina (і, ї, є, ґ), Belarus (ў), Serbia (ђ, ћ, џ), Makedonia (ѓ, ќ, ѕ), dan Rusia (ы, э, ё).
* Teks dalam aksara yang dipakai beberapa bahasa (Latin, Sirilik, Arab, Dewanagari, dan lainnya), jika cukup panjang untuk dinilai, diteruskan ke [franc](https://github.com/wooorm/franc), dibatasi pada bahasa yang umum dalam email agar pesan pendek tidak diberi label bahasa yang langka.

Bahasa dilaporkan sebagai `result.language`, dan `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) menambahkan 3 poin pada email yang terdeteksi dengan yakin dalam bahasa lain.


## Bahasa yang kurang dikenal model

Pengklasifikasi belajar dari contoh. Dataset spam publik berisi jauh lebih banyak spam berbahasa asing daripada ham berbahasa asing, sehingga pengklasifikasi yang naif belajar bahwa teks bahasa Tionghoa atau Arab itu sendiri berarti spam. Spam Scanner mengoreksi hal ini dengan tiga cara:

1. **Bahasa tidak pernah menjadi bukti.** Bahasa dan aksara yang terdeteksi tidak digunakan sebagai petunjuk.
2. **Kata ditimbang dalam bahasanya.** Probabilitas spam sebuah kata dihitung terhadap jumlah pesan spam dan ham yang dilihat pengklasifikasi dalam bahasa pesan tersebut, bukan dalam semua bahasa. Kata sehari-hari bahasa Portugis dalam model yang sebagian besar melihat spam berbahasa Portugis tetap netral.
3. **Keyakinan mengikuti cakupan.** Hasil ditarik ke arah "ragu" sebanding dengan berapa banyak pesan dari setiap jenis yang dilihat pengklasifikasi dalam bahasa itu: keyakinan penuh memerlukan 1.000 pesan dari masing-masing jenis (atau 2% dari kelas yang lebih kecil, untuk model pribadi yang kecil). Bahasa tanpa ham dalam data latih selalu mendapat "ragu".

Model bawaan tidak pernah melihat [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), yaitu pesan SMS yang diterjemahkan mesin ke 21 bahasa. Sebelum aturan ini, model menandai 5,7% ham di dalamnya sebagai spam, termasuk 55% ham berbahasa Portugis dan 41% ham berbahasa Prancis. Dengan aturan ini, 0,18%: tidak ada sama sekali dalam bahasa Tionghoa, Arab, Korea, Jepang, Hindi, Portugis, Prancis, atau 20 bahasa lain, dan 0,27% dalam bahasa Inggris.


## Menangkap spam dalam bahasa-bahasa tersebut

Ragu itu aman, tetapi tidak menangkap spam. Tiga hal yang menangkapnya:

* **Pemeriksaan lain** tidak bergantung pada bahasa: domain tiruan, tautan menipu, file executable, makro, autentikasi, daftar blokir, aturan.
* **Model bahasa.** Model terbuka modern membaca 100 hingga 200 bahasa, dan Spam Scanner bertanya kepada model setiap kali pengklasifikasi ragu. Tes end-to-end memeriksa bahwa `qwen3.5:4b` menangkap spam dan meloloskan ham dalam bahasa Tionghoa, Arab, Korea, Hindi, dan Thai. [Model bahasa](llm.md)
* **Pelatihan dengan email Anda.** Dalam model yang dilatih dengan email Anda sendiri, beberapa ratus pesan dari setiap jenis dalam suatu bahasa memberi pengklasifikasi keyakinan penuh dalam bahasa tersebut. [Pelatihan](training.md), dan [dataset opsional](training.md#more-languages) yang menambahkan 21 bahasa.
