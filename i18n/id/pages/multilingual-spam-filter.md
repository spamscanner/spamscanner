<!-- source: 0ad167ddd34e -->

<!--
label: Filter spam multibahasa
title: Filter spam multibahasa: Tionghoa, Arab, Rusia, dan aksara lain
description: Cara Spam Scanner menyaring spam dalam setiap bahasa: segmentasi kata Unicode, membongkar penyamaran, dan tidak menandai bahasa yang kurang dikenal model.
keywords: filter spam multibahasa, filter spam bahasa Tionghoa, filter spam bahasa Arab, filter spam bahasa Rusia, filter spam bahasa Jepang, deteksi spam Unicode, spam homoglif
-->

# Filter spam multibahasa

Banyak filter spam dibuat untuk bahasa Inggris. Spam dalam bahasa lain lolos darinya, dan email biasa dalam bahasa lain ditandai karena aksaranya. Spam Scanner dibuat untuk menghindari keduanya.


## Membaca kata-kata

Kata-kata ditemukan dengan `Intl.Segmenter`, yaitu aturan batas kata Unicode dengan kamus untuk bahasa Tionghoa, Jepang, Thai, Laos, Khmer, dan Burma. Sebuah kalimat Tionghoa menjadi kata-kata seperti 恭喜, 获得, dan 大奖, bukan satu string panjang yang tidak pernah berulang.

Penyamaran dibongkar sebelum dihitung: karakter tak terlihat di dalam kata, huruf Sirilik atau Yunani di dalam kata Latin (`pаypal`), angka sebagai pengganti huruf (`v1agra`), serta huruf matematis atau huruf berbingkai (𝐅𝐑𝐄𝐄). Setiap penyamaran juga menjadi petunjuk tersendiri.


## Tidak menandai yang tidak dikenalnya

Dataset spam publik berisi jauh lebih banyak spam berbahasa asing daripada ham berbahasa asing, sehingga pengklasifikasi yang naif belajar bahwa teks bahasa Arab atau Korea itu sendiri adalah spam. Spam Scanner tidak pernah menggunakan bahasa sebagai petunjuk, menimbang setiap kata terhadap jumlah spam dan ham dalam bahasanya sendiri, dan tetap "ragu" sebanding dengan sedikitnya ham yang pernah dilihatnya dalam suatu bahasa.

Dalam pengujian pada pesan SMS dalam 21 bahasa yang belum pernah dilihat model bawaan, cara ini menurunkan positif palsu dalam bahasa Tionghoa, Arab, Korea, Jepang, Hindi, Bengali, Urdu, Turki, Ukraina, dan Swedia menjadi nol.


## Menangkap spam dalam setiap bahasa

* **Pemeriksaan yang tidak membaca kata:** domain tiruan, tautan menipu, file executable, makro, SPF, DKIM, DMARC, dan daftar blokir.
* **Model bahasa** untuk pesan yang meragukan. Model terbuka seperti Qwen 3.5 dan Gemma 4 membaca 140 hingga 200 bahasa; tes end-to-end memeriksa spam dan ham dalam bahasa Tionghoa, Arab, Korea, Hindi, dan Thai dengan model sungguhan.
* **Email Anda sendiri.** Beberapa ratus pesan dari setiap jenis dalam suatu bahasa memberi model yang dilatih dengan email Anda keyakinan penuh dalam bahasa tersebut.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Untuk hanya menerima bahasa tertentu, `--allow-language en,de` menambahkan poin pada email yang terdeteksi dengan yakin dalam bahasa lain.

[Bahasa secara rinci](../../docs/languages.md)
