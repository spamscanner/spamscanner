<!-- source: 361732724f0e -->

<!--
label: FAQ
title: Pertanyaan yang sering diajukan
description: Jawaban tentang Spam Scanner: seberapa akurat, bahasa apa yang didukung, apa yang dikirim lewat jaringan, model bahasa, SpamAssassin, dan Forward Email.
keywords: FAQ Spam Scanner, pertanyaan filter spam, akurasi filter spam, privasi filter spam
-->

# Pertanyaan yang sering diajukan


## Apa itu Spam Scanner?

Filter spam untuk Node.js, baris perintah, dan server email. Spam Scanner membaca pesan email mentah dan memutuskan apakah pesan itu spam, phishing, penipuan, atau membawa malware, disertai skor dan daftar tes yang menentukannya. Spam Scanner berjalan sebagai pustaka, milter untuk Postfix dan Sendmail, server spamd yang kompatibel dengan SpamAssassin, content filter Postfix, HTTP API, atau server TCP.


## Apakah gratis?

[Lisensinya](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), Business Source License 1.1, mengizinkan penggunaan apa pun kecuali menawarkan deteksi spam sebagai layanan kepada pihak lain, dan menyebutkan tanggal lisensi berubah menjadi Apache License 2.0.


## Seberapa akurat?

Pada pesan bahasa Inggris yang disisihkan dari data latihnya, pengklasifikasi bawaan saja tidak menandai satu pun ham sebagai spam dan menangkap 97% spam; angka lengkap per bahasa ada di [panduan pelatihan](../../docs/training.md#the-bundled-model). Tautan, lampiran, autentikasi, daftar blokir, dan model bahasa menambah hasil itu. Email Anda sendiri adalah ujian sesungguhnya: `spamscanner eval` mengukur model apa pun pada email berlabel apa pun.


## Bahasa apa yang didukung?

Semuanya. Kata-kata disegmentasi dengan aturan Unicode, termasuk bahasa Tionghoa, Jepang, dan Thai, yang tidak memakai spasi. Untuk bahasa yang jarang dilihat model bawaan, model tetap ragu alih-alih menandainya, dan keputusan diserahkan ke model bahasa atau pelatihan Anda sendiri. [Bahasa](../../docs/languages.md)


## Apakah email saya dikirim ke suatu tempat?

Tidak. Secara bawaan, nama host dari tautan dicari di resolver DNS penyaring milik Cloudflare, dan tidak ada hal lain yang keluar dari mesin. Autentikasi, daftar blokir, model bahasa, dan layanan reputasi nonaktif sampai dikonfigurasi, dan data pribadi dihapus sebelum email dikirim ke model bahasa yang di-hosting. [Keamanan dan privasi](../../docs/security.md)


## Apakah saya memerlukan model bahasa?

Tidak. Model bahasa adalah pendapat kedua untuk kasus yang meragukan. Tanpa model, pesan-pesan itu diputuskan hanya berdasarkan skornya.


## Model bahasa mana yang sebaiknya digunakan?

`qwen3.5:4b` melalui Ollama di CPU, atau `qwen3.5:9b` dengan GPU. Keduanya berlisensi Apache dan membaca 201 bahasa. Spam Scanner membaca probabilitas setiap vonis dari satu langkah model; di CPU dua inti, cara ini memakan sekitar 11 detik per pesan, dibandingkan 31 detik untuk jawaban tertulis, dengan akurasi yang sama. Untuk layanan yang di-hosting, model keputusan Cloudflare Clef dan TypeSafe Jev menjawab dalam waktu kurang dari satu detik; Anthropic, OpenAI, Google, dan lainnya juga dapat digunakan. [Pengukuran](../../docs/llm.md#measured) dan [model yang direkomendasikan](../../docs/llm.md#recommended-open-models)


## Dapatkah menggantikan SpamAssassin?

Untuk sebagian besar konfigurasi, ya: Spam Scanner memakai protokol spamd, sehingga spamc, Exim, dan Haraka berfungsi tanpa perubahan, dan menulis header `X-Spam-*` yang sama. Spam Scanner tidak menjalankan file aturan SpamAssassin. [Alternatif SpamAssassin](/spamassassin-alternative/)


## Apakah email yang sah akan ditolak?

Penolakan email nonaktif secara bawaan: milter hanya menandai. Dengan `--reject`, hanya pesan dengan skor 15 atau lebih yang ditolak, dengan galat sementara 451, sehingga pengirim mencoba lagi dan kesalahan dapat diperbaiki dengan mengubah pengaturan. Content filter tidak pernah menolak selama sesi SMTP.


## Bagaimana melatihnya dengan email saya?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, lalu `--model model.json`. File mbox, Maildir, folder berisi file `.eml`, serta dataset CSV atau JSON Lines semuanya dapat digunakan. [Pelatihan](../../docs/training.md)


## Apakah bisa berjalan tanpa Node.js?

Ya: binary mandiri untuk Linux, macOS, dan Windows sudah menyertakan Node.js dan modelnya. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Siapa pembuatnya?

[Forward Email](https://forwardemail.net), untuk server emailnya sendiri.
