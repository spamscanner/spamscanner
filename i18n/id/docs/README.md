<!-- source: 8860e232d858 -->

# Dokumentasi Spam Scanner

Spam Scanner adalah filter spam untuk Node.js dan baris perintah, dengan kode sumber di GitHub. Spam Scanner membaca pesan email mentah dan memutuskan apakah pesan itu spam, phishing, penipuan, atau membawa malware, dalam bahasa apa pun. Spam Scanner berjalan sebagai pustaka, alat baris perintah, milter Postfix atau Sendmail, content filter Postfix, server spamd yang kompatibel dengan SpamAssassin, HTTP API, atau server TCP.

Spam Scanner dibuat oleh [Forward Email](https://forwardemail.net) untuk server emailnya sendiri.


## Cara sebuah pesan dinilai

Setiap pemeriksaan menambahkan atau mengurangi poin. Totalnya menentukan hasil:

| Skor          | Tindakan | Yang dilakukan server email      |
| ------------- | -------- | -------------------------------- |
| Di bawah 5    | `accept` | Mengirimkan pesan                |
| 5 sampai 14,9 | `tag`    | Mengirimkannya dengan tanda spam |
| 15 ke atas    | `reject` | Menolaknya selama sesi SMTP      |

Kedua ambang batas dapat diubah. Setiap hasil mencantumkan tes yang terpicu, dengan poin dan alasannya, sehingga setiap keputusan selalu dapat dijelaskan.

Pemeriksaannya:

* **Pengklasifikasi terlatih** membaca kata-kata pesan dalam aksara apa pun, bentuk tautannya, pengirimnya, dan lampirannya. Pengklasifikasi ini sudah dilatih dengan dataset publik dan belajar dari email Anda sendiri. [Cara kerja pengklasifikasi](how-it-works.md#the-classifier)
* **Pemeriksaan phishing** menangkap domain tiruan (`paypa1.com`, `pаypal.com` dengan а Sirilik), tautan yang teksnya menampilkan satu alamat tetapi tujuannya alamat lain, dan nama tampilan yang mengaku sebagai suatu merek. [Phishing](how-it-works.md#phishing)
* **Pemeriksaan lampiran** menemukan file executable, file executable yang diganti namanya menjadi dokumen, ekstensi ganda, trik nama file kanan-ke-kiri, file executable di dalam file ZIP, makro Office, dan konten PDF aktif. ClamAV dapat memindai lampiran untuk virus. [Lampiran](how-it-works.md#attachments)
* **Autentikasi**: SPF, DKIM, DMARC, dan ARC, ketika alamat IP klien diketahui. [Autentikasi](how-it-works.md#authentication)
* **Daftar blokir DNS** untuk alamat IP klien dan domain dalam tautan, serta resolver penyaring Cloudflare untuk situs malware dan dewasa yang dikenal. [Daftar blokir](how-it-works.md#blocklists)
* **Aturan** untuk pola yang tidak perlu dipelajari pengklasifikasi: string tes GTUBE, subjek sekstorsi, penipuan tagihan PayPal, pemalsuan domain sendiri, dan instruksi yang disembunyikan untuk filter AI. [Aturan](scoring.md#rules)
* **Model bahasa**, opsional, memberi pendapat kedua untuk kasus yang meragukan: model lokal melalui Ollama atau server apa pun yang kompatibel dengan OpenAI, model keputusan seperti Clef dari Cloudflare, atau Claude, ChatGPT, Gemini, dan lainnya. Secara bawaan, model memberikan probabilitas untuk setiap vonis dalam satu langkah alih-alih menulis jawaban. [Model bahasa](llm.md)


## Mulai dari mana

* [Memulai](getting-started.md): instal dan pindai pesan pertama.
* [Baris perintah](cli.md): setiap perintah dan opsi.
* [Postfix dan Sendmail](postfix.md): saring server email dengan milter atau content filter.
* [Server email lain](mail-servers.md): Exim, Haraka, Dovecot, procmail, dan apa pun yang dapat memanggil HTTP API.
* [Pelatihan](training.md): ajari dengan email Anda sendiri dan ukur hasilnya.
* [Model bahasa](llm.md): keputusan dan pembuatan teks, akurasi dan kecepatan yang terukur, model keputusan, penyedia, model terbuka yang direkomendasikan, privasi, dan injeksi prompt.
* [Bahasa](languages.md): cara membaca bahasa Tionghoa, Arab, Thai, dan setiap aksara lainnya.
* [Forward Email](forward-email.md): cara Forward Email menggunakannya, dan peningkatan dari versi 5 atau 6.
* [Referensi API](api.md) dan [tes dan skor](scoring.md).
* [Keamanan dan privasi](security.md): apa yang keluar dari mesin, dan cara menghentikannya.
