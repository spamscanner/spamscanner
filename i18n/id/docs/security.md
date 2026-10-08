<!-- source: 60f00f92b5aa -->

# Keamanan dan privasi

Spam Scanner membaca email, yang bersifat pribadi, dari pengirim, yang mungkin berniat jahat. Halaman ini mencantumkan apa saja yang dikirimnya ke luar, dan bagaimana ia memperlakukan apa yang dibacanya.


## Apa yang keluar dari mesin

Secara bawaan, satu hal: **nama host dari tautan** dalam pesan dicari di resolver penyaring Cloudflare, 1.1.1.2 dan 1.0.0.2 (malware dan phishing) serta 1.1.1.3 dan 1.0.0.3 (juga konten dewasa). Ini adalah kueri DNS biasa untuk nama seperti `example.com`; tidak ada bagian dari pesan atau alamatnya yang dikirim. Nonaktifkan dengan `phishing: {cloudflare: false}` atau `--no-cloudflare`, atau hanya pemeriksaan konten dewasa dengan `phishing: {adult: false}`.

Semua yang lain nonaktif sampai dikonfigurasi:

| Pemeriksaan         | Mengirim                                                               | Ke                                                                  |
| ------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `authentication`    | Kueri DNS untuk catatan SPF, DKIM, DMARC, dan ARC milik pengirim       | Resolver Anda, atau `dnsServers`                                    |
| `dnsbl`             | Alamat IP klien, dibalik, dan domain tautan, sebagai kueri DNS         | Name server daftar blokir, melalui resolver Anda atau `dns.servers` |
| `llm`               | Ringkasan pesan, dengan data pribadi dihapus untuk penyedia jarak jauh | Server model bahasa yang Anda tentukan ([privasi](llm.md#privacy))  |
| `reputation.apiUrl` | Alamat IP, domain, dan alamat pengirim                                 | Layanan yang Anda tentukan                                          |
| `clamav`            | Lampiran                                                               | clamd Anda, melalui soketnya                                        |

Tidak ada telemetri, tidak ada pemeriksaan pembaruan, dan tidak ada unduhan saat berjalan. Model sudah disertakan di dalam paket.


## Apa yang disimpan

Tidak ada, kecuali diminta. Hasil pemindaian tidak dicatat atau disimpan. `learn()` mengubah pengklasifikasi di memori; perubahan itu hanya ditulis ke disk oleh `saveModel()`, `spamscanner learn`, atau opsi `--out` pada server. File model berisi jumlah fitur yang di-hash, bukan kata atau teks pesan.

Jawaban model bahasa di-cache di memori, dengan kunci berupa hash dari apa yang dikirim, sehingga salinan berulang dari pesan yang sama hanya ditanyakan sekali. Jawaban DNS di-cache di memori selama sepuluh menit.


## Input berbahaya

* Lampiran dikenali dari byte-nya, tidak pernah dieksekusi atau dibuka oleh program lain. Arsip ZIP dibaca dari central directory-nya, dengan batas jumlah entri; arsip bersarang tidak dibongkar.
* Teks isi pesan dibaca hingga `maxLength` (100.000 karakter) dan server menerima pesan hingga 25 MB.
* Setiap pemeriksaan jaringan memiliki batas waktu (`timeout`, 10 detik secara bawaan). Pemeriksaan yang gagal atau melewati batas waktu dilewati dan pemindaian selesai tanpanya.
* Header `X-Spam-*` yang sudah ada dalam pesan dihapus oleh milter, content filter, dan `--headers`, sehingga pengirim tidak dapat menandai email mereka sendiri sebagai bersih.
* Header vonis spam dari Microsoft hanya dipercaya jika pesan datang langsung dari server Microsoft, dan header Received tidak pernah digunakan untuk menentukan asal pesan.
* Teks yang ditujukan kepada filter AI diberi skor sebagai spam, dan model bahasa diberi tahu bahwa pesan tersebut adalah data, bukan instruksi. [Injeksi prompt](llm.md#prompt-injection)


## Server

Server milter, HTTP, TCP, dan spamd mendengarkan di 127.0.0.1 kecuali `--host` menentukan lain. HTTP API membandingkan tokennya dalam waktu konstan dan menolak `/learn` tanpa token. Tidak satu pun yang mendukung TLS: untuk menjangkaunya melalui jaringan, gunakan jaringan privat, tunnel SSH, atau reverse proxy dengan TLS.

Jalankan sebagai pengguna tanpa hak istimewa. [Unit systemd dalam panduan Postfix](postfix.md#1-run-the-milter) menambahkan pengerasan keamanan yang lazim.


## Melaporkan kerentanan

Laporkan masalah keamanan secara privat melalui [pelaporan kerentanan GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), bukan di issue publik.
