<!-- source: 1d7373f991c2 -->

# Keamanan dan privasi

Spam Scanner membaca email, yang bersifat pribadi, dari pengirim, yang mungkin berniat jahat. Halaman ini mencantumkan apa saja yang dikirimnya ke luar, dan bagaimana ia memperlakukan apa yang dibacanya.


## Apa yang keluar dari mesin

Secara bawaan, satu hal: **nama host dari tautan** dalam pesan dicari di resolver penyaring Cloudflare, 1.1.1.2 dan 1.0.0.2 (malware dan phishing) serta 1.1.1.3 dan 1.0.0.3 (juga konten dewasa). Ini adalah kueri DNS biasa untuk nama seperti `example.com`; tidak ada bagian dari pesan atau alamatnya yang dikirim. Nonaktifkan dengan `phishing: {cloudflare: false}` atau `--no-cloudflare`, atau hanya pemeriksaan konten dewasa dengan `phishing: {adult: false}`.

Semua yang lain nonaktif sampai dikonfigurasi:

| Pemeriksaan         | Mengirim                                                                                                         | Ke                                                                  |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `authentication`    | Kueri DNS untuk catatan SPF, DKIM, DMARC, dan ARC milik pengirim                                                 | Resolver Anda, atau `dnsServers`                                    |
| `dnsbl`             | Alamat IP klien, dibalik, dan domain tautan, sebagai kueri DNS                                                   | Name server daftar blokir, melalui resolver Anda atau `dns.servers` |
| `llm`               | Ringkasan pesan, dengan data pribadi dihapus untuk penyedia jarak jauh                                           | Server model bahasa yang Anda tentukan ([privasi](llm.md#privacy))  |
| `reputation.apiUrl` | Alamat IP dan nama host terverifikasi klien, serta alamat From, pengirim amplop, dan Reply-To, beserta domainnya | Layanan yang Anda tentukan                                          |
| `clamav`            | Lampiran                                                                                                         | clamd Anda, melalui soketnya                                        |

Tidak ada telemetri, tidak ada pemeriksaan pembaruan, dan tidak ada unduhan saat berjalan. Model sudah disertakan di dalam paket.


## Apa yang disimpan

Tidak ada, kecuali diminta. Hasil pemindaian tidak dicatat atau disimpan. `learn()` mengubah pengklasifikasi di memori; perubahan itu hanya ditulis ke disk oleh `saveModel()`, `spamscanner learn`, atau opsi `--out` pada server. File model berisi jumlah fitur yang di-hash, bukan kata atau teks pesan.

Jawaban model bahasa di-cache di memori, dengan kunci berupa hash dari apa yang dikirim, sehingga salinan berulang dari pesan yang sama hanya ditanyakan sekali. Jawaban DNS di-cache di memori selama sepuluh menit, dan jawaban layanan reputasi selama lima menit (`reputation.cacheTtl`; permintaan yang gagal selama satu menit).


## Input berbahaya

* Lampiran dikenali dari byte-nya, tidak pernah dieksekusi atau dibuka oleh program lain. Arsip ZIP dibaca dari central directory-nya, dengan batas jumlah entri (2000) dan jumlah byte namanya (1 MiB; nama yang lebih dari 1 KiB mempertahankan 512 byte pertama dan terakhirnya, dan temuan menampilkan paling banyak 100 karakter dari sebuah nama), setiap entri dibaca sekali berapa pun banyaknya direktori yang menunjuk kepadanya; tidak ada yang didekompresi, sehingga program di dalam arsip bersarang atau terkompresi tidak terlihat. Pesan yang dilampirkan (`message/rfc822`, atau lampiran yang nama filenya berakhiran `.eml`) dibuka hingga tiga tingkat ke dalam, untuk paling banyak 100 lampirannya dan total 25 MB pesan terlampir; lampiran milik pesan itu sendiri selalu diperiksa semuanya. Pesan yang melampaui batas parser MIME (lebih dari 1000 bagian, atau header bagian lebih dari 1 MB) dibaca sejauh yang diizinkan parser (bagian-bagian pertamanya, dengan header yang terlalu besar dipangkas agar pengirimnya tetap dihitung) dan mendapat `MIME_TOO_COMPLEX`, yang tidak dapat diimbangi kredit apa pun; ClamAV membacanya secara utuh. Pesan yang dilampirkan yang gagal diurai parser juga mendapatkannya, dan tidak pernah menggagalkan pemindaian. Field alamat dibaca hingga 16 KB masing-masing (2000 alamat, 16 grup bersarang) dan 64 KB secara keseluruhan untuk setiap pesan, dipotong hanya di akhir sebuah alamat yang utuh, karena parser alamat membutuhkan waktu yang tumbuh sebanding dengan kuadrat jumlah alamat; mailauth juga membaca From dan Return-Path dengan batas yang sama (field lainnya apa adanya, agar tanda tangan atasnya tetap berlaku), dan header yang akan membutuhkan waktu lebih dari linear untuk dibacanya (ribuan baris terlipat, atau tanda tangan yang menyebut ribuan field) dipangkas. Field From yang dipotong menggagalkan DMARC dan tidak memasukkan apa pun ke daftar izin. HTML dibaca oleh parser milik Spam Scanner sendiri, dalam waktu linear, seberapa pun dalam sarangnya.
* Teks isi pesan dibaca hingga `maxLength` (100.000 karakter) dan server menerima pesan hingga 25 MB. Tautan dibaca hingga `phishing.maxLength` (1.000.000 karakter).
* Setiap pemeriksaan jaringan memiliki batas waktu (`timeout`, 10 detik secara bawaan). Pemeriksaan yang gagal atau melewati batas waktu dilewati dan pemindaian selesai tanpanya. Autentikasi dan model gambar (10 gambar pertama) masing-masing selesai seluruhnya dalam batas itu: autentikasi tidak mengirim kueri DNS setelahnya, dan tidak lebih dari 300 untuk satu pesan (cukup untuk SPF pada batas RFC 7208, bersama DKIM, ARC, DMARC, dan BIMI), dan hanya memeriksa 8 tanda tangan DKIM pertama dari sebuah pesan (mailauth sendiri membaca paling banyak 50 set ARC). Header `Authentication-Results` yang ditambahkan milter berisi paling banyak 8 KiB hasil. ClamAV (empat lampiran sekaligus) punya batas sendiri untuk semua lampiran sebuah pesan (`clamav.timeout`, 60 detik), dan lampiran yang tidak dapat dipindainya dicantumkan di `results.virusScanErrors`. Model bahasa punya batas waktunya sendiri (`llm.timeout`).
* Daftar izin hanya memercayai hal yang tidak dapat dipalsukan pengirim: alamat dan nama host terverifikasi klien, serta domain pengirim yang dikonfirmasi autentikasi. [Daftar izin dan daftar tolak](api.md#allowlist-and-denylist)
* Header `X-Spam-*` yang sudah ada dalam pesan dihapus oleh milter, content filter, dan `--headers`, sehingga pengirim tidak dapat menandai email mereka sendiri sebagai bersih.
* Header vonis spam dari Microsoft hanya dipercaya jika pesan datang langsung dari server Microsoft, dan header Received tidak pernah digunakan untuk menentukan asal pesan.
* Teks yang ditujukan kepada filter AI diberi skor sebagai spam, dan model bahasa diberi tahu bahwa pesan tersebut adalah data, bukan instruksi. [Injeksi prompt](llm.md#prompt-injection)


## Server

Server milter, HTTP, TCP, dan spamd mendengarkan di 127.0.0.1 kecuali `--host` menentukan lain. HTTP API membandingkan tokennya dalam waktu konstan dan menolak `/learn` tanpa token. Tidak satu pun yang mendukung TLS: untuk menjangkaunya melalui jaringan, gunakan jaringan privat, tunnel SSH, atau reverse proxy dengan TLS.

Jalankan sebagai pengguna tanpa hak istimewa. [Unit systemd dalam panduan Postfix](postfix.md#1-run-the-milter) menambahkan pengerasan keamanan yang lazim.


## Melaporkan kerentanan

Laporkan masalah keamanan secara privat melalui [pelaporan kerentanan GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), bukan di issue publik.
