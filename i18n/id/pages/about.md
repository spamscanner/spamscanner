<!-- source: 599bd320e55a -->

<!--
label: Tentang
title: Tentang Spam Scanner, lisensi, dan privasi
description: Siapa yang membuat Spam Scanner, cara melaporkan bug atau kerentanan, lisensinya, dan apa yang dikumpulkan situs ini: tanpa cookie dan tanpa analitik.
keywords: tentang Spam Scanner, Forward Email, lisensi Spam Scanner, BUSL-1.1, kontak Spam Scanner, privasi Spam Scanner
-->

# Tentang Spam Scanner

Spam Scanner adalah filter spam email buatan [Forward Email](https://forwardemail.net), layanan email yang berfokus pada privasi, yang membangunnya untuk server email miliknya sendiri. Kode sumber, isu, dan rilis ada di [GitHub](https://github.com/spamscanner/spamscanner), dan paketnya ada di [npm](https://www.npmjs.com/package/spamscanner).


## Siapa pembuatnya

Tim Forward Email menulis dan memelihara Spam Scanner. Forward Email tidak menyimpan log isi pesan, jadi tidak bisa mengirim email ke layanan penyaringan luar: filternya harus berjalan di server sendiri dan menjelaskan setiap keputusan tanpa ada orang yang membaca email. [Cara Forward Email memakainya](../../docs/forward-email.md)

Forward Email juga sumber terbuka, di [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Pendirinya adalah salah satu karyawan pertama DuckDuckGo.


## Kontak

* **Pertanyaan, bug, dan permintaan fitur:** buka isu di [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Kerentanan keamanan:** laporkan secara pribadi melalui [pelaporan kerentanan GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), bukan di isu publik. Alamat yang sama ada di [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Lisensi lain:** hubungi [Forward Email](https://forwardemail.net).


## Ketentuan lisensi

[Lisensi](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) Spam Scanner adalah Business Source License 1.1, dengan Apache License 2.0 sebagai Change License. Change Date yang disebutkan dalam lisensi sudah lewat, dan sejak tanggal itu lisensi memberi Anda hak berdasarkan Apache License 2.0.


## Privasi

Situs ini tidak memasang cookie dan tidak memuat analitik, pelacak, iklan, font, atau skrip dari situs lain. Setiap file berasal dari spamscanner.net.

* Tema, bahasa yang Anda pilih, dan server Mastodon tujuan berbagi disimpan di penyimpanan lokal peramban Anda dan tidak dikirim ke mana pun.
* Video baru dimuat saat Anda memutarnya.
* Tautan berbagi adalah tautan biasa, jadi tidak ada apa pun dari jaringan tersebut yang dimuat sampai Anda mengikutinya.
* Situs ini di-hosting di GitHub Pages, dan GitHub mencatat alamat IP setiap pengunjung untuk keperluan keamanan. Lihat [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) dan [Pernyataan Privasi GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Apa yang dikirim perangkat lunak

Spam Scanner tidak mengirim telemetri dan tidak memeriksa pembaruan. Secara default ia mencari nama host tautan dalam pesan di resolver DNS penyaring milik Cloudflare, dan tidak ada hal lain yang keluar dari mesin. Pemeriksaan jaringan lainnya mati sampai Anda menyalakannya. [Keamanan dan privasi](../../docs/security.md)


## Rilis

Biner mandiri dibangun oleh GitHub Actions dari repositori publik. Setiap rilis mencantumkan hash-nya dalam file `SHA256SUMS`, yang diperiksa skrip pemasangan, dan setiap biner membawa atestasi asal build bertanda tangan. Rilis dan catatannya ada di [GitHub](https://github.com/spamscanner/spamscanner/releases).
