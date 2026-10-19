<!-- source: 988243aec4f3 -->

<!--
label: Filter spam self-hosted
title: Filter spam self-hosted untuk server email Anda sendiri
description: Filter spam di server Anda sendiri. Spam Scanner menyimpan email di mesin, menyertakan modelnya dalam paket, tidak mengirim telemetri, dan terhubung ke Postfix atau Exim.
keywords: filter spam self-hosted, filter spam on-premise, filter spam pribadi, filter spam lokal, filter spam untuk server email, filter spam tanpa cloud
-->

# Filter spam self-hosted

Spam Scanner berjalan di server Anda sendiri dan menyimpan email di sana. Model pengklasifikasinya ada di dalam paket, tidak ada telemetri atau pemeriksaan pembaruan, dan secara default satu-satunya yang dikirim adalah kueri DNS untuk nama host setiap tautan.


## Apa yang keluar dari server

Secara default, hanya nama host tautan dalam pesan. Nama itu dicari di resolver penyaring milik Cloudflare (1.1.1.2 dan 1.1.1.3) sebagai kueri DNS biasa, dan tidak ada bagian pesan atau alamatnya yang dikirim. `--no-cloudflare` juga mematikan ini.

Setiap pemeriksaan lain yang memakai jaringan mati sampai Anda menyalakannya:

| Pemeriksaan           | Nyalakan dengan      | Yang dikirim                                         |
| --------------------- | -------------------- | ---------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | Kueri DNS untuk catatan pengirim                     |
| Daftar blokir DNS     | `--dnsbl`, `--uribl` | Alamat IP klien dan domain tautan, sebagai kueri DNS |
| ClamAV                | `--clamav`           | Lampiran, ke clamd Anda sendiri                      |
| Model bahasa          | `--llm`              | Ringkasan pesan, ke server yang Anda tentukan        |

Pemindaian tidak dicatat atau disimpan. [Keamanan dan privasi](../../docs/security.md)


## Pasang di server

```sh
npm install --global spamscanner
```

Atau biner mandiri, dengan Node.js dan model di dalamnya:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Skrip pemasangan memeriksa biner terhadap file `SHA256SUMS` dari rilis sebelum memasangnya, dan setiap biner memiliki atestasi asal build bertanda tangan yang diperiksa oleh `gh attestation verify`. Biner tersedia untuk Linux (x64 dan arm64), macOS, dan Windows. Biner Linux membutuhkan glibc, jadi di Alpine pasang dengan npm. [Memulai](../../docs/getting-started.md)

Tidak ada pemeriksaan pembaruan. Untuk memperbarui, jalankan lagi perintah pemasangan: kedua perintah memasang rilis terbaru.


## Jalankan sebagai layanan

Server milter, HTTP, TCP, dan spamd mendengarkan di 127.0.0.1 kecuali `--host` menyatakan lain. Jalankan sebagai pengguna tanpa hak istimewa, misalnya di bawah systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

[Unit lengkap dan penyiapannya](../../docs/postfix.md#1-run-the-milter) ada di panduan Postfix. Tidak ada server yang memakai TLS, jadi untuk menjangkaunya dari mesin lain, gunakan jaringan privat, terowongan SSH, atau reverse proxy dengan TLS.


## Hubungkan server email Anda

| Server email                             | Perintah                                | Port      |
| ---------------------------------------- | --------------------------------------- | --------- |
| Postfix atau Sendmail                    | `spamscanner milter`                    | 7831      |
| Postfix, tanpa pernah menolak email      | `spamscanner filter`, filter konten     | tidak ada |
| Exim, Haraka, atau spamc                 | `spamscanner spamd`                     | 783       |
| Apa pun yang memakai HTTP                | `spamscanner http`                      | 7832      |
| Klien TCP sederhana                      | `spamscanner server`                    | 7830      |
| Server email yang ditulis dengan Node.js | `import SpamScanner from 'spamscanner'` | tidak ada |

Server dapat menambahkan header `X-Spam-Flag`, `X-Spam-Score`, dan `X-Spam-Status` ke pesan, dan pustaka mengembalikan skor serta setiap uji yang terpicu. Panduan: [filter spam Postfix](/postfix-spam-filter/), [server email lain](../../docs/mail-servers.md), dan [API HTTP](../../docs/http-api.md).


## Jaga model bahasa tetap lokal

Model bahasa bersifat opsional dan hanya membaca kasus yang meragukan: spam yang jelas dan ham yang jelas tidak pernah sampai kepadanya. Dengan Ollama, model berjalan di server yang sama, jadi tidak ada pesan yang keluar:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` berjalan di CPU. Dengan penyedia ter-hosting, data pribadi dihapus dari pesan sebelum dikirim. [Model bahasa](../../docs/llm.md)


## Latih dengan email Anda sendiri

Model bawaan dilatih dengan dataset publik. Model yang dilatih dengan email yang diterima server Anda bekerja lebih baik, dan tetap berada di server itu:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

File model menyimpan hitungan fitur yang di-hash, bukan kata atau teks pesan. [Pelatihan](../../docs/training.md)


## Persyaratan

Node.js 18 atau lebih baru di Linux, macOS, atau Windows, atau tidak ada apa pun dengan biner mandiri. ClamAV dan Ollama bersifat opsional dan berjalan sebagai layanan sendiri.
