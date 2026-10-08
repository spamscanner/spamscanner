<!-- source: 0378a5e0f12b -->

<!--
label: Deteksi phishing
title: Deteksi phishing: domain tiruan, tautan menipu, dan spoofing
description: Cara Spam Scanner mendeteksi phishing: domain tiruan Unicode, tautan yang menampilkan alamat lain dari tujuannya, nama merek, resolver Cloudflare, dan DMARC.
keywords: deteksi phishing, filter phishing email, serangan homograf, homograf IDN, deteksi domain tiruan, tautan menipu, email peniruan merek
-->

# Deteksi phishing untuk email

Phishing bekerja dengan menyamar sebagai pihak lain. Spam Scanner memeriksa tempat-tempat penyamaran itu terlihat.


## Domain tiruan

Setiap domain dalam tautan direduksi menjadi kerangka dengan tabel confusables Unicode dan dibandingkan dengan hampir 100 merek yang sering ditiru:

| Domain                              | Terdeteksi sebagai               |
| ----------------------------------- | -------------------------------- |
| `pаypal.com` (а Sirilik)            | Karakter yang mirip              |
| `paypa1-secure.top`                 | Karakter yang ditukar            |
| `xn--pple-43d.com`                  | Punycode untuk `аpple.com`       |
| `paypal.com.account-verify.example` | Merek di domain milik pihak lain |
| `paypall.com`                       | Selisih satu huruf               |

Merek dapat ditambahkan, dan domain milik Anda dapat dimasukkan ke daftar izin.


## Tautan menipu

Tautan HTML yang teksnya berupa satu alamat dan tujuannya alamat lain, misalnya teks `https://www.paypal.com/signin` yang mengarah ke `http://paypa1-secure.top/login`, menambahkan 3 poin.


## Nama tampilan dan spoofing

* Nama tampilan yang memuat merek ("PayPal Security") dari alamat di domain lain.
* Nama tampilan yang memuat alamat email yang berbeda.
* Email yang mengaku berasal dari domain penerima sendiri tetapi gagal SPF, DKIM, dan DMARC.


## Situs berbahaya yang dikenal

Host tautan dicari di resolver 1.1.1.2 milik Cloudflare, yang memblokir situs malware dan phishing yang dikenal, dan secara opsional di daftar blokir domain seperti Spamhaus DBL.


## Lampiran

Phishing juga datang sebagai lampiran HTML yang menampilkan halaman login palsu secara offline, dan sebagai file executable yang diganti namanya menjadi `.pdf`. Keduanya dikenali dari isinya.

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

[Cara kerja pemeriksaan](../../docs/how-it-works.md#phishing)
