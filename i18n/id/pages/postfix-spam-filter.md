<!-- source: f33722183f00 -->

<!--
label: Filter spam Postfix
title: Filter spam Postfix dengan milter atau content filter
description: Saring spam di server Postfix dengan milter atau content filter Spam Scanner: penyiapan, unit systemd, penolakan dengan 4xx atau 5xx, dan folder Junk.
keywords: filter spam Postfix, milter Postfix, smtpd_milters, content filter Postfix, anti spam Postfix, tolak spam Postfix
-->

# Filter spam Postfix

Spam Scanner menyaring server Postfix dalam sekitar lima menit. Spam Scanner berjalan sebagai milter, sehingga Postfix menanyakan setiap pesan kepadanya selama sesi SMTP dan dapat menolak spam sebelum menerimanya.


## Instal dan jalankan

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` memeriksa SPF, DKIM, DMARC, dan ARC; `--subject-tag` menandai spam di subjek. Setiap pesan mendapat header `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status`, dan `X-Spam-Action`, dan setiap header `X-Spam-*` yang dimasukkan pengirim dihapus terlebih dahulu.


## Hubungkan Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` meloloskan email tanpa disaring jika milter mati; `tempfail` justru meminta pengirim mencoba lagi.


## Tolak spam selama sesi SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

Pesan yang mencapai ambang tolak (15 poin) ditolak dengan `451 4.7.1 Message rejected as spam`. Kode 451 bersifat sementara: pengirim menyimpan pesan dan mencoba lagi, sehingga keputusan yang salah hanya menyebabkan penundaan, bukan pesan yang hilang. Setelah hasilnya terlihat benar, `--reject-code 550` membuat penolakan menjadi permanen.


## Tanpa milter

Content filter berjalan setelah Postfix menerima pesan: Postfix mengalirkannya ke `spamscanner filter`, yang menambahkan header lalu mengembalikannya. Tidak ada yang pernah ditolak selama sesi, dan kegagalan selalu menunda pengiriman alih-alih memantulkannya. [Penyiapan content filter](../../docs/postfix.md#content-filter)


## Spam ke Junk

Dengan Dovecot, sebuah aturan Sieve memindahkan email yang ditandai:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Diuji dengan Postfix sungguhan

Tes end-to-end proyek ini menjalankan Postfix dengan milter dan content filter: ham dikirim dengan header dan `X-Spam-Flag` palsu dihapus, spam ditandai, dan GTUBE ditolak dengan 550 selama sesi SMTP.

Berikutnya: [panduan lengkap Postfix dan Sendmail](../../docs/postfix.md), dengan unit systemd dan `INPUT_MAIL_FILTER` milik Sendmail.
