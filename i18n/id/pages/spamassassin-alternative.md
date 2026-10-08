<!-- source: 1562b843d858 -->

<!--
label: Alternatif SpamAssassin
title: Alternatif SpamAssassin yang memakai protokol spamd
description: Ganti spamd SpamAssassin dengan Spam Scanner. spamc, Exim, dan Haraka tetap berfungsi, header X-Spam tetap bernama sama, dan setiap bahasa didukung.
keywords: alternatif SpamAssassin, pengganti spamd, spamc, filter spam Exim, Haraka spamassassin, alternatif rspamd, X-Spam-Status
-->

# Alternatif SpamAssassin yang memakai protokol spamd

Spam Scanner menjawab protokol spamd milik SpamAssassin, sehingga perangkat lunak yang ditulis untuk SpamAssassin dapat memakainya tanpa perubahan: spamc, kondisi `spam` di Exim, plugin `spamassassin` di Haraka, dan lainnya.


## Ganti dengan Spam Scanner

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

Spam Scanner menjawab `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING`, dan, dengan `--allow-tell`, `TELL` untuk pembelajaran. Tes end-to-end proyek ini menjalankan spamc milik SpamAssassin sendiri terhadapnya.


## Yang tetap sama

* Header: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level`, dan `X-Spam-Status` dalam format SpamAssassin, sehingga aturan Sieve, procmail, dan klien email yang sudah ada tetap berfungsi.
* Skor dengan ambang batas 5, tersusun dari tes bernama dengan poin: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS`, dan seterusnya.
* Skor per tes dapat diubah berdasarkan nama tes.


## Yang berbeda

* **Bahasa.** Kata-kata disegmentasi dengan aturan Unicode, sehingga bahasa Tionghoa, Jepang, dan Thai dibaca sebagai kata, bukan satu string panjang, dan penyamaran seperti karakter tak terlihat atau huruf Sirilik dalam kata Latin dibongkar terlebih dahulu.
* **Phishing.** Domain tiruan, tautan menipu, dan nama merek di nama tampilan diperiksa tanpa aturan tambahan.
* **Lampiran** dikenali dari byte-nya: file executable yang diganti namanya menjadi `.pdf` tetaplah file executable.
* **Model bahasa.** Kasus yang meragukan dapat diteruskan ke model lokal melalui Ollama atau ke model yang di-hosting.
* **Node.js.** Satu `npm install`, atau binary mandiri; tidak ada modul Perl atau pembaruan aturan yang perlu dikelola.

Spam Scanner tidak menjalankan file aturan SpamAssassin, dan format basis data Bayes-nya berbeda: latih dari email yang sama dengan `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot, dan procmail](../../docs/mail-servers.md)
