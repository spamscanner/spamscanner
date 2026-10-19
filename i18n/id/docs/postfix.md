<!-- source: 6675649d593a -->

# Postfix dan Sendmail

Spam Scanner terhubung ke Postfix dengan dua cara:

* **Sebagai milter** (disarankan). Postfix menanyakan setiap pesan kepadanya selama sesi SMTP, sebelum menerimanya. Spam dapat ditolak dengan balasan 4xx atau 5xx, sehingga server pengirim, bukan server Anda, yang menanganinya. Sendmail memakai protokol yang sama.
* **Sebagai content filter.** Postfix menerima pesan, mengalirkannya ke `spamscanner filter`, yang menambahkan header lalu mengembalikannya dengan sendmail. Tidak ada yang pernah ditolak selama sesi SMTP.

Keduanya menambahkan header berikut ke setiap pesan:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.3
X-Spam-Action: tag
```

Header `X-Spam-*` yang sudah ada dalam pesan dihapus terlebih dahulu, sehingga pengirim tidak dapat menandai emailnya sendiri sebagai bersih.

Pesan dengan lampiran yang tidak dapat dipindai ClamAV mungkin berisi virus, jadi keduanya menundanya (Postfix atau pengirim mencoba lagi nanti), sama seperti ketika pemindaian gagal. Dengan `--on-error accept`, pesan itu diteruskan dengan tambahan `X-Spam-Virus-Scan: failed`.


## Milter

### 1. Jalankan milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Dengan `--reject`, pesan yang mencapai ambang tolak (15 poin) ditolak dengan `451 4.7.1 Message rejected as spam`. Kode 451 bersifat sementara: pengirim mencoba lagi nanti dan kesalahan masih dapat diperbaiki dengan mengubah pengaturan. Gunakan `--reject-code 550` untuk penolakan permanen setelah hasilnya terlihat benar. Dengan `--quarantine`, spam justru masuk ke hold queue Postfix. Pesan yang tidak dapat dipindai sepenuhnya oleh milter mendapat balasan 4xx; `--on-error accept` justru meloloskannya.

Sebagai layanan systemd, di `/etc/systemd/system/spamscanner-milter.service`:

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. Arahkan Postfix ke milter

Di `/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters` mencakup email yang datang melalui SMTP. Biarkan `non_smtpd_milters` kosong kecuali email yang dikirim dengan perintah `sendmail` juga perlu dipindai.

### 3. Uji

[swaks](https://www.jetmore.org/john/code/swaks/) mengirim pesan uji. GTUBE adalah string tes yang dianggap spam oleh setiap filter spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Tanpa `--reject`, pesan dikirim dengan `X-Spam-Flag: YES` dan subjek yang ditandai. Dengan `--reject`, swaks menampilkan balasan 451 atau 550.


## Content filter

Gunakan cara ini jika email tidak boleh ditolak selama sesi SMTP, atau untuk server yang tidak dapat memakai milter.

Di `/etc/postfix/master.cf`, tambahkan layanan filter dan gunakan pada listener SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] --from=${sender} -- ${recipient}
```

Postfix menjalankan filter dengan environment yang hampir kosong, sehingga `argv` menyebut Node.js dan skripnya dengan path lengkap (`command -v node` dan `npm root --global` menampilkannya). Lalu:

```sh
sudo postfix reload
```

Filter mengembalikan pesan dengan `sendmail -G -i`. Email yang dikirim dengan cara ini tidak melewati listener `smtp` lagi, sehingga tidak disaring dua kali.

Kode keluar memberi tahu Postfix apa yang terjadi: 0 terkirim, 69 ditolak (dengan `--reject`: Postfix memantulkannya ke pengirim), 75 kegagalan sementara (Postfix menyimpan pesan dan mencoba lagi). Setiap kegagalan pemindaian atau pengiriman menghasilkan 75, begitu pula pesan dengan lampiran yang tidak dapat dipindai ClamAV, sehingga pengaturan yang rusak tidak pernah menghilangkan atau memantulkan email. Dengan `--on-error accept`, pesan yang pemindaiannya gagal, atau yang tidak dapat dipindai sepenuhnya oleh ClamAV, justru diteruskan, dengan tanda `X-Spam-Virus-Scan: failed` (lihat [CLI](cli.md#filter)).


## Sendmail

Di `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` membuat Sendmail menjawab dengan kegagalan sementara selama milter tidak tersedia; hapus untuk menerima email tanpa disaring. Bangun ulang `sendmail.cf` dan mulai ulang Sendmail.

Nama host klien hanya dapat memasukkan pesan ke daftar izin jika terverifikasi. Postfix hanya mengirimkannya jika nama DNS balik klien ter-resolve kembali ke alamatnya, dan `unknown` jika tidak. Sendmail mengirimkan nama DNS balik meskipun tidak ter-resolve kembali (nama yang dapat dipilih siapa pun yang memiliki DNS balik untuk alamatnya sendiri), dan menyatakannya dalam makro `{client_resolve}`-nya, yang tidak dikirimkannya secara bawaan. Tambahkan makro itu ke makro yang dikirim saat koneksi, sebelum `INPUT_MAIL_FILTER`, agar hanya nama host yang dinyatakannya sebagai `OK` yang dihitung:

```text
define(`confMILTER_MACROS_CONNECT', `j, _, {daemon_name}, {if_name}, {if_addr}, {client_resolve}')
```


## Memilah spam ke folder Junk

Penandaan saja tetap mengirim spam ke kotak masuk. Dengan Dovecot, sebuah aturan Sieve memindahkannya:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Server email lain](mail-servers.md) membahas Dovecot, Exim, Haraka, dan procmail, dan [pelatihan](training.md#learning-from-reports) menunjukkan cara belajar dari email yang dipindahkan pengguna ke dalam dan keluar dari Junk.


## Diuji

Tes end-to-end repositori menjalankan Postfix sungguhan: ham dikirim dengan header, `X-Spam-Flag` palsu dihapus, spam ditandai, GTUBE ditolak dengan 550 selama sesi SMTP, dan content filter menandai email di port kedua. `scripts/e2e-postfix.sh` menyiapkan Postfix tersebut dan `test/e2e/postfix.test.js` mengirim emailnya.
