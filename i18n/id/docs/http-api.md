<!-- source: 665fbc0d5adc -->

# HTTP API, server TCP, dan spamd


## HTTP API

```sh
spamscanner http --port 7832    # token in SPAMSCANNER_TOKEN
```

API HTTP membaca tokennya dari variabel lingkungan `SPAMSCANNER_TOKEN`. `--token` juga berfungsi, tetapi pengguna lain di mesin itu dapat melihat opsi baris perintah di `ps`.

Server mendengarkan di 127.0.0.1 kecuali `--host` menentukan lain. Dengan token, setiap permintaan kecuali `/health` memerlukan `Authorization: Bearer <token>`. Tempatkan di belakang reverse proxy dengan TLS sebelum membukanya ke luar mesin.

| Metode dan path    | Body         | Jawaban                                                                   |
| ------------------ | ------------ | ------------------------------------------------------------------------- |
| `GET /health`      |              | `{"ok": true, "version": "..."}`                                          |
| `POST /scan`       | Pesan mentah | [Hasil pemindaian](api.md#the-result) sebagai JSON                        |
| `POST /check`      | Pesan mentah | Pesan dengan header `X-Spam-*` yang ditambahkan, sebagai `message/rfc822` |
| `POST /learn/spam` | Pesan mentah | `{"ok": true, "learned": "spam"}`; memerlukan token                       |
| `POST /learn/ham`  | Pesan mentah | `{"ok": true, "learned": "ham"}`; memerlukan token                        |

Parameter kueri menjelaskan sesi SMTP:

| Parameter    | Arti                                                              |
| ------------ | ----------------------------------------------------------------- |
| `ip`         | Alamat IP klien                                                   |
| `hostname`   | Nama reverse DNS-nya yang terverifikasi                           |
| `helo`       | Nama HELO atau EHLO-nya                                           |
| `from`       | Pengirim envelope                                                 |
| `to`         | Penerima; ulangi parameter ini atau pisahkan beberapa dengan koma |
| `verbose=1`  | `/scan`: juga mengembalikan daftar kata dan subjek                |
| `subjectTag` | `/check`: awalan untuk subjek spam, misalnya `%5BSPAM%5D`         |

Tanpa `ip`, pemeriksaan SPF, DKIM, DMARC, ARC, dan daftar blokir IP (`--auth`, `--dnsbl`) dilewati.

`/check` juga mengembalikan `X-Spam-Flag`, `X-Spam-Score`, dan `X-Spam-Action` sebagai header respons, sehingga klien dapat memutuskan tanpa mengurai pesan.

Pesan yang lebih besar dari 25 MiB (`--max-size`) mendapat `413`, sebelum isinya dibaca jika `Content-Length` memberikan ukurannya. Pemindaian yang gagal mendapat `500` dengan `{"error": "..."}`. Server menangani paling banyak 200 permintaan sekaligus (`--max-connections`), termasuk permintaan pipelined; permintaan berikutnya mendapat `503` dengan `Retry-After: 1`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Dengan `--out model.json`, apa yang diajarkan melalui `/learn` disimpan ke file tersebut setelah setiap permintaan. Tanpanya, pembelajaran hanya bertahan sampai server dimulai ulang.

Dari Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Dari Python:

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## Server TCP

```sh
spamscanner server --port 7830
```

Kirim pesan mentah, tutup sisi pengiriman koneksi, lalu baca satu baris JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Dengan `--verbose`, jawabannya berupa satu baris teks: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` atau `HAM -2.5/5.0 BAYES_00`.

Server TCP tidak mengetahui alamat IP klien, sehingga `--auth` dan `--dnsbl` tidak berpengaruh. Server hanya menjawab setelah klien menutup sisi pengirimannya (`nc -N` atau `nc -q 1`, atau `shutdown(SHUT_WR)` pada soket); klien yang membiarkannya terbuka tidak mendapat jawaban, dan koneksi ditutup setelah 60 detik tanpa data. Server menjawab pesan yang lebih besar dari 25 MiB (`--max-size`) dengan galat.


## spamd

```sh
spamscanner spamd --port 783
```

Server yang kompatibel dengan SpamAssassin untuk spamc, Exim, Haraka, dan klien SpamAssassin lainnya. [Menyiapkan Exim dan Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Perintah        | Jawaban                                                                |
| --------------- | ---------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                              |
| `SYMBOLS`       | Vonis dan nama tes yang terpicu                                        |
| `REPORT`        | Vonis dan tabel tes, poin, serta alasan                                |
| `REPORT_IFSPAM` | Seperti `REPORT`, dengan laporan kosong untuk ham                      |
| `PROCESS`       | Vonis dan pesan dengan header `X-Spam-*`                               |
| `HEADERS`       | Vonis dan blok header pesan dengan header `X-Spam-*`                   |
| `PING`          | `PONG`                                                                 |
| `SKIP`          | Tidak ada                                                              |
| `TELL`          | Mempelajari spam atau ham, dengan `--allow-tell`; menyimpan ke `--out` |

Permintaan terkompresi (`Compress: zlib`) ditolak.

Klien spamd juga tidak mengirim alamat IP klien, sehingga `--auth` dan `--dnsbl` tidak berpengaruh. Pesan yang lebih besar dari 25 MiB (`--max-size`) mendapat `65` (`EX_DATAERR`), pesan yang lebih pendek dari `Content-length`-nya mendapat `76` (`EX_PROTOCOL`), dan koneksi yang tidak mengirim apa pun selama 60 detik ditutup.
