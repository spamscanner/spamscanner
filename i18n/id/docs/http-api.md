<!-- source: faf44f093f8b -->

# HTTP API, server TCP, dan spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Server mendengarkan di 127.0.0.1 kecuali `--host` menentukan lain. Dengan token, setiap permintaan kecuali `/health` memerlukan `Authorization: Bearer <token>`. Tempatkan di belakang reverse proxy dengan TLS sebelum membukanya ke luar mesin.

| Metode dan path    | Body         | Jawaban                                                                   |
| ------------------ | ------------ | ------------------------------------------------------------------------- |
| `GET /health`      |              | `{"ok": true, "version": "7.0.0"}`                                        |
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

`/check` juga mengembalikan `X-Spam-Flag`, `X-Spam-Score`, dan `X-Spam-Action` sebagai header respons, sehingga klien dapat memutuskan tanpa mengurai pesan.

Pesan yang lebih besar dari 25 MB mendapat `413`. Pemindaian yang gagal mendapat `500` dengan `{"error": "..."}`.

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
