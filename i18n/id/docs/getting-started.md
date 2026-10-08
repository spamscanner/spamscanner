<!-- source: 8263c06f1dab -->

# Memulai

Spam Scanner memerlukan Node.js 18 atau lebih baru, atau tidak memerlukan apa pun jika memakai binary mandiri.


## Instal

Sebagai alat baris perintah:

```sh
npm install --global spamscanner
spamscanner version
```

Sebagai pustaka dalam proyek Node.js:

```sh
npm install spamscanner
```

Sebagai binary mandiri untuk Linux atau macOS, dengan Node.js dan model yang sudah tertanam:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binary untuk Linux (x64 dan arm64), macOS (Intel dan Apple silicon), dan Windows dilampirkan pada setiap [rilis](https://github.com/spamscanner/spamscanner/releases).


## Pindai sebuah pesan

Simpan pesan sebagai file (sebagian besar program email menyebutnya "Save as" atau "Show original") lalu pindai:

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

Kode keluar adalah 0 untuk ham, 1 untuk spam, dan 2 untuk galat, sehingga skrip dapat langsung menggunakannya. `--json` mencetak hasil lengkap dan `--headers` mencetak pesan dengan header `X-Spam-*` yang ditambahkan.

Pesan juga dapat berasal dari input standar:

```sh
cat message.eml | spamscanner scan -
```


## Gunakan dari Node.js

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJS juga berfungsi:

```js
const SpamScanner = require('spamscanner');
```

`scan()` menerima pesan mentah sebagai Buffer, string, Uint8Array, atau readable stream. String selalu dianggap sebagai teks pesan: Spam Scanner tidak pernah membaca file hanya karena sebuah string terlihat seperti path. Gunakan `scanner.scanFile(path)` untuk file.


## Beri tahu tentang sesi SMTP

Alamat IP klien, hostname yang terverifikasi, nama HELO, dan envelope membuat hasil lebih akurat: autentikasi memerlukan alamat IP, dan aturan pemalsuan domain sendiri memerlukan daftar penerima.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

Hal yang sama dari baris perintah:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Aktifkan pemeriksaan tambahan

Tidak satu pun dari pemeriksaan ini aktif secara bawaan, karena masing-masing memerlukan layanan atau keputusan:

| Pemeriksaan                  | Opsi pustaka                                     | Baris perintah              |
| ---------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC        | `authentication: true`                           | `--auth`                    |
| Daftar blokir IP             | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Daftar blokir domain tautan  | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                       | `clamav: true` atau `clamav: {socket}`           | `--clamav [socket]`         |
| Model bahasa                 | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Daftar izin dan daftar tolak | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Resolver penyaring Cloudflare (1.1.1.2 untuk malware, 1.1.1.3 untuk konten dewasa) ditanya tentang host tautan secara bawaan. Nonaktifkan dengan `phishing: {cloudflare: false}` atau `--no-cloudflare`. [Apa yang keluar dari mesin](security.md)

Spamhaus dan beberapa daftar blokir lain tidak menjawab kueri yang dikirim melalui resolver publik seperti 8.8.8.8 atau 1.1.1.1. Gunakan dengan resolver cache lokal, dan periksa ketentuan penggunaannya untuk volume Anda.


## Langkah berikutnya

* Pasang di depan server email: [Postfix dan Sendmail](postfix.md), [server lain](mail-servers.md).
* Ajari dengan email Anda sendiri: [pelatihan](training.md).
* Tambahkan model bahasa untuk kasus yang meragukan: [model bahasa](llm.md).
