<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner dibuat oleh [Forward Email](https://forwardemail.net), layanan email sumber terbuka yang berfokus pada privasi, untuk server emailnya sendiri. Forward Email tidak menyimpan log isi pesan, sehingga layanan penyaringan dari luar tidak dapat dipakai: filter harus berjalan di servernya sendiri, dan harus menjelaskan setiap keputusan tanpa ada orang yang membaca email.

Halaman ini menunjukkan cara server email seperti milik Forward Email menggunakannya, dan apa yang berubah untuk kode yang ditulis untuk Spam Scanner 5 atau 6.


## Di server email masuk

Forward Email menerima email dengan [smtp-server](https://nodemailer.com/extras/smtp-server/). Polanya, untuk server apa pun yang dibangun di atasnya:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()` menerima stream SMTP secara langsung. Jika hasil [mailauth](https://github.com/postalsys/mailauth) sudah tersedia, lewati `authentication` dan berikan alamat IP saja.

Balasan 421 atau 451 membuat server pengirim mengantrekan pesan dan mencoba lagi nanti. Aturan penolakan baru dapat dimulai dengan kode sementara lalu beralih ke 550 setelah hasilnya diperiksa, tanpa kehilangan email di antaranya.


## Meningkatkan dari versi 5 atau 6

Versi 7 adalah penulisan ulang. Konstruktor, `scan()`, dan field hasil yang dibaca kode versi 5 dan 6 masih berfungsi; pengklasifikasi, model, dan pemeriksaan TensorFlow opsional berubah.

### Tetap sama

* `new SpamScanner(options)` dan `await scanner.scan(source)`.
* `require('spamscanner')` mengembalikan kelas, dan `import SpamScanner from 'spamscanner'` berfungsi.
* `result.isSpam`, `result.message`, serta `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros`, dan `.idnHomographAttack`.
* Setiap item dalam `results.phishing`, `.executables`, `.arbitrary`, dan `.viruses` dikonversi menjadi string pesan yang sama jenisnya seperti sebelumnya (`String(item)`, template literal, `message.includes('adult-related content')`). Sekarang item tersebut berupa objek dengan `type`, `message`, dan detail.
* `getTokensAndMailFromSource()`, `getClassification()`, dan `getTokens()`.
* Opsi berikut dipetakan ke nama barunya: `clamscan` menjadi `clamav`, `enableMacroDetection: false` menjadi `macros: false`, `enableArbitraryDetection: false` menjadi `arbitrary: false`, `enableAuthentication` dengan `authOptions` menjadi `authentication` dan `session`, `enableReputation` dengan `reputationOptions.apiUrl` menjadi `reputation`, `strictIDNDetection` menjadi `phishing.homograph.strictMode`, serta `allowlist` dan `denylist`. `logger` dan `memoize` diterima tetapi diabaikan.

### Berubah

| Sebelumnya                                                                                 | Sekarang                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` membaca file                                                    | String adalah teks pesan. Gunakan `scanFile(path)` atau berikan Buffer                                                                                                       |
| Model naive Bayes berbasis kata (`classifier.json`), kini tidak dapat dimuat               | Pengklasifikasi dan format model baru; latih ulang dengan `spamscanner train` ([pelatihan](training.md))                                                                     |
| Pemeriksaan toksisitas dan NSFW memuat model TensorFlow dari jaringan saat pertama dipakai | Bawa model Anda sendiri: `toxicity: {model}` dan `nsfw: {model}` menerima objek apa pun dengan metode `classify()`, misalnya dari `@tensorflow-models/toxicity` dan `nsfwjs` |
| `results.arbitrary` mencantumkan setiap pola yang cocok                                    | Hanya mencantumkan aturan yang cukup kuat untuk menandai spam dengan sendirinya; semua aturan ada di `result.tests`                                                          |
| Jawaban ya atau tidak                                                                      | `result.score`, `result.action` (`accept`, `tag`, atau `reject`), dan `result.tests`, masing-masing dengan poin dan alasan                                                   |
| `isSpam` ditentukan oleh pengklasifikasi atau satu pemeriksaan mana pun                    | `isSpam` berarti skor 5 atau lebih; ambang batas dan poin dapat diubah                                                                                                       |
| Pemeriksaan reputasi terhadap endpoint Forward Email                                       | Layanan reputasi generik, nonaktif kecuali `reputation.apiUrl` diatur                                                                                                        |

### Baru

* [Model bahasa](llm.md) untuk kasus yang meragukan, lokal atau yang di-hosting.
* SPF, DKIM, DMARC, dan ARC; daftar blokir DNS; resolver penyaring Cloudflare.
* Pemeriksaan lampiran berdasarkan isi: file executable yang disamarkan, arsip, makro, PDF aktif.
* [Milter, HTTP API, server TCP, dan server spamd](mail-servers.md), serta [baris perintah](cli.md).
* Pelatihan, evaluasi, dan pembelajaran dari laporan, melalui baris perintah atau API.
