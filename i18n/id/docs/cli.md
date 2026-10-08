<!-- source: a59bc5927d86 -->

# Baris perintah

```text
spamscanner <command> [options]
```

| Perintah                                   | Fungsinya                                                                         |
| ------------------------------------------ | --------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Memindai pesan dari file atau input standar                                       |
| `filter -f <sender> -- <recipients...>`    | Content filter Postfix: memindai input standar, menambahkan header, meneruskannya |
| `milter`                                   | Milter untuk Postfix dan Sendmail, port 7831                                      |
| `http`                                     | HTTP API, port 7832                                                               |
| `server`                                   | Server TCP biasa, port 7830                                                       |
| `spamd`                                    | Server spamd yang kompatibel dengan SpamAssassin, port 783                        |
| `train`                                    | Melatih model dari file mbox, Maildir, folder, atau dataset                       |
| `eval`                                     | Mengukur model pada email berlabel                                                |
| `learn spam\|ham [file\|-] --model <file>` | Mengajari model satu pesan                                                        |
| `llm-test`                                 | Memeriksa pengaturan model bahasa dengan tiga pesan contoh                        |
| `models`                                   | Menampilkan daftar model terbuka yang direkomendasikan                            |
| `version`, `help`                          |                                                                                   |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Opsi                       | Arti                                                         |
| -------------------------- | ------------------------------------------------------------ |
| `--json`                   | Mencetak hasil lengkap sebagai JSON                          |
| `--headers`                | Mencetak pesan dengan header `X-Spam-*` yang ditambahkan     |
| `--subject-tag <tag>`      | Juga menambahkan awalan pada subjek spam                     |
| `--verbose`                | Menampilkan setiap tes, dan petunjuk terkuat pengklasifikasi |
| `--threshold <n>`          | Skor saat email dianggap spam (bawaan 5)                     |
| `--reject-threshold <n>`   | Skor saat email ditolak (bawaan 15)                          |
| `--model <file>`           | File model sebagai pengganti model bawaan                    |
| `--no-classifier`          | Tidak menggunakan pengklasifikasi                            |
| `--config <file>`          | File JSON berisi [opsi pustaka](api.md#options)              |
| `--allow-language <codes>` | Bahasa yang diterima, misalnya `en,de,fr`                    |

Kode keluar: 0 ham, 1 spam, 2 galat.

### Sesi SMTP

| Opsi                | Arti                                              |
| ------------------- | ------------------------------------------------- |
| `--ip <address>`    | Alamat IP klien yang mengirim pesan               |
| `--hostname <name>` | Nama reverse DNS klien yang terverifikasi         |
| `--helo <name>`     | Nama yang diberikan klien dalam HELO atau EHLO    |
| `--from <address>`  | Pengirim envelope (MAIL FROM)                     |
| `--to <address>`    | Penerima envelope; ulangi untuk beberapa penerima |

### Pemeriksaan

| Opsi                  | Arti                                                                          |
| --------------------- | ----------------------------------------------------------------------------- |
| `--auth`              | Memeriksa SPF, DKIM, DMARC, dan ARC (memerlukan `--ip`)                       |
| `--dnsbl <zone>`      | Daftar blokir IP, misalnya `zen.spamhaus.org`; dapat diulang                  |
| `--uribl <zone>`      | Daftar blokir domain untuk tautan, misalnya `dbl.spamhaus.org`; dapat diulang |
| `--dns-server <ip>`   | Name server untuk pemeriksaan DNS; dapat diulang                              |
| `--no-cloudflare`     | Tidak menanyakan tautan ke resolver penyaring Cloudflare                      |
| `--clamav [socket]`   | Memindai lampiran dengan clamd, di soket bawaannya atau soket yang diberikan  |
| `--allowlist <value>` | Selalu menerima alamat IP, domain, atau alamat ini; dapat diulang             |
| `--denylist <value>`  | Selalu menolak alamat IP, domain, atau alamat ini; dapat diulang              |

### Model bahasa

| Opsi                                                       | Arti                                                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini`, dan lainnya ([daftar](llm.md#providers))   |
| `--llm-model <name>`                                       | Model, misalnya `qwen3.5:4b` atau `claude-haiku-4-5`                                  |
| `--llm-url <url>`                                          | URL dasar, misalnya `http://10.0.0.5:11434`                                           |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Mengubah satu bagian dari URL penyedia                                                |
| `--llm-api-key <key>`                                      | Kunci API; lihat juga variabel lingkungan di bawah                                    |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header`, atau `none`                      |
| `--llm-auth-header <name>`                                 | Header untuk kunci, dengan `--llm-auth header`                                        |
| `--llm-username`, `--llm-password`                         | Untuk `--llm-auth basic`                                                              |
| `--llm-header "Name: value"`                               | Header permintaan tambahan; dapat diulang                                             |
| `--llm-mode <mode>`                                        | `auto` (hanya kasus yang meragukan, bawaan) atau `always`                             |
| `--llm-timeout <ms>`                                       | Bawaan 30000                                                                          |
| `--llm-policy <text>`                                      | Aturan tambahan untuk model, misalnya "Kami tidak pernah mengirim tagihan"            |
| `--llm-redact`, `--no-llm-redact`                          | Menghapus data pribadi terlebih dahulu; aktif secara bawaan untuk penyedia jarak jauh |


## filter

[Content filter Postfix](postfix.md#content-filter). Perintah ini membaca pesan dari input standar, menambahkan header `X-Spam-*`, dan meneruskannya ke sendmail dengan envelope yang sama.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Opsi                  | Arti                                                                 |
| --------------------- | -------------------------------------------------------------------- |
| `--sendmail <path>`   | Bawaan `/usr/sbin/sendmail`                                          |
| `--subject-tag <tag>` | Menambahkan awalan pada subjek spam                                  |
| `--reject`            | Memantulkan email yang mencapai ambang tolak alih-alih meneruskannya |
| `--discard`           | Membuang email yang mencapai ambang tolak alih-alih meneruskannya    |

Kode keluar mengikuti konvensi sendmail, yang dibaca Postfix: 0 terkirim (atau dibuang), 64 tidak ada penerima yang diberikan, 69 ditolak sebagai spam (Postfix memantulkannya), 75 kegagalan apa pun, sehingga Postfix menyimpan pesan dan mencoba lagi nanti.


## milter, http, server, dan spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Port 783 adalah port yang dipakai klien SpamAssassin secara bawaan. Port di bawah 1024 memerlukan root atau capability `CAP_NET_BIND_SERVICE`; gunakan port lain, seperti `--port 7833`, dan beri tahu kliennya.

| Opsi                  | Arti                                                                            |
| --------------------- | ------------------------------------------------------------------------------- |
| `--port <n>`          | Port TCP                                                                        |
| `--host <ip>`         | Alamat yang didengarkan (bawaan 127.0.0.1)                                      |
| `--socket <path>`     | Mendengarkan di soket Unix sebagai gantinya                                     |
| `--reject`            | Milter: menolak email yang mencapai ambang tolak                                |
| `--reject-code <n>`   | Milter: 451, coba lagi nanti (bawaan), atau 550                                 |
| `--quarantine`        | Milter: menahan spam di karantina server email                                  |
| `--name <hostname>`   | Milter: nama server ini di Authentication-Results                               |
| `--token <secret>`    | HTTP: mensyaratkan `Authorization: Bearer <secret>`; diperlukan untuk `/learn`  |
| `--allow-tell`        | spamd: menerima permintaan TELL (`spamc -L spam`) untuk pembelajaran            |
| `--out <file>`        | HTTP dan spamd: menyimpan hasil pembelajaran ke file model ini                  |
| `--subject-tag <tag>` | Milter dan spamd: menambahkan awalan pada subjek spam                           |
| `--verbose`           | Milter: mencatat setiap pemindaian. Server TCP: menjawab dengan satu baris teks |

Opsi pemindaian di atas juga berlaku untuk server. [Milter](postfix.md#milter), [HTTP API, server TCP, dan spamd](http-api.md).


## train, eval, dan learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Opsi                                            | Arti                                                                    |
| ----------------------------------------------- | ----------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: file mbox, Maildir, atau folder berisi file `.eml`; dapat diulang |
| `--ham <path>`                                  | Ham, sama seperti di atas; dapat diulang                                |
| `--dataset <file>`                              | File CSV atau JSON Lines dengan kolom teks dan label; dapat diulang     |
| `--text-column <name>`, `--label-column <name>` | Nama kolom, jika tidak terdeteksi                                       |
| `--out <file>`                                  | Lokasi penulisan model (bawaan `spamscanner-model.json`)                |
| `--merge`                                       | Mulai dari model bawaan (atau `--model`) alih-alih model kosong         |

`learn` memperbarui file model di tempat, dan membuatnya dari model bawaan pada kali pertama. [Pelatihan](training.md)


## llm-test dan models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` mengirim satu pesan biasa dan dua penipuan, dalam bahasa Inggris dan Italia, ke model, mencetak vonisnya, dan keluar dengan kode 0 hanya jika ketiganya benar.


## File konfigurasi

`--config file.json` (atau variabel lingkungan `SPAMSCANNER_CONFIG`) memuat [opsi pustaka](api.md#options). Opsi baris perintah menimpa isi file.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Variabel lingkungan

| Variabel                                                                                                                                                                                                                                             | Arti                                                   |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | File konfigurasi                                       |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | File model yang dipakai sebagai pengganti model bawaan |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | Token untuk HTTP API                                   |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | Kunci API untuk penyedia model bahasa mana pun         |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Kunci milik masing-masing penyedia                     |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | Log debug                                              |
