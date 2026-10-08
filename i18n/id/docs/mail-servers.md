<!-- source: 1151282f29d3 -->

# Server email lain

Spam Scanner mendukung empat protokol, sehingga sebagian besar perangkat lunak email dapat menggunakannya tanpa plugin khusus:

| Protokol | Perintah                                 | Digunakan oleh                                                   |
| -------- | ---------------------------------------- | ---------------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (dengan filter-milter)              |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka, dan apa pun yang ditulis untuk SpamAssassin |
| HTTP     | `spamscanner http`                       | Skrip, webhook, MTA dan layanan kustom                           |
| Pipe     | `spamscanner scan`, `spamscanner filter` | Pipe Postfix, procmail, maildrop, cron job                       |

[Postfix dan Sendmail](postfix.md) memiliki halaman tersendiri.


## Pengganti langsung untuk spamd SpamAssassin

`spamscanner spamd` menjawab protokol spamd milik SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING`, dan, dengan `--allow-tell`, `TELL`. Perangkat lunak yang ditulis untuk SpamAssassin berfungsi tanpa perubahan; hentikan `spamd` dan jalankan Spam Scanner di port yang sama.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

Dengan spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Tes end-to-end repositori menjalankan spamc milik SpamAssassin sendiri terhadapnya.


## Exim

Kondisi ACL `spam` di Exim berkomunikasi dengan spamd. Dalam konfigurasi utama:

```text
spamd_address = 127.0.0.1 783
```

Dalam DATA ACL (`acl_check_data` di exim4 Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` menjawab dengan galat sementara 4xx, sehingga pengirim mencoba lagi dan kesalahan dapat diperbaiki. Ubah menjadi `deny` untuk penolakan permanen setelah hasilnya terlihat benar.


## Haraka

Plugin `spamassassin` di Haraka berkomunikasi dengan spamd. Aktifkan di `config/plugins` dan atur, di `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: folder Junk dan pembelajaran

Sebuah aturan Sieve memindahkan email yang ditandai ke Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

Dengan IMAPSieve, memindahkan pesan ke dalam atau keluar dari Junk dapat mengajari model. Jalankan HTTP API dengan token dan file model:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

lalu arahkan server milter atau spamd ke model yang sama dengan `--model /var/lib/spamscanner/model.json` (atau `SPAMSCANNER_MODEL`). Mulai ulang sesekali agar hasil pembelajaran terbaca. Skrip yang dijalankan oleh `sieve_pipe` mengirim pesan:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

[Panduan pelaporan spam](https://doc.dovecot.org/main/core/config/spam_reporting.html) Dovecot menunjukkan sisa penyiapannya, yang sama untuk filter spam apa pun yang belajar dari skrip.


## procmail dan maildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop:

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

`scan --headers` keluar dengan kode 1 untuk spam. Dengan aturan di atas, procmail dan maildrop memakai keluarannya, bukan kode keluarnya.


## HTTP API

Program apa pun yang dapat membuat permintaan HTTP dapat memindai email:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API](http-api.md) mencantumkan setiap endpoint.


## Di dalam server email Node.js

Dengan [smtp-server](https://nodemailer.com/extras/smtp-server/), plugin Haraka, atau server Node.js lainnya, panggil pustaka secara langsung:

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({authentication: true});

// smtp-server's onData handler
async function onData(stream, session, callback) {
  const result = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (result.action === 'reject') {
    const error = new Error('Message rejected as spam');
    error.responseCode = 451;
    return callback(error);
  }

  // Deliver, with result.isSpam deciding the folder.
  callback();
}
```

`session.envelope` dari smtp-server sudah memiliki bentuk `mailFrom` dan `rcptTo` yang dibaca Spam Scanner.
