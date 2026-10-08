<!-- source: 1151282f29d3 -->

# Diğer posta sunucuları

Spam Scanner dört protokol konuşur; bu nedenle çoğu posta yazılımı ona özel bir eklenti olmadan onu kullanabilir:

| Protokol | Komut                                    | Kullananlar                                               |
| -------- | ---------------------------------------- | --------------------------------------------------------- |
| Milter   | `spamscanner milter`                     | Postfix, Sendmail, OpenSMTPD (filter-milter ile)          |
| spamd    | `spamscanner spamd`                      | spamc, Exim, Haraka ve SpamAssassin için yazılmış her şey |
| HTTP     | `spamscanner http`                       | Betikler, web kancaları, özel MTA'lar ve hizmetler        |
| Pipe     | `spamscanner scan`, `spamscanner filter` | Postfix pipe'ları, procmail, maildrop, cron görevleri     |

[Postfix ve Sendmail](postfix.md) için ayrı bir sayfa vardır.


## SpamAssassin'in spamd'si için doğrudan yerine geçen bir sunucu

`spamscanner spamd`, SpamAssassin'in spamd protokolüne yanıt verir: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` ve `--allow-tell` ile `TELL`. SpamAssassin için yazılmış yazılımlar değişiklik yapılmadan çalışır; `spamd` hizmetini durdurun ve Spam Scanner'ı aynı bağlantı noktasında başlatın.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

spamc ile:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

Deponun uçtan uca testleri SpamAssassin'in kendi spamc istemcisini ona karşı çalıştırır.


## Exim

Exim'in `spam` ACL koşulu spamd ile konuşur. Ana yapılandırmada:

```text
spamd_address = 127.0.0.1 783
```

DATA ACL'de (Debian'ın exim4 paketinde `acl_check_data`):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` geçici bir 4xx hatasıyla yanıt verir; böylece göndericiler yeniden dener ve bir hata düzeltilebilir. Sonuçlar doğru görünmeye başladığında kalıcı geri çevirme için bunu `deny` olarak değiştirin.


## Haraka

Haraka'nın `spamassassin` eklentisi spamd ile konuşur. Eklentiyi `config/plugins` içinde etkinleştirin ve `config/spamassassin.ini` içinde şunları ayarlayın:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: Junk klasörü ve öğrenme

Bir Sieve kuralı etiketlenmiş postayı Junk klasörüne taşır:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

IMAPSieve ile bir iletiyi Junk klasörüne taşımak veya oradan çıkarmak modele öğretim yapabilir. HTTP API'yi bir belirteç ve bir model dosyasıyla başlatın:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

ve milter'ı veya spamd sunucusunu `--model /var/lib/spamscanner/model.json` (veya `SPAMSCANNER_MODEL`) ile aynı modele yönlendirin. Öğrenilenleri alması için onu zaman zaman yeniden başlatın. `sieve_pipe` tarafından çalıştırılan bir betik iletiyi gönderir:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

Dovecot'un [spam bildirme kılavuzu](https://doc.dovecot.org/main/core/config/spam_reporting.html) kurulumun geri kalanını gösterir; bu, bir betikten öğrenen her spam filtresi için aynıdır.


## procmail ve maildrop

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

`scan --headers` spam için 1 koduyla çıkar. Yukarıdaki kurallarla procmail ve maildrop çıkış kodunu değil, çıktıyı kullanır.


## HTTP API

HTTP isteği gönderebilen her program postayı tarayabilir:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[HTTP API](http-api.md) tüm uç noktaları listeler.


## Bir Node.js posta sunucusunun içinde

[smtp-server](https://nodemailer.com/extras/smtp-server/), Haraka eklentileri veya başka herhangi bir Node.js sunucusuyla kitaplığı doğrudan çağırın:

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

smtp-server'dan gelen `session.envelope`, Spam Scanner'ın okuduğu `mailFrom` ve `rcptTo` yapısına zaten sahiptir.
