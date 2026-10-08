<!-- source: f1043eb5fc58 -->

# Postfix ve Sendmail

Spam Scanner, Postfix'e iki şekilde bağlanır:

* **Milter olarak** (önerilen). Postfix her ileti için SMTP oturumu sırasında, iletiyi kabul etmeden önce ona danışır. Spam 4xx veya 5xx yanıtıyla geri çevrilebilir; böylece onunla sizin sunucunuz değil, gönderen sunucu ilgilenir. Sendmail de aynı protokolü kullanır.
* **İçerik filtresi olarak.** Postfix iletiyi kabul eder ve `spamscanner filter` komutuna aktarır; bu komut üst bilgileri ekler ve iletiyi sendmail ile geri verir. SMTP oturumu sırasında hiçbir şey geri çevrilmez.

İkisi de her iletiye şu üst bilgileri ekler:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

İletide zaten bulunan `X-Spam-*` üst bilgileri önce kaldırılır; böylece bir gönderici kendi postasını temiz olarak işaretleyemez.


## Milter

### 1. Milter'ı çalıştırın

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

`--reject` ile reddetme eşiğindeki (15 puan) iletiler `451 4.7.1 Message rejected as spam` ile geri çevrilir. 451 geçici bir hatadır: gönderici daha sonra yeniden dener ve bir hata bir ayar değiştirilerek hâlâ düzeltilebilir. Sonuçlar doğru görünmeye başladığında kalıcı geri çevirme için `--reject-code 550` kullanın. `--quarantine` ile spam bunun yerine Postfix'in bekletme kuyruğuna (hold queue) gider.

`/etc/systemd/system/spamscanner-milter.service` içinde bir systemd hizmeti olarak:

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

### 2. Postfix'i ona yönlendirin

`/etc/postfix/main.cf` içinde:

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

`smtpd_milters` SMTP üzerinden gelen postayı kapsar. `sendmail` komutuyla gönderilen postanın da taranması gerekmiyorsa `non_smtpd_milters` ayarını boş bırakın.

### 3. Test edin

[swaks](https://www.jetmore.org/john/code/swaks/) test iletileri gönderir. GTUBE, her spam filtresinin spam olarak kabul ettiği bir test dizisidir:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

`--reject` olmadan ileti `X-Spam-Flag: YES` ve etiketlenmiş bir konuyla teslim edilir. `--reject` ile swaks 451 veya 550 yanıtını gösterir.


## İçerik filtresi

Postanın SMTP oturumu sırasında hiçbir zaman geri çevrilmemesi gerektiğinde veya milter kullanamayan bir sunucu için bunu kullanın.

`/etc/postfix/master.cf` içinde bir filtre hizmeti ekleyin ve onu SMTP dinleyicisinde kullanın:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix filtreyi neredeyse boş bir ortamla çalıştırır; bu nedenle `argv` Node.js'i ve betiği tam yollarıyla belirtir (`command -v node` ve `npm root --global` bu yolları gösterir). Ardından:

```sh
sudo postfix reload
```

Filtre iletiyi `sendmail -G -i` ile geri verir. Bu şekilde gönderilen posta `smtp` dinleyicisinden yeniden geçmez, bu yüzden iki kez filtrelenmez.

Çıkış kodları Postfix'e ne olduğunu bildirir: 0 teslim edildi, 69 geri çevrildi (`--reject` ile: Postfix iletiyi göndericiye geri döndürür), 75 geçici hata (Postfix iletiyi saklar ve yeniden dener). Her tarama veya teslimat hatası 75'tir; böylece bozuk bir ayar hiçbir zaman postayı kaybettirmez veya geri döndürmez.


## Sendmail

`sendmail.mc` içinde:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T`, milter kullanılamazken Sendmail'in geçici hatayla yanıt vermesini sağlar; postayı bunun yerine filtrelenmeden kabul etmek için kaldırın. `sendmail.cf` dosyasını yeniden oluşturun ve Sendmail'i yeniden başlatın.


## Spamı Junk klasörüne ayırmak

Yalnızca etiketlemek spamı gelen kutusuna teslim eder. Dovecot ile bir Sieve kuralı onu taşır:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Diğer posta sunucuları](mail-servers.md) Dovecot, Exim, Haraka ve procmail'i ele alır; [eğitim](training.md#learning-from-reports) ise kullanıcıların Junk klasörüne taşıdığı ve oradan çıkardığı postadan nasıl öğrenileceğini gösterir.


## Test edildi

Deponun uçtan uca testleri gerçek bir Postfix çalıştırır: ham üst bilgileriyle teslim edilir, sahte bir `X-Spam-Flag` kaldırılır, spam etiketlenir, GTUBE SMTP oturumu sırasında 550 ile geri çevrilir ve içerik filtresi ikinci bir bağlantı noktasında postayı etiketler. `scripts/e2e-postfix.sh` bu Postfix'i kurar, `test/e2e/postfix.test.js` ise postayı gönderir.
