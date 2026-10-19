<!-- source: 665fbc0d5adc -->

# HTTP API, TCP sunucusu ve spamd


## HTTP API

```sh
spamscanner http --port 7832    # token in SPAMSCANNER_TOKEN
```

HTTP API'si belirtecini `SPAMSCANNER_TOKEN` ortam değişkeninden okur. `--token` da çalışır, ancak makinedeki diğer kullanıcılar komut satırı seçeneklerini `ps` ile görebilir.

`--host` aksini belirtmedikçe 127.0.0.1 adresini dinler. Bir belirteç ayarlandığında `/health` dışındaki her istek `Authorization: Bearer <token>` gerektirir. Makinenin dışına açmadan önce TLS'li bir ters vekil sunucunun arkasına koyun.

| Yöntem ve yol      | Gövde     | Yanıt                                                            |
| ------------------ | --------- | ---------------------------------------------------------------- |
| `GET /health`      |           | `{"ok": true, "version": "..."}`                                 |
| `POST /scan`       | Ham ileti | JSON olarak [tarama sonucu](api.md#the-result)                   |
| `POST /check`      | Ham ileti | `X-Spam-*` üst bilgileri eklenmiş ileti, `message/rfc822` olarak |
| `POST /learn/spam` | Ham ileti | `{"ok": true, "learned": "spam"}`; belirteç gerektirir           |
| `POST /learn/ham`  | Ham ileti | `{"ok": true, "learned": "ham"}`; belirteç gerektirir            |

Sorgu parametreleri SMTP oturumunu tanımlar:

| Parametre    | Anlamı                                                        |
| ------------ | ------------------------------------------------------------- |
| `ip`         | İstemcinin IP adresi                                          |
| `hostname`   | İstemcinin doğrulanmış ters DNS adı                           |
| `helo`       | İstemcinin HELO veya EHLO adı                                 |
| `from`       | Zarf göndericisi                                              |
| `to`         | Bir alıcı; tekrarlayın veya birkaç alıcıyı virgülle ayırın    |
| `verbose=1`  | `/scan`: sözcük listesini ve konuyu da döndürür               |
| `subjectTag` | `/check`: spamın konusunun başına ekler, örneğin `%5BSPAM%5D` |

`ip` olmadan SPF, DKIM, DMARC, ARC ve IP engel listesi denetimleri (`--auth`, `--dnsbl`) atlanır.

`/check` ayrıca `X-Spam-Flag`, `X-Spam-Score` ve `X-Spam-Action` değerlerini yanıt üst bilgileri olarak döndürür; böylece bir istemci iletiyi ayrıştırmadan karar verebilir.

25 MiB'tan (`--max-size`) büyük iletiler, `Content-Length` boyutu verdiğinde gövde okunmadan önce, `413` alır. Başarısız olan bir tarama `{"error": "..."}` ile birlikte `500` alır. Sunucu aynı anda en fazla 200 isteği (`--max-connections`), ardışık (pipelined) olanlar dahil, işler; fazlası `Retry-After: 1` ile birlikte `503` alır.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

`--out model.json` ile, `/learn` aracılığıyla öğretilenler her istekten sonra o dosyaya kaydedilir. Bu seçenek olmadan öğrenilenler sunucu yeniden başlatılana kadar geçerlidir.

Node.js'ten:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Python'dan:

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


## TCP sunucusu

```sh
spamscanner server --port 7830
```

Ham iletiyi gönderin, bağlantının gönderme tarafını kapatın ve tek satırlık JSON'u okuyun:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

`--verbose` ile yanıt bunun yerine bir metin satırıdır: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` veya `HAM -2.5/5.0 BAYES_00`.

TCP sunucusu istemcinin IP adresini bilmez, bu yüzden `--auth` ve `--dnsbl` etkisizdir. Yalnızca istemci gönderme tarafını kapattığında yanıt verir (`nc -N` ya da `nc -q 1` veya bir sokette `shutdown(SHUT_WR)`); onu açık tutan bir istemci yanıt almaz ve bağlantı 60 saniye veri gelmezse kapatılır. 25 MiB'tan (`--max-size`) büyük iletilere hatayla yanıt verir.


## spamd

```sh
spamscanner spamd --port 783
```

spamc, Exim, Haraka ve diğer SpamAssassin istemcileri için SpamAssassin uyumlu bir sunucu. [Exim ve Haraka'yı kurmak](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Komut           | Yanıt                                                                |
| --------------- | -------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                            |
| `SYMBOLS`       | Karar ve tetiklenen testlerin adları                                 |
| `REPORT`        | Karar ve testler, puanlar ve nedenlerden oluşan bir tablo            |
| `REPORT_IFSPAM` | `REPORT` gibi, ham için boş bir raporla                              |
| `PROCESS`       | Karar ve `X-Spam-*` üst bilgileri eklenmiş ileti                     |
| `HEADERS`       | Karar ve iletinin `X-Spam-*` üst bilgileri eklenmiş üst bilgi bloğu  |
| `PING`          | `PONG`                                                               |
| `SKIP`          | Hiçbir şey                                                           |
| `TELL`          | `--allow-tell` ile spam veya ham öğrenir; `--out` dosyasına kaydeder |

Sıkıştırılmış istekler (`Compress: zlib`) reddedilir.

spamd istemcileri de istemcinin IP adresini göndermez, bu yüzden `--auth` ve `--dnsbl` etkisizdir. 25 MiB'tan (`--max-size`) büyük bir ileti `65` (`EX_DATAERR`), `Content-length` değerinden kısa bir ileti `76` (`EX_PROTOCOL`) alır ve 60 saniye boyunca hiçbir şey göndermeyen bağlantılar kapatılır.
