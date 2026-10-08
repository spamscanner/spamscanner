<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner, açık kaynaklı ve gizlilik odaklı e-posta hizmeti [Forward Email](https://forwardemail.net) tarafından kendi posta sunucuları için geliştirildi. Forward Email ileti içeriğinin günlüğünü tutmaz; bu yüzden dışarıdaki hiçbir filtreleme hizmeti işe yaramazdı: filtrenin kendi sunucularında çalışması ve postayı bir insan okumadan her kararını açıklaması gerekiyordu.

Bu sayfa, Forward Email'inki gibi bir posta sunucusunun onu nasıl kullandığını ve Spam Scanner 5 veya 6 için yazılmış kodda nelerin değiştiğini gösterir.


## Gelen posta sunucusunda

Forward Email postayı [smtp-server](https://nodemailer.com/extras/smtp-server/) ile alır. Bunun üzerine kurulmuş her sunucu için kalıp şöyledir:

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

`scanner.scan()` SMTP akışını doğrudan kabul eder. [mailauth](https://github.com/postalsys/mailauth) sonuçları zaten elinizdeyse `authentication` seçeneğini atlayın ve yalnızca IP adresini verin.

421 veya 451 yanıtı, gönderen sunucunun iletiyi kuyruğa almasını ve daha sonra yeniden denemesini sağlar. Yeni reddetme kuralları geçici bir kodla başlayabilir ve sonuçları denetlendikten sonra arada posta kaybetmeden 550'ye geçebilir.


## 5 veya 6 sürümünden yükseltme

Sürüm 7 baştan yeniden yazılmıştır. Oluşturucu, `scan()` ve sürüm 5 ve 6 kodunun okuduğu sonuç alanları hâlâ çalışır; sınıflandırıcı, model ve isteğe bağlı TensorFlow denetimleri değişti.

### Aynı kalanlar

* `new SpamScanner(options)` ve `await scanner.scan(source)`.
* `require('spamscanner')` sınıfı döndürür ve `import SpamScanner from 'spamscanner'` çalışır.
* `result.isSpam`, `result.message` ve `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` ile `.idnHomographAttack`.
* `results.phishing`, `.executables`, `.arbitrary` ve `.viruses` içindeki her öğe önceki ile aynı türde bir ileti dizesine dönüşür (`String(item)`, şablon dizgileri, `message.includes('adult-related content')`). Bunlar artık `type`, `message` ve ayrıntılar içeren nesnelerdir.
* `getTokensAndMailFromSource()`, `getClassification()` ve `getTokens()`.
* Şu seçenekler yeni adlarına eşlenir: `clamscan` → `clamav`, `enableMacroDetection: false` → `macros: false`, `enableArbitraryDetection: false` → `arbitrary: false`, `authOptions` ile birlikte `enableAuthentication` → `authentication` ve `session`, `reputationOptions.apiUrl` ile birlikte `enableReputation` → `reputation`, `strictIDNDetection` → `phishing.homograph.strictMode` ve `allowlist` ile `denylist`. `logger` ve `memoize` kabul edilir ve yok sayılır.

### Değişenler

| Önce                                                                                  | Şimdi                                                                                                                                                                    |
| ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `scan('path/to/file.eml')` dosyayı okuyordu                                           | Dize ileti metnidir. `scanFile(path)` kullanın veya bir Buffer verin                                                                                                     |
| Artık yüklenemeyen, sözcüklere dayalı saf Bayes modeli (`classifier.json`)            | Yeni bir sınıflandırıcı ve model biçimi; `spamscanner train` ile yeniden eğitin ([eğitim](training.md))                                                                  |
| Zehirlilik ve NSFW denetimleri ilk kullanımda TensorFlow modellerini ağdan yüklüyordu | Kendi modelinizi getirin: `toxicity: {model}` ve `nsfw: {model}`, `classify()` yöntemi olan herhangi bir nesneyi alır; örneğin `@tensorflow-models/toxicity` ve `nsfwjs` |
| `results.arbitrary` eşleşen her kalıbı listeliyordu                                   | Yalnızca tek başına spam işaretleyecek kadar güçlü kuralları listeler; tüm kurallar `result.tests` içindedir                                                             |
| Evet veya hayır yanıtı                                                                | Her birinin puanı ve nedeni olan `result.score`, `result.action` (`accept`, `tag` veya `reject`) ve `result.tests`                                                       |
| `isSpam` kararını sınıflandırıcı veya herhangi tek bir denetim veriyordu              | `isSpam` 5 veya daha yüksek puan demektir; eşikler ve puanlar değiştirilebilir                                                                                           |
| Bir Forward Email uç noktasına karşı itibar denetimleri                               | `reputation.apiUrl` ayarlanmadıkça kapalı olan genel bir itibar hizmeti                                                                                                  |

### Yeni olanlar

* Kararsız kalınan durumlar için yerel veya barındırılan [dil modelleri](llm.md).
* SPF, DKIM, DMARC ve ARC; DNS engelleme listeleri; Cloudflare'in filtreleme yapan çözümleyicileri.
* İçeriğe göre ek denetimleri: kamufle edilmiş yürütülebilir dosyalar, arşivler, makrolar, etkin içerikli PDF'ler.
* Bir [milter, HTTP API, TCP sunucusu ve spamd sunucusu](mail-servers.md) ve bir [komut satırı](cli.md).
* Komut satırından veya API'den eğitim, değerlendirme ve bildirimlerden öğrenme.
