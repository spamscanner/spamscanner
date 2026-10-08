<!-- source: 60f00f92b5aa -->

# Güvenlik ve gizlilik

Spam Scanner, özel olan postayı, düşmanca niyetli olabilecek göndericilerden okur. Bu sayfa herhangi bir yere ne gönderdiğini ve okuduklarını nasıl ele aldığını listeler.


## Makineden ne çıkar

Varsayılan olarak tek bir şey: bir iletideki **bağlantıların ana makine adları**, Cloudflare'in filtreleme yapan çözümleyicileri olan 1.1.1.2 ve 1.0.0.2'de (kötü amaçlı yazılım ve kimlik avı) ve 1.1.1.3 ve 1.0.0.3'te (ayrıca yetişkin içerik) sorgulanır. Bunlar `example.com` gibi adlar için sıradan DNS sorgularıdır; iletinin veya adreslerinin hiçbir parçası gönderilmez. Bunları `phishing: {cloudflare: false}` veya `--no-cloudflare` ile, yalnızca yetişkin içerik denetimini ise `phishing: {adult: false}` ile kapatın.

Geri kalan her şey yapılandırılana kadar kapalıdır:

| Denetim             | Gönderdiği                                                                        | Gönderildiği yer                                                                  |
| ------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `authentication`    | Göndericinin SPF, DKIM, DMARC ve ARC kayıtları için DNS sorguları                 | Çözümleyiciniz veya `dnsServers`                                                  |
| `dnsbl`             | İstemcinin ters çevrilmiş IP adresi ve bağlantı alan adları, DNS sorguları olarak | Engelleme listelerinin ad sunucuları, çözümleyiciniz veya `dns.servers` üzerinden |
| `llm`               | Uzak sağlayıcılar için kişisel verileri çıkarılmış bir ileti özeti                | Belirttiğiniz dil modeli sunucusu ([gizlilik](llm.md#privacy))                    |
| `reputation.apiUrl` | Göndericinin IP adresi, alan adı ve adresi                                        | Belirttiğiniz hizmet                                                              |
| `clamav`            | Ekler                                                                             | Kendi clamd'niz, soketi üzerinden                                                 |

Telemetri, güncelleme denetimi ve çalışma zamanında indirme yoktur. Model paketin içinde gelir.


## Neleri saklar

İstenmedikçe hiçbir şeyi. Taramalar günlüğe kaydedilmez veya saklanmaz. `learn()` sınıflandırıcıyı bellekte değiştirir; sınıflandırıcı diske yalnızca `saveModel()`, `spamscanner learn` veya sunucuların `--out` seçeneğiyle yazılır. Bir model dosyası sözcükleri veya ileti metnini değil, karma değerine dönüştürülmüş özellik sayılarını içerir.

Dil modeli yanıtları, gönderilen içeriğin karma değeriyle anahtarlanarak bellekte önbelleğe alınır; böylece aynı iletinin tekrarlanan kopyaları için yalnızca bir kez sorulur. DNS yanıtları on dakika boyunca bellekte önbelleğe alınır.


## Düşmanca girdi

* Ekler baytlarından tanınır; hiçbir zaman yürütülmez veya başka bir programla açılmaz. ZIP arşivleri, girdi sayısına bir sınır konarak merkezi dizinlerinden okunur; iç içe arşivler açılmaz.
* Gövde metni `maxLength` (100.000 karakter) değerine kadar okunur ve sunucular 25 MB'a kadar iletileri kabul eder.
* Her ağ denetiminin bir zaman aşımı vardır (`timeout`, varsayılan olarak 10 saniye). Başarısız olan veya zaman aşımına uğrayan bir denetim atlanır ve tarama onsuz tamamlanır.
* Bir iletide zaten bulunan `X-Spam-*` üst bilgileri milter, içerik filtresi ve `--headers` tarafından kaldırılır; böylece göndericiler kendi postalarını temiz olarak işaretleyemez.
* Microsoft'un spam kararı üst bilgilerine yalnızca ileti doğrudan Microsoft sunucularından geldiğinde güvenilir ve bir iletinin nereden geldiğine karar vermek için Received üst bilgileri hiçbir zaman kullanılmaz.
* Yapay zekâ filtrelerine hitap eden metin spam olarak puanlanır ve dil modeline iletinin talimat değil veri olduğu söylenir. [İstem enjeksiyonu](llm.md#prompt-injection)


## Sunucular

Milter, HTTP, TCP ve spamd sunucuları, `--host` aksini belirtmedikçe 127.0.0.1 adresini dinler. HTTP API belirtecini sabit sürede karşılaştırır ve belirteç olmadan `/learn` isteğini reddeder. Hiçbiri TLS konuşmaz: onlara bir ağ üzerinden ulaşmak için özel bir ağ, bir SSH tüneli veya TLS'li bir ters vekil sunucu kullanın.

Onları ayrıcalıksız bir kullanıcıyla çalıştırın. [Postfix kılavuzundaki systemd birimi](postfix.md#1-run-the-milter) olağan sağlamlaştırma ayarlarını ekler.


## Güvenlik açığı bildirmek

Güvenlik sorunlarını herkese açık sorun kayıtlarında değil, [GitHub'ın güvenlik açığı bildirme özelliği](https://github.com/spamscanner/spamscanner/security/advisories/new) üzerinden gizli olarak bildirin.
