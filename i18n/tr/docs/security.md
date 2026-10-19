<!-- source: 1d7373f991c2 -->

# Güvenlik ve gizlilik

Spam Scanner, özel olan postayı, düşmanca niyetli olabilecek göndericilerden okur. Bu sayfa herhangi bir yere ne gönderdiğini ve okuduklarını nasıl ele aldığını listeler.


## Makineden ne çıkar

Varsayılan olarak tek bir şey: bir iletideki **bağlantıların ana makine adları**, Cloudflare'in filtreleme yapan çözümleyicileri olan 1.1.1.2 ve 1.0.0.2'de (kötü amaçlı yazılım ve kimlik avı) ve 1.1.1.3 ve 1.0.0.3'te (ayrıca yetişkin içerik) sorgulanır. Bunlar `example.com` gibi adlar için sıradan DNS sorgularıdır; iletinin veya adreslerinin hiçbir parçası gönderilmez. Bunları `phishing: {cloudflare: false}` veya `--no-cloudflare` ile, yalnızca yetişkin içerik denetimini ise `phishing: {adult: false}` ile kapatın.

Geri kalan her şey yapılandırılana kadar kapalıdır:

| Denetim             | Gönderdiği                                                                                                                  | Gönderildiği yer                                                                  |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `authentication`    | Göndericinin SPF, DKIM, DMARC ve ARC kayıtları için DNS sorguları                                                           | Çözümleyiciniz veya `dnsServers`                                                  |
| `dnsbl`             | İstemcinin ters çevrilmiş IP adresi ve bağlantı alan adları, DNS sorguları olarak                                           | Engelleme listelerinin ad sunucuları, çözümleyiciniz veya `dns.servers` üzerinden |
| `llm`               | Uzak sağlayıcılar için kişisel verileri çıkarılmış bir ileti özeti                                                          | Belirttiğiniz dil modeli sunucusu ([gizlilik](llm.md#privacy))                    |
| `reputation.apiUrl` | İstemcinin IP adresi ve doğrulanmış ana makine adı ile From, zarf göndericisi ve Reply-To adresleri ve bunların alan adları | Belirttiğiniz hizmet                                                              |
| `clamav`            | Ekler                                                                                                                       | Kendi clamd'niz, soketi üzerinden                                                 |

Telemetri, güncelleme denetimi ve çalışma zamanında indirme yoktur. Model paketin içinde gelir.


## Neleri saklar

İstenmedikçe hiçbir şeyi. Taramalar günlüğe kaydedilmez veya saklanmaz. `learn()` sınıflandırıcıyı bellekte değiştirir; sınıflandırıcı diske yalnızca `saveModel()`, `spamscanner learn` veya sunucuların `--out` seçeneğiyle yazılır. Bir model dosyası sözcükleri veya ileti metnini değil, karma değerine dönüştürülmüş özellik sayılarını içerir.

Dil modeli yanıtları, gönderilen içeriğin karma değeriyle anahtarlanarak bellekte önbelleğe alınır; böylece aynı iletinin tekrarlanan kopyaları için yalnızca bir kez sorulur. DNS yanıtları on dakika, bir itibar hizmetinin yanıtları beş dakika (`reputation.cacheTtl`; başarısız bir istek bir dakika) boyunca bellekte önbelleğe alınır.


## Düşmanca girdi

* Ekler baytlarından tanınır; hiçbir zaman yürütülmez veya başka bir programla açılmaz. ZIP arşivleri, girdi sayısına (2000) ve adlarının baytlarına (1 MiB; 1 KiB'ı aşan bir ad ilk ve son 512 baytını korur ve bulgular bir adın en fazla 100 karakterini gösterir) sınır konarak merkezi dizinlerinden okunur; her girdi, onu kaç dizin gösterirse göstersin bir kez okunur. Hiçbir şey açılmaz (sıkıştırması çözülmez), bu yüzden iç içe ya da sıkıştırılmış arşivlerin içindeki programlar görülmez. Ekli iletiler (`message/rfc822` ya da dosya adı `.eml` ile biten ekler) en fazla üç düzey derinliğe kadar, en çok 100 eki ve toplamda 25 MB ekli ileti için açılır; iletinin kendi eklerinin hepsi her zaman incelenir. MIME ayrıştırıcının sınırlarını (1000'den fazla parça ya da 1 MB'ı aşan bir parça başlığı) aşan bir ileti, ayrıştırıcının izin verdiği kadar okunur (ilk parçaları, gönderici yine sayılsın diye kısaltılmış aşırı büyük bir başlıkla) ve hiçbir indirimin dengelemediği `MIME_TOO_COMPLEX` alır; ClamAV ise onu bütünüyle okur. Ayrıştırıcının başarısız olduğu ekli bir ileti de bunu alır ve taramayı hiçbir zaman başarısız kılmaz. Adres alanları, adres ayrıştırıcının harcadığı süre adres sayısının karesiyle arttığı için, her biri en fazla 16 KB (2000 adres, 16 iç içe grup) ve her ileti için toplamda en fazla 64 KB olmak üzere, yalnızca tam bir adresin sonunda kesilerek okunur; mailauth da From ve Return-Path'i böyle sınırlı okur (diğer alanları ise olduğu gibi, böylece onlar üzerindeki bir imza geçerli kalır) ve okunması doğrusal zamandan uzun sürecek bir başlığı (binlerce katlanmış satır ya da binlerce alanı belirten imzalar) kısaltarak okur. Kesilen bir From alanı DMARC'ı başarısız kılar ve hiçbir şeye izin vermez. HTML, Spam Scanner'ın kendi ayrıştırıcısıyla, ne kadar derin iç içe olursa olsun doğrusal zamanda okunur.
* Gövde metni `maxLength` (100.000 karakter) değerine kadar okunur ve sunucular 25 MB'a kadar iletileri kabul eder. Bağlantılar `phishing.maxLength` sınırına kadar okunur (1.000.000 karakter).
* Her ağ denetiminin bir zaman aşımı vardır (`timeout`, varsayılan olarak 10 saniye). Başarısız olan veya zaman aşımına uğrayan bir denetim atlanır ve tarama onsuz tamamlanır. Kimlik doğrulama ve görüntü modeli (ilk 10 görüntü) her biri bütünüyle bu süre içinde biter: kimlik doğrulama bu süreden sonra hiçbir DNS sorgusu göndermez, bir ileti için 300'den fazlasını da göndermez (RFC 7208 sınırlarında SPF ile birlikte DKIM, ARC, DMARC ve BIMI için yer) ve bir iletinin yalnızca ilk 8 DKIM imzasını denetler (mailauth'un kendisi en fazla 50 ARC kümesi okur). Milter'ın eklediği `Authentication-Results` başlığı en fazla 8 KiB sonuç içerir. ClamAV'ın (aynı anda dört ek) bir iletinin tüm ekleri için kendi sınırı vardır (`clamav.timeout`, 60 saniye); tarayamadığı ekler `results.virusScanErrors` içinde listelenir. Dil modelinin kendi süresi vardır (`llm.timeout`).
* İzin listesi yalnızca göndericinin sahteleyemeyeceği şeylere güvenir: istemcinin adresi ve doğrulanmış ana makine adı ile kimlik doğrulamanın onayladığı gönderici alan adları. [İzin ve engelleme listesi](api.md#allowlist-and-denylist)
* Bir iletide zaten bulunan `X-Spam-*` üst bilgileri milter, içerik filtresi ve `--headers` tarafından kaldırılır; böylece göndericiler kendi postalarını temiz olarak işaretleyemez.
* Microsoft'un spam kararı üst bilgilerine yalnızca ileti doğrudan Microsoft sunucularından geldiğinde güvenilir ve bir iletinin nereden geldiğine karar vermek için Received üst bilgileri hiçbir zaman kullanılmaz.
* Yapay zekâ filtrelerine hitap eden metin spam olarak puanlanır ve dil modeline iletinin talimat değil veri olduğu söylenir. [İstem enjeksiyonu](llm.md#prompt-injection)


## Sunucular

Milter, HTTP, TCP ve spamd sunucuları, `--host` aksini belirtmedikçe 127.0.0.1 adresini dinler. HTTP API belirtecini sabit sürede karşılaştırır ve belirteç olmadan `/learn` isteğini reddeder. Hiçbiri TLS konuşmaz: onlara bir ağ üzerinden ulaşmak için özel bir ağ, bir SSH tüneli veya TLS'li bir ters vekil sunucu kullanın.

Onları ayrıcalıksız bir kullanıcıyla çalıştırın. [Postfix kılavuzundaki systemd birimi](postfix.md#1-run-the-milter) olağan sağlamlaştırma ayarlarını ekler.


## Güvenlik açığı bildirmek

Güvenlik sorunlarını herkese açık sorun kayıtlarında değil, [GitHub'ın güvenlik açığı bildirme özelliği](https://github.com/spamscanner/spamscanner/security/advisories/new) üzerinden gizli olarak bildirin.
