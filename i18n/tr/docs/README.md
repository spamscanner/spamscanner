<!-- source: c56969e779c4 -->

# Spam Scanner belgeleri

Spam Scanner, kaynak kodu GitHub'da bulunan, Node.js ve komut satırı için bir spam filtresidir. Ham bir e-posta iletisini okur ve iletinin hangi dilde olursa olsun spam, kimlik avı veya dolandırıcılık olup olmadığına ya da kötü amaçlı yazılım taşıyıp taşımadığına karar verir. Bir kitaplık, bir komut satırı aracı, bir Postfix veya Sendmail milter'ı, bir Postfix içerik filtresi, SpamAssassin uyumlu bir spamd sunucusu, bir HTTP API veya bir TCP sunucusu olarak çalışır.

[Forward Email](https://forwardemail.net) tarafından kendi posta sunucuları için geliştirilmiştir.


## Bir ileti nasıl değerlendirilir

Her denetim puan ekler veya düşer. Sonucu toplam belirler:

| Puan        | Eylem    | Posta sunucusunun yaptığı                   |
| ----------- | -------- | ------------------------------------------- |
| 5'in altı   | `accept` | İletiyi teslim eder                         |
| 5 ile 14,9  | `tag`    | İletiyi spam olarak işaretleyip teslim eder |
| 15 ve üzeri | `reject` | İletiyi SMTP oturumu sırasında geri çevirir |

İki eşik de değiştirilebilir. Her sonuç tetiklenen testleri puanları ve bir nedenle birlikte listeler; böylece bir karar her zaman açıklanabilir.

Denetimler:

* **Eğitilmiş bir sınıflandırıcı** iletinin sözcüklerini hangi yazı sisteminde olursa olsun, bağlantılarının biçimini, göndericisini ve eklerini okur. Herkese açık veri kümeleriyle eğitilmiş olarak gelir ve kendi postanızdan öğrenir. [Sınıflandırıcı nasıl çalışır](how-it-works.md#the-classifier)
* **Kimlik avı denetimleri** benzer alan adlarını (`paypa1.com`, Kiril а harfli `pаypal.com`), metni bir adres gösterip hedefi başka bir adres olan bağlantıları ve bir marka adına konuşan görünen adları yakalar. [Kimlik avı](how-it-works.md#phishing)
* **Ek denetimleri** yürütülebilir dosyaları, belge olarak yeniden adlandırılmış yürütülebilir dosyaları, çift uzantıları, sağdan sola dosya adı hilelerini, ZIP dosyalarındaki yürütülebilir dosyaları, Office makrolarını ve etkin PDF içeriğini bulur. ClamAV ekleri virüslere karşı tarayabilir. [Ekler](how-it-works.md#attachments)
* **Kimlik doğrulama**: istemcinin IP adresi biliniyorsa SPF, DKIM, DMARC ve ARC. [Kimlik doğrulama](how-it-works.md#authentication)
* İstemcinin IP adresi ve bağlantılardaki alan adları için **DNS engelleme listeleri** ve bilinen kötü amaçlı yazılım ve yetişkin içerikli siteler için Cloudflare'in filtreleme yapan çözümleyicileri. [Engelleme listeleri](how-it-works.md#blocklists)
* Hiçbir sınıflandırıcının öğrenmesi gerekmeyen kalıplar için **kurallar**: GTUBE test dizisi, şantaj (sextortion) konu satırları, PayPal fatura dolandırıcılıkları, kendi alan adını taklit etme ve yapay zekâ filtreleri için gizlenmiş talimatlar. [Kurallar](scoring.md#rules)
* İsteğe bağlı **bir dil modeli**, kararsız kalınan durumlarda ikinci bir görüş verir: Ollama veya OpenAI uyumlu herhangi bir sunucu üzerinden yerel bir model ya da Claude, ChatGPT, Gemini ve diğerleri. [Dil modelleri](llm.md)


## Nereden başlamalı

* [Başlarken](getting-started.md): kurun ve ilk iletiyi tarayın.
* [Komut satırı](cli.md): tüm komutlar ve seçenekler.
* [Postfix ve Sendmail](postfix.md): bir posta sunucusunu milter veya içerik filtresiyle filtreleyin.
* [Diğer posta sunucuları](mail-servers.md): Exim, Haraka, Dovecot, procmail ve HTTP API çağırabilen her şey.
* [Eğitim](training.md): ona kendi postanızı öğretin ve sonucu ölçün.
* [Dil modelleri](llm.md): sağlayıcılar, önerilen açık modeller, gizlilik ve istem enjeksiyonu.
* [Diller](languages.md): Çince, Arapça, Tayca ve diğer tüm yazı sistemlerini nasıl okuduğu.
* [Forward Email](forward-email.md): Forward Email'in onu nasıl kullandığı ve 5 veya 6 sürümünden yükseltme.
* [API başvurusu](api.md) ve [testler ve puanlar](scoring.md).
* [Güvenlik ve gizlilik](security.md): makineden ne çıkar ve bu nasıl durdurulur.
