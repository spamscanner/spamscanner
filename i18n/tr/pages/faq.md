<!-- source: c93fa1a3f9c7 -->

<!--
label: SSS
title: Sıkça sorulan sorular
description: Spam Scanner hakkında yanıtlar: ne kadar doğru olduğu, hangi dilleri desteklediği, ağ üzerinden ne gönderdiği, dil modelleri, SpamAssassin ve Forward Email.
keywords: Spam Scanner SSS, spam filtresi soruları, spam filtresi doğruluğu, spam filtresi gizliliği, istenmeyen e-posta filtresi
-->

# Sıkça sorulan sorular


## Spam Scanner nedir?

Node.js, komut satırı ve posta sunucuları için bir spam filtresi. Ham bir e-posta iletisini okur ve iletinin spam, kimlik avı veya dolandırıcılık olup olmadığına ya da kötü amaçlı yazılım taşıyıp taşımadığına bir puanla ve karara götüren testlerin listesiyle birlikte karar verir. Bir kitaplık, Postfix ve Sendmail için bir milter, SpamAssassin uyumlu bir spamd sunucusu, bir Postfix içerik filtresi, bir HTTP API veya bir TCP sunucusu olarak çalışır.


## Ücretsiz mi?

[Lisansı](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) olan Business Source License 1.1, spam tespitini başkalarına hizmet olarak sunmak dışında her türlü kullanıma izin verir ve Apache License 2.0'a geçeceği tarihi belirtir.


## Ne kadar doğru?

Eğitim verisinden ayrılmış İngilizce iletilerde, paketle gelen sınıflandırıcı tek başına hiçbir ham iletiyi spam olarak işaretlemedi ve spamın %97'sini yakaladı; dillere göre tüm sayılar [eğitim kılavuzunda](../../docs/training.md#the-bundled-model) yer alır. Bağlantılar, ekler, kimlik doğrulama, engelleme listeleri ve bir dil modeli buna katkıda bulunur. Asıl test sizin postanızdır: `spamscanner eval` herhangi bir modeli etiketlenmiş herhangi bir posta üzerinde ölçer.


## Hangi dilleri destekliyor?

Hepsini. Sözcükleri, boşluk içermeyen Çince, Japonca ve Tayca dahil Unicode kurallarıyla bölütler. Paketle gelen modelin bir dilde az posta gördüğü durumlarda iletiyi işaretlemek yerine "emin değil" sonucunda kalır ve kararı bir dil modeli ya da kendi eğitiminiz verir. [Diller](../../docs/languages.md)


## Postamı bir yere gönderiyor mu?

Hayır. Varsayılan olarak bağlantıların ana makine adlarını Cloudflare'in filtreleme yapan DNS çözümleyicilerinde sorgular; makineden başka hiçbir şey çıkmaz. Kimlik doğrulama, engelleme listeleri, dil modelleri ve itibar hizmetleri yapılandırılana kadar kapalıdır ve posta barındırılan bir dil modeline gitmeden önce kişisel veriler çıkarılır. [Güvenlik ve gizlilik](../../docs/security.md)


## Bir dil modeline ihtiyacım var mı?

Hayır. Model, sınırdaki durumlar için ikinci bir görüştür. Model olmadan bu iletilere yalnızca puanlarına göre karar verilir.


## Hangi dil modelini kullanmalıyım?

CPU üzerinde Ollama aracılığıyla `qwen3.5:4b` ya da GPU ile `qwen3.5:9b`. İkisi de Apache lisanslıdır ve 201 dil okur. Anthropic, OpenAI, Google ve diğerlerinin barındırılan modelleri de çalışır. [Önerilen modeller](../../docs/llm.md#recommended-open-models)


## SpamAssassin'in yerini alabilir mi?

Çoğu kurulum için evet: spamd'nin protokolünü konuşur, bu nedenle spamc, Exim ve Haraka değişiklik yapılmadan çalışır ve aynı `X-Spam-*` üst bilgilerini yazar. SpamAssassin'in kural dosyalarını çalıştırmaz. [SpamAssassin alternatifi](/spamassassin-alternative/)


## Meşru postayı reddeder mi?

Postayı geri çevirmek varsayılan olarak kapalıdır: milter yalnızca etiketler. `--reject` ile yalnızca 15 veya daha yüksek puan alan iletiler geçici bir 451 hatasıyla geri çevrilir; böylece göndericiler yeniden dener ve bir hata bir ayar değiştirilerek düzeltilebilir. İçerik filtresi SMTP oturumu sırasında hiçbir zaman geri çevirmez.


## Kendi postamla nasıl eğitirim?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, ardından `--model model.json`. Mbox dosyaları, Maildir'ler, `.eml` dosyalarından oluşan klasörler ve CSV veya JSON Lines veri kümelerinin tümü çalışır. [Eğitim](../../docs/training.md)


## Node.js olmadan çalışır mı?

Evet: Linux, macOS ve Windows için bağımsız ikili dosyalar Node.js'i ve modeli içerir. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Kim geliştiriyor?

Kendi posta sunucuları için [Forward Email](https://forwardemail.net).
