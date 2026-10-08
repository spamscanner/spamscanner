<!-- source: f33722183f00 -->

<!--
label: Postfix spam filtresi
title: Milter veya içerik filtresiyle Postfix spam filtresi
description: Postfix sunucusunda Spam Scanner'ın milter veya içerik filtresiyle spamı filtreleyin: kurulum, systemd birimi, 4xx veya 5xx ile reddetme ve Junk klasörü.
keywords: Postfix spam filtresi, Postfix milter, smtpd_milters, Postfix içerik filtresi, Postfix anti-spam, Postfix spam engelleme, Postfix spam reddetme
-->

# Postfix spam filtresi

Spam Scanner bir Postfix sunucusunu yaklaşık beş dakikada filtrelemeye başlar. Milter olarak çalışır; böylece Postfix her ileti için SMTP oturumu sırasında ona danışır ve spamı kabul etmeden önce geri çevirebilir.


## Kurun ve çalıştırın

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` SPF, DKIM, DMARC ve ARC denetimlerini yapar; `--subject-tag` spamı konu satırında işaretler. Her ileti `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` ve `X-Spam-Action` üst bilgilerini alır; göndericinin eklediği her `X-Spam-*` üst bilgisi önce kaldırılır.


## Postfix'i bağlayın

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept`, milter çalışmıyorsa postanın filtrelenmeden geçmesine izin verir; `tempfail` ise göndericilerden yeniden denemelerini ister.


## Spamı SMTP oturumu sırasında geri çevirin

```sh
spamscanner milter --port 7831 --auth --reject
```

Reddetme eşiğindeki (15 puan) iletiler `451 4.7.1 Message rejected as spam` ile geri çevrilir. 451 geçici bir hatadır: gönderici iletiyi saklar ve yeniden dener; böylece yanlış bir karar bir iletinin kaybına değil, yalnızca gecikmeye mal olur. Sonuçlar doğru görünmeye başladığında `--reject-code 550` geri çevirmeyi kalıcı hâle getirir.


## Milter olmadan

İçerik filtresi, Postfix bir iletiyi kabul ettikten sonra çalışır: Postfix iletiyi `spamscanner filter` komutuna aktarır; bu komut üst bilgileri ekler ve iletiyi geri verir. Oturum sırasında hiçbir şey geri çevrilmez ve bir hata olduğunda teslimat her zaman geri döndürülmek yerine ertelenir. [İçerik filtresi kurulumu](../../docs/postfix.md#content-filter)


## Spamı Junk klasörüne

Dovecot ile bir Sieve kuralı etiketlenmiş postayı klasöre taşır:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Gerçek bir Postfix ile test edildi

Projenin uçtan uca testleri Postfix'i milter ve içerik filtresiyle çalıştırır: ham, üst bilgileriyle ve sahte `X-Spam-Flag` kaldırılmış olarak teslim edilir, spam etiketlenir ve GTUBE SMTP oturumu sırasında 550 ile geri çevrilir.

Sonraki: systemd birimi ve Sendmail'in `INPUT_MAIL_FILTER` ayarıyla birlikte [Postfix ve Sendmail için kapsamlı kılavuz](../../docs/postfix.md).
