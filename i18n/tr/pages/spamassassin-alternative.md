<!-- source: 1562b843d858 -->

<!--
label: SpamAssassin alternatifi
title: spamd protokolünü konuşan bir SpamAssassin alternatifi
description: SpamAssassin'in spamd'sini Spam Scanner ile değiştirin. spamc, Exim ve Haraka çalışmaya devam eder, X-Spam üst bilgileri aynı kalır, her dil desteklenir.
keywords: SpamAssassin alternatifi, spamd yerine, spamc, Exim spam filtresi, Haraka spamassassin, rspamd alternatifi, X-Spam-Status
-->

# spamd protokolünü konuşan bir SpamAssassin alternatifi

Spam Scanner, SpamAssassin'in spamd protokolüne yanıt verir; bu nedenle SpamAssassin için yazılmış yazılımlar onu değişiklik yapmadan kullanır: spamc, Exim'in `spam` koşulu, Haraka'nın `spamassassin` eklentisi ve diğerleri.


## Yerine koyun

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

`CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` komutlarına ve `--allow-tell` ile öğrenme için `TELL` komutuna yanıt verir. Projenin uçtan uca testleri SpamAssassin'in kendi spamc istemcisini ona karşı çalıştırır.


## Ne aynı kalır

* Üst bilgiler: SpamAssassin biçiminde `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` ve `X-Spam-Status`; böylece mevcut Sieve, procmail ve posta istemcisi kuralları çalışmaya devam eder.
* Puanlı, adlandırılmış testlerden oluşan ve eşiği 5 olan bir puan: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` vb.
* Test başına puanlar test adıyla değiştirilebilir.


## Ne farklıdır

* **Diller.** Sözcükler Unicode kurallarıyla bölütlenir; böylece Çince, Japonca ve Tayca uzun tek bir dizi olarak değil sözcükler olarak okunur ve görünmez karakterler ya da Latin sözcüklerdeki Kiril harfleri gibi kamuflajlar önce geri çözülür.
* **Kimlik avı.** Benzer alan adları, yanıltıcı bağlantılar ve görünen adlardaki marka adları ek kural gerekmeden denetlenir.
* **Ekler** baytlarından tanınır: adı `.pdf` olarak değiştirilmiş bir yürütülebilir dosya yine yürütülebilir dosyadır.
* **Dil modelleri.** Kararsız kalınan durumlar Ollama aracılığıyla yerel bir modele ya da barındırılan bir modele gönderilebilir.
* **Node.js.** Tek bir `npm install` ya da bağımsız bir ikili dosya; yönetilecek Perl modülü veya kural güncellemesi yoktur.

Spam Scanner, SpamAssassin'in kural dosyalarını çalıştırmaz ve Bayes veritabanı biçimi kendine özgüdür: onu aynı postayla `spamscanner train` kullanarak eğitin.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot ve procmail](../../docs/mail-servers.md)
