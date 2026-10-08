<!-- source: 0ad167ddd34e -->

<!--
label: Çok dilli spam filtresi
title: Çince, Arapça, Rusça ve her yazı için çok dilli spam filtresi
description: Spam Scanner her dilde spamı nasıl filtreler: Unicode sözcük bölütleme, kamuflajları geri çözme ve modelin az tanıdığı bir dili asla işaretlememe.
keywords: çok dilli spam filtresi, Çince spam filtresi, Arapça spam filtresi, Rusça spam filtresi, Japonca spam filtresi, Türkçe spam filtresi, Unicode spam tespiti, homoglif spam
-->

# Çok dilli spam filtresi

Pek çok spam filtresi İngilizce için geliştirildi. Başka dillerdeki spam bu filtrelerden kaçar, başka dillerdeki sıradan posta ise yazı sistemi yüzünden işaretlenir. Spam Scanner her ikisinden de kaçınmak için geliştirildi.


## Sözcükleri okumak

Sözcükler, Çince, Japonca, Tayca, Laoca, Kmerce ve Birmanca için sözlükler içeren Unicode sözcük sınırı kuralları olan `Intl.Segmenter` ile bulunur. Çince bir cümle hiç tekrarlanmayan uzun tek bir dizi olarak değil, 恭喜, 获得 ve 大奖 gibi sözcüklere ayrılır.

Kamuflajlar sayımdan önce geri çözülür: sözcüklerin içindeki görünmez karakterler, Latin sözcüklerin içindeki Kiril veya Yunan harfleri (`pаypal`), harf yerine rakamlar (`v1agra`) ve matematiksel ya da çerçeveli harfler (𝐅𝐑𝐄𝐄). Her kamuflaj aynı zamanda başlı başına bir ipucudur.


## Bilmediğini işaretlememek

Herkese açık spam veri kümeleri yabancı dilde çok daha fazla spam, çok daha az ham içerir; bu yüzden saf bir sınıflandırıcı Arapça veya Korece metnin kendisinin spam olduğunu öğrenir. Spam Scanner dili hiçbir zaman ipucu olarak kullanmaz, her sözcüğü kendi dilinin spam ve ham sayılarına göre tartar ve bir dilde ne kadar az ham gördüyse o oranda "emin değil" sonucunda kalır.

Paketle gelen modelin hiç görmediği 21 dildeki SMS iletileriyle yapılan bir testte bu yöntem Çince, Arapça, Korece, Japonca, Hintçe, Bengalce, Urduca, Türkçe, Ukraynaca ve İsveççedeki yanlış pozitifleri sıfıra indirdi.


## Her dilde spamı yakalamak

* **Sözcük okumayan denetimler:** benzer alan adları, yanıltıcı bağlantılar, yürütülebilir dosyalar, makrolar, SPF, DKIM, DMARC ve engelleme listeleri.
* **Emin olunamayan iletiler için bir dil modeli.** Qwen 3.5 ve Gemma 4 gibi açık modeller 140 ile 200 arasında dil okur; uçtan uca testler Çince, Arapça, Korece, Hintçe ve Tayca spam ve hamı gerçek bir modelle denetler.
* **Kendi postanız.** Bir dilde her türden birkaç yüz ileti, postanızla eğitilen bir modele o dilde tam güven kazandırır.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Yalnızca bazı dilleri kabul etmek için `--allow-language en,de`, başka bir dilde olduğu güvenle tespit edilen postaya puan ekler.

[Diller ayrıntılı olarak](../../docs/languages.md)
