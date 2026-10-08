<!-- source: 9537a0e62eb0 -->

# Diller

Spam her dilde gelir, sıradan posta da öyle. Spam Scanner ikisini de okur ve az tanıdığı dillerde dikkatli davranır: her Arapça veya Çince iletiyi işaretleyen bir spam filtresi, hiç filtre olmamasından daha kötüdür.


## Her yazı sistemini okumak

* **Sözcükler.** Metin, Unicode sözcük sınırı kurallarını izleyen ve boşluksuz yazılan Çince, Japonca, Tayca, Laoca, Kmerce ve Birmanca için sözlükler kullanan `Intl.Segmenter` ile bölünür. Uzun metinler önce parçalara ayrılır, çünkü Node.js 18'deki bölütleyici çok uzun dizilerde yavaşlar.
* **Normalleştirme.** Unicode NFKC tam genişlikli harfleri ve süslü harflerin çoğunu (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) düz harflere dönüştürür. Metin Unicode kurallarına göre küçük harfe çevrilir.
* **Kamuflajlar.** Sözcüklerin içindeki görünmez karakterler (iki harf arasında sıfır genişlikli boşluk bulunan `free`, yumuşak tireler) kaldırılır ve sayılır. Kiril а harfli `pаypal` gibi alfabeleri karıştıran sözcükler tek bir alfabeye geri eşlenir ve sayılır. Harf yerine kullanılan rakamlar (`v1agra`) dönüştürülür. Her kamuflaj başlı başına bir özelliktir; üç veya daha fazla görünmez karakter ya da iki veya daha fazla karışık sözcük ayrıca puan ekler.


## Dili tespit etmek

Her iletinin dili yazı sisteminden ve birçok dilin paylaştığı yazı sistemlerinde harflerinden tespit edilir:

* Hangul Koreceyi gösterir; Hiragana ve Katakana Japonca anlamına gelir; Tay, Yunan, İbrani, Ermeni, Gürcü, Bengal, Tamil ve tek bir dil tarafından kullanılan diğer yazı sistemleri dili doğrudan belirtir.
* Yalnızca tek bir dilde bulunan Kiril harfleri Ukraynaca (і, ї, є, ґ), Belarusça (ў), Sırpça (ђ, ћ, џ), Makedonca (ѓ, ќ, ѕ) ve Rusça (ы, э, ё) arasında karar verir.
* Birkaç dilin paylaştığı yazı sistemlerindeki (Latin, Kiril, Arap, Devanagari ve diğerleri) metin, karar verecek kadar uzunsa [franc](https://github.com/wooorm/franc) aracına gider; kısa iletilerin nadir dillerle etiketlenmemesi için franc e-postada yaygın dillerle sınırlandırılır.

Dil `result.language` olarak bildirilir ve `allowedLanguages: ['en', 'de']` (`--allow-language en,de`), başka bir dilde olduğu güvenle tespit edilen postaya 3 puan ekler.


## Modelin az tanıdığı diller

Bir sınıflandırıcı örneklerden öğrenir. Herkese açık spam veri kümelerinde yabancı dilde çok daha fazla spam, çok daha az ham bulunur; bu yüzden saf bir sınıflandırıcı Çince veya Arapça metnin kendisinin spam anlamına geldiğini öğrenir. Spam Scanner bunu üç yolla düzeltir:

1. **Dil hiçbir zaman kanıt değildir.** Tespit edilen dil ve yazı sistemi ipucu olarak kullanılmaz.
2. **Sözcükler kendi dilleri içinde tartılır.** Bir sözcüğün spam olasılığı, sınıflandırıcının tüm dillerde değil, iletinin dilinde gördüğü spam ve ham iletilerin sayısına göre hesaplanır. Çoğunlukla Portekizce spam görmüş bir modelde gündelik bir Portekizce sözcük nötr kalır.
3. **Güven kapsamı izler.** Sonuç, sınıflandırıcının o dilde her türden kaç ileti gördüğüyle orantılı olarak "emin değil" yönüne çekilir: tam güven için her türden 1.000 ileti (küçük kişisel modellerde küçük sınıfın %2'si) gerekir. Eğitim verisinde hiç hamı olmayan bir dil her zaman "emin değil" sonucunu alır.

Paketle gelen model, 21 dile makine çevirisiyle aktarılmış SMS iletilerinden oluşan [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) veri kümesini hiç görmedi. Bu kurallardan önce bu hamın %5,7'sini, Portekizcenin %55'i ve Fransızcanın %41'i dahil, spam olarak işaretliyordu. Kurallarla birlikte oran %0,18'e indi: Çince, Arapça, Korece, Japonca, Hintçe, Portekizce, Fransızca ve 20 başka dilde hiç, İngilizcede ise %0,27.


## Bu dillerde spamı yakalamak

"Emin değil" sonucu güvenlidir ama spamı yakalamaz. Üç şey yakalar:

* **Diğer denetimler** dile bağlı değildir: benzer alan adları, yanıltıcı bağlantılar, yürütülebilir dosyalar, makrolar, kimlik doğrulama, engelleme listeleri, kurallar.
* **Bir dil modeli.** Günümüzün açık modelleri 100 ile 200 arasında dil okur ve Spam Scanner sınıflandırıcı emin olmadığında bir modele danışır. Uçtan uca testler, `qwen3.5:4b` modelinin Çince, Arapça, Korece, Hintçe ve Taycada spamı yakaladığını ve hamı geçirdiğini denetler. [Dil modelleri](llm.md)
* **Kendi postanızla eğitim.** Kendi postanızla eğitilen bir modelde, bir dilde her türden birkaç yüz ileti sınıflandırıcıya o dilde tam güven kazandırır. [Eğitim](training.md) ve 21 dil ekleyen [isteğe bağlı bir veri kümesi](training.md#more-languages).
