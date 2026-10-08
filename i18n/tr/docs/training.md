<!-- source: 7cc30ff4ad91 -->

# Eğitim

Paketle gelen model kutudan çıktığı gibi çalışır. Kendi postanızla eğitilen bir model daha iyi çalışır, çünkü sizin haminizin neye benzediğini öğrenir: bültenlerinizi, iş arkadaşlarınızın yazış biçimini, aldığınız dilleri.


## Bir model eğitin

`train` komutunu spam ve ham klasörlerine yönlendirin:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Kaynaklar şunlar olabilir:

* gzip ile sıkıştırılmış olanlar dahil (`.mbox.gz`) **mbox** dosyaları,
* bir **Maildir** (`cur` ve `new` klasörleri okunur, `tmp` atlanır),
* özyinelemeli olarak okunan, `.eml` dosyalarından oluşan bir **klasör**,
* bir **veri kümesi**: bir metin sütunu ve bir etiket sütunu içeren CSV veya JSON Lines dosyası (`--dataset`). `text`, `message`, `body`, `email` veya `content` ile `label`, `category`, `class`, `spam` veya `is_spam` adlı sütunlar kendiliğinden bulunur; aksi hâlde `--text-column` ve `--label-column` kullanın. `spam`, `1`, `phishing` ve `ham`, `0`, `not_spam`, `legitimate` gibi etiketler anlaşılır.

Yinelenen iletiler bir kez sayılır. Boş bir modelle başlamak yerine paketle gelen modelin üzerine eklemek için `--merge` ekleyin.

Modeli kullanın:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Ne kadar posta yeterli: her türden birkaç yüz ileti kullanışlı bir model, birkaç bin ileti iyi bir model verir. İkisini kabaca dengeli tutun ve filtrelenmesini istemediğiniz postaları (parola sıfırlama iletileri, kendi tedarikçilerinizden gelen faturalar) hamın içinde bulundurun.


## Ölçün

Postanın bir kısmını eğitimin dışında tutun ve ölçümü onun üzerinde yapın:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Paketle gelen modelin, hiç görmediği ve çoğu neredeyse hiç bilmediği dillerde olan 21 dildeki SMS iletileri üzerindeki sonucu:

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

Kesinlik (precision), spam dediklerinin ne kadarının gerçekten spam olduğudur; duyarlılık (recall) ise spamın ne kadarını yakaladığıdır. "Emin değil" sonucunu alan iletiler burada kaçırılmış spam sayılır; oysa bir taramada diğer denetimler ve dil modeli bunları yine de yakalayabilir. İzlenmesi gereken sayı yanlış pozitiflerdir: spam olarak işaretlenen ham. Yukarıdaki çalıştırmada model bu iletilerin çoğu hakkında yanılmak yerine emin olmadığını söylüyor; az postası olan diller için amaçlanan davranış budur.

`--json` aynı sayıları betikler için verir.


## Bildirimlerden öğrenme

Kullanıcılar postayı bir Junk klasörüne taşıdığında veya oradan çıkardığında modele her seferinde bir ileti öğretin:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

İlk `learn` dosyayı paketle gelen modelden oluşturur. HTTP üzerinden, [HTTP API](http-api.md) içindeki `POST /learn/spam` ve `/learn/ham` aynı işi yapar; `spamc -L spam` ise `--allow-tell` ile [spamd sunucusuna](mail-servers.md#a-drop-in-for-spamassassins-spamd) karşı çalışır. [Dovecot'un IMAPSieve özelliği](mail-servers.md#dovecot-junk-folder-and-learning) bir ileti taşındığında bunlardan birini çağırabilir.

Node.js'ten:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Yanlış sınıflandırıldığı bildirilen bir ileti daha önce öğrenildiyse, doğru sınıfta öğrenilmeden önce yanlış sınıftan geri alınmalıdır (unlearn).


## Paketle gelen model

`model/classifier.json`, `npm run model:train` tarafından Hugging Face üzerindeki, tümü açık lisanslı şu herkese açık veri kümelerinden oluşturulur:

| Veri kümesi                                                                                                                                                                                                                                                                                                                | Lisans                         | İçerik                          |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                     | 43 dilde iletiler ve e-postalar |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Herkese açık araştırma derlemi | Enron-Spam derlemi              |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                        | Rusça Telegram iletileri        |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                            | Yapay iletiler                  |

Model 62.480 spam ve 76.489 ham iletiden öğrendi. Betik her onuncu iletiyi ayırır, geri kalanıyla eğitir ve diğer denetimler olmadan yalnızca sınıflandırıcıyı ölçer:

| Ayrılmış test |  İleti | Kesinlik | Duyarlılık | Yanlış pozitif | Emin değil |
| ------------- | -----: | -------: | ---------: | -------------: | ---------: |
| İngilizce     |  6.564 |   %100,0 |      %97,0 |           %0,0 |       %2,4 |
| Rusça         |  1.682 |   %100,0 |      %97,4 |           %0,0 |       %2,2 |
| İtalyanca     |  1.389 |    %98,1 |      %85,3 |           %1,8 |      %10,9 |
| Almanca       |  1.309 |    %97,7 |      %76,1 |           %2,2 |      %20,7 |
| İspanyolca    |  1.281 |    %97,5 |      %82,5 |           %2,6 |      %16,8 |
| Enron-Spam    |  2.888 |   %100,0 |      %93,1 |           %0,0 |       %4,5 |
| all-scam-spam |  4.236 |   %100,0 |      %88,8 |           %0,0 |      %11,2 |
| Tümü          | 13.840 |    %99,2 |      %85,1 |           %0,5 |      %12,4 |

Burada spam, sınıflandırıcı olasılığının %99 veya üzeri olması anlamına gelir; bu, sınıflandırıcının tek başına spam eşiğine ulaştığı noktadır. Bir taramada sınıflandırıcının daha az emin olduğu spam yine de puan alır ve diğer denetimler kendi puanlarını ekler.

Almanca, İspanyolca ve İtalyanca sonuçlar, hem spam hem ham olarak etiketlenmiş neredeyse aynı iletiler içeren yapay veri kümelerinden gelir: bu hatanın bir kısmı modelde değil, etiketlerdedir. En iyi çözüm kendi dillerinizdeki postadır. Tüm diller ve veri kümeleriyle birlikte sayılar modelin `metadata.metrics` alanında bulunur.

### Daha fazla dil

`npm run model:train -- --with multilingual-sms`, [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) veri kümesini ekler: 21 dile makine çevirisiyle aktarılmış SMS Spam Collection. Veri kümesinin kartı GPL lisansı belirttiği için paketle gelen modele dahil edilmemiştir; modeli paylaşma biçiminize uygun olup olmadığını denetleyin. Bu veri kümesiyle eğitildiğinde, paketle gelen modelin neredeyse hiç bilmediği diller için ayrılmış test sonuçları şöyleydi:

| Dil       | İleti | Kesinlik | Duyarlılık | Yanlış pozitif |
| --------- | ----: | -------: | ---------: | -------------: |
| Çince     |   430 |   %100,0 |      %82,3 |           %0,0 |
| Arapça    |   430 |   %100,0 |      %84,6 |           %0,0 |
| Korece    |   412 |   %100,0 |      %80,4 |           %0,0 |
| Japonca   |   486 |    %96,0 |      %85,7 |           %0,5 |
| Hintçe    |   412 |   %100,0 |      %63,9 |           %0,0 |
| Fransızca |   480 |    %98,6 |      %94,2 |           %0,6 |
| Türkçe    |   220 |   %100,0 |      %73,1 |           %0,0 |

### Yeniden eğitin

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Model dosyası

Bir model bir JSON dosyasıdır: öğrenilen spam ve ham iletilerin sayısını ve karma değerine dönüştürülmüş her özellik için o özelliği içeren spam ve ham iletilerin sayısını sıralanmış ve base64 ile kodlanmış olarak tutar. Hiçbir sözcük ve hiçbir ileti metni içermez. `--max-features` yalnızca en sık görülen özellikleri tutar, `--min-count` ise nadir olanları atar; ikisi de boyut karşılığında doğruluktan ödün verir. Paketle gelen model yaklaşık 6 MB içinde 400.000 özellik tutar.

Spam Scanner 6 ve önceki sürümlerin modelleri yüklenemez: farklı özellikleri karma değerine dönüştürüyorlardı. Aynı postadan yeni bir model eğitin.
