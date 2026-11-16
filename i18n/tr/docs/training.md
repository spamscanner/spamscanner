<!-- source: c4f8c2c7aa5a -->

# Eğitim

Paketle gelen model kutudan çıktığı gibi çalışır. Kendi postanızla eğitilen bir model daha iyi çalışır, çünkü sizin haminizin neye benzediğini öğrenir: bültenlerinizi, iş arkadaşlarınızın yazış biçimini, aldığınız dilleri.


## Bir model eğitin

`train` komutunu spam ve ham klasörlerine yönlendirin:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Kaynaklar şunlar olabilir:

* gzip ile sıkıştırılmış olanlar dahil (`.mbox.gz`; diğer `.gz` dosyaları atlanır) **mbox** dosyaları,
* bir **Maildir** (`cur` ve `new` klasörleri okunur, `tmp` atlanır),
* özyinelemeli olarak okunan, `.eml` dosyalarından oluşan bir **klasör**,
* bir **veri kümesi**: bir metin sütunu ve bir etiket sütunu içeren CSV veya JSON Lines dosyası (`--dataset`). `text`, `message`, `body`, `email text`, `email`, `content`, `sms` veya `v2` ile `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` veya `labels` adlı sütunlar ya da JSON alanları, büyük-küçük harf fark etmeksizin kendiliğinden bulunur (JSON Lines'ta `label_text`, `label` alanından önce); aksi hâlde `--text-column` ve `--label-column` kullanın. Nesne olmayan bir JSON satırı atlanır. `spam`, `1`, `phishing` ve `ham`, `0`, `not_spam`, `legitimate` gibi etiketler anlaşılır.

Yinelenen iletiler bir kez sayılır. Hem spam hem de ham kaynaklarında bulunan bir ileti spam olarak tutulur, çünkü önce spam kaynakları okunur. Boş bir modelle başlamak yerine paketle gelen modelin üzerine eklemek için `--merge` ekleyin.

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
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
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

| Veri kümesi                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Lisans                         | İçerik                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------ | -------------------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                     | 43 dilde iletiler ve e-postalar                                                        |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Herkese açık araştırma derlemi | Enron-Spam derlemi                                                                     |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                        | Rusça Telegram iletileri                                                               |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                            | Yapay iletiler                                                                         |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                      | Posta listeleri, bültenler, spam, oltalama ve dolandırıcılık e-postaları               |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                            | Hindistan'ın 14 dilinde iletiler                                                       |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                     | Kategoriye göre Endonezce e-postalar                                                   |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                     | Bir şirketin İspanyolca postası                                                        |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0     | Olağan posta: faturalar, rezervasyonlar, bültenler, promosyonlar ve hesap bildirimleri |

Ham, olağan iş ve mağaza postasını (faturalar, sipariş ve hesap bildirimleri, bültenler, promosyonlar) içerir; böylece bu tür posta tek başına spam olarak okunmaz.

Model 77.564 spam ve 112.586 ham iletiden öğrendi. Betik her onuncu iletiyi ayırır, geri kalanıyla eğitir ve diğer denetimler olmadan yalnızca sınıflandırıcıyı ölçer:

| Ayrılmış test |  İleti | Kesinlik | Duyarlılık | Yanlış pozitif | Emin değil |
| ------------- | -----: | -------: | ---------: | -------------: | ---------: |
| İngilizce     |  8.515 |   %100,0 |      %96,4 |           %0,0 |       %2,6 |
| Rusça         |  1.680 |   %100,0 |      %97,4 |           %0,0 |       %2,3 |
| İtalyanca     |  1.392 |    %98,6 |      %81,0 |           %1,2 |      %12,5 |
| Almanca       |  1.314 |    %97,8 |      %72,5 |           %2,1 |      %22,6 |
| İspanyolca    |  2.088 |    %98,5 |      %56,1 |           %0,4 |      %15,7 |
| Enron-Spam    |  2.888 |   %100,0 |      %92,4 |           %0,0 |       %4,4 |
| all-scam-spam |  4.236 |   %100,0 |      %89,3 |           %0,0 |      %11,6 |
| Tümü          | 18.967 |    %99,6 |      %77,2 |           %0,2 |      %15,8 |

Burada spam, sınıflandırıcı olasılığının %99 veya üzeri olması anlamına gelir; bu, sınıflandırıcının tek başına spam eşiğine ulaştığı noktadır. Bir taramada sınıflandırıcının daha az emin olduğu spam yine de puan alır ve diğer denetimler kendi puanlarını ekler.

Almanca, İspanyolca ve İtalyanca sonuçlar, hem spam hem ham olarak etiketlenmiş neredeyse aynı iletiler içeren yapay veri kümelerinden gelir: bu hatanın bir kısmı modelde değil, etiketlerdedir. En iyi çözüm kendi dillerinizdeki postadır. Tüm diller ve veri kümeleriyle birlikte sayılar modelin `metadata.metrics` alanında bulunur.

### Daha fazla dil

`npm run model:train -- --with multilingual-sms`, [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) veri kümesini ekler: 21 dile makine çevirisiyle aktarılmış SMS Spam Collection. Veri kümesinin kartı GPL lisansı belirttiği için paketle gelen modele dahil edilmemiştir; modeli paylaşma biçiminize uygun olup olmadığını denetleyin. Bu veri kümesiyle eğitildiğinde, paketle gelen modelin neredeyse hiç bilmediği diller için ayrılmış test sonuçları şöyleydi:

| Dil       | İleti | Kesinlik | Duyarlılık | Yanlış pozitif |
| --------- | ----: | -------: | ---------: | -------------: |
| Çince     |   432 |   %100,0 |      %86,1 |           %0,0 |
| Arapça    |   432 |   %100,0 |      %83,1 |           %0,0 |
| Korece    |   412 |   %100,0 |      %78,3 |           %0,0 |
| Japonca   |   486 |    %96,1 |      %87,5 |           %0,5 |
| Hintçe    |   494 |   %100,0 |      %76,2 |           %0,0 |
| Fransızca |   511 |    %98,7 |      %88,6 |           %0,6 |
| Türkçe    |   222 |   %100,0 |      %70,4 |           %0,0 |

### Yeniden eğitin

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Model dosyası

Bir model bir JSON dosyasıdır: öğrenilen spam ve ham iletilerin sayısını ve karma değerine dönüştürülmüş her özellik için o özelliği içeren spam ve ham iletilerin sayısını sıralanmış ve base64 ile kodlanmış olarak tutar. Hiçbir sözcük ve hiçbir ileti metni içermez. `--max-features` yalnızca en sık görülen özellikleri tutar, `--min-count` ise nadir olanları atar; ikisi de boyut karşılığında doğruluktan ödün verir. Paketle gelen model yaklaşık 6 MB içinde 400.000 özellik tutar.

Spam Scanner 6 ve önceki sürümlerin modelleri yüklenemez: farklı özellikleri karma değerine dönüştürüyorlardı. Aynı postadan yeni bir model eğitin.
