<!-- source: 0378a5e0f12b -->

<!--
label: Kimlik avı tespiti
title: Kimlik avı tespiti: benzer alan adları ve yanıltıcı bağlantılar
description: Spam Scanner kimlik avını nasıl tespit eder: Unicode benzer alan adları, başka adrese giden bağlantılar, marka görünen adları, Cloudflare ve DMARC.
keywords: kimlik avı tespiti, oltalama tespiti, phishing tespiti, e-posta kimlik avı filtresi, homograf saldırısı, IDN homograf, benzer alan adı tespiti, yanıltıcı bağlantı, marka taklidi e-posta
-->

# E-postada kimlik avı tespiti

Kimlik avı, başka biri gibi görünerek işler. Spam Scanner kamuflajın kendini ele verdiği yerleri denetler.


## Benzer alan adları

Bir bağlantıdaki her alan adı, Unicode karıştırılabilir karakterler tablosuyla bir iskelete indirgenir ve sık taklit edilen yaklaşık 100 markayla karşılaştırılır:

| Alan adı                            | Yakalanma nedeni             |
| ----------------------------------- | ---------------------------- |
| `pаypal.com` (Kiril а)              | Karıştırılabilir karakterler |
| `paypa1-secure.top`                 | Yer değiştirmiş karakterler  |
| `xn--pple-43d.com`                  | `аpple.com` için Punycode    |
| `paypal.com.account-verify.example` | Başkasının alan adında marka |
| `paypall.com`                       | Bir harf farkı               |

Marka eklenebilir ve sahip olduğunuz alan adları izin listesine alınabilir.


## Yanıltıcı bağlantılar

Metni bir adres, hedefi başka bir adres olan bir HTML bağlantısı, örneğin `http://paypa1-secure.top/login` adresini gösteren `https://www.paypal.com/signin` metni, 3 puan ekler.


## Görünen adlar ve sahtecilik

* Başka bir alan adındaki bir adresten gelen, bir marka içeren görünen ad ("PayPal Security").
* Farklı bir e-posta adresi içeren görünen ad.
* Alıcının kendi alan adından geldiğini iddia eden ve SPF, DKIM ve DMARC denetimlerinden geçemeyen posta.


## Bilinen kötü siteler

Bağlantı ana makineleri, bilinen kötü amaçlı yazılım ve kimlik avı sitelerini engelleyen Cloudflare'in 1.1.1.2 çözümleyicisinde ve isteğe bağlı olarak Spamhaus DBL gibi alan adı engelleme listelerinde sorgulanır.


## Ekler

Kimlik avı, çevrimdışı sahte bir oturum açma sayfası çizen HTML ekleri ve adı `.pdf` olarak değiştirilmiş yürütülebilir dosyalar biçiminde de gelir. İkisi de içerikleriyle bulunur.

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

[Denetimler nasıl çalışır](../../docs/how-it-works.md#phishing)
