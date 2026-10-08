<!-- source: 6f6b765c5fc1 -->

# Testler ve puanlar

Bir ileti 5 puanda spamdır ve 15 puanda reddedilir. Aşağıdaki her test puan ekler veya düşer; sonuç tetiklenen testleri listeler.

Eşikleri `threshold` ve `rejectThreshold` ile değiştirin. Puanları `scores` ile değiştirin: ya ayar anahtarına göre (`scores: {deceptiveLink: 4}`) ya da o testin puanını sabitleyen test adına göre (`scores: {FROM_NAME_BRAND: 4}`).


## Sınıflandırıcı

| Test                             | Puan                 | Anlamı                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` ile `BAYES_999` arası | -2,5 ile +6,25 arası | Sınıflandırıcının log-odds ölçeğindeki spam olasılığı: %90'da 2,4 puan, %99'da 5 ve %99,9'da 6,25; böylece sınıflandırıcı tek başına yalnızca en az %99 emin olduğunda spam işaretler. Ad aralığı belirtir: `BAYES_999` %99,9 veya üzeri, `BAYES_99` %99 ile %99,9 arası, `BAYES_50` %40 ile %60 arası. `bayesHam` ve `bayesSpam` ayar anahtarları iki ucu belirler. |


## Kimlik avı ve bağlantılar

| Test                        | Puan | Ayar anahtarı       | Anlamı                                                                                                  |
| --------------------------- | ---: | ------------------- | ------------------------------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |    5 | `homograph`         | Bir bağlantının alan adı, benzer görünümlü veya yer değiştirmiş karakterlerle bir markayı taklit ediyor |
| `MIXED_SCRIPT_DOMAIN`       |    3 | `mixedScriptDomain` | Bir alan adı etiketi alfabeleri karıştırıyor                                                            |
| `BRAND_IN_DOMAIN`           |  1,5 | `brandInDomain`     | Başkasının alan adının içinde bir marka adı                                                             |
| `TYPO_DOMAIN`               |    1 | `typoDomain`        | Bir markanın alan adından bir harf farkı                                                                |
| `DECEPTIVE_LINK`            |    3 | `deceptiveLink`     | Bir bağlantı bir adres gösteriyor ve başka bir adrese gidiyor                                           |
| `MALICIOUS_DOMAIN`          |    6 | `maliciousDomain`   | Cloudflare'in kötü amaçlı yazılım çözümleyicisi bağlantı verilen bir alan adını engelliyor              |
| `ADULT_DOMAIN`              |    2 | `adultDomain`       | Cloudflare'in aile çözümleyicisi bağlantı verilen bir alan adını engelliyor                             |
| `URIBL_<LIST>`              |    5 | `uriblListed`       | Bağlantı verilen bir alan adı bir alan adı engelleme listesinde, örneğin `URIBL_DBL`                    |


## Ekler

| Test                    |     Puan | Ayar anahtarı                            | Anlamı                                                             |
| ----------------------- | -------: | ---------------------------------------- | ------------------------------------------------------------------ |
| `EXECUTABLE_ATTACHMENT` |       10 | `executable`                             | Bir program veya betik                                             |
| `DISGUISED_EXECUTABLE`  |       12 | `disguisedExecutable`                    | Belge veya görüntü gibi adlandırılmış bir program                  |
| `DOUBLE_EXTENSION`      |        6 | `doubleExtension`                        | `invoice.pdf.exe` gibi bir ad                                      |
| `RTL_OVERRIDE_FILENAME` |        6 | `rtlOverride`                            | Sağdan sola geçersiz kılma karakteri gerçek uzantıyı gizliyor      |
| `EXECUTABLE_IN_ARCHIVE` |        8 | `executableInArchive`                    | Bir ZIP dosyasının içinde bir program                              |
| `ENCRYPTED_ARCHIVE`     |        2 | `encryptedArchive`                       | Tarayıcıların açamadığı bir arşiv                                  |
| `MACRO_ATTACHMENT`      |        4 | `macro`                                  | Makro içeren bir Office dosyası                                    |
| `PDF_ACTIVE_CONTENT`    |        3 | `pdfActive`                              | JavaScript, başlatma eylemleri veya gömülü dosyalar içeren bir PDF |
| `RTF_EMBEDDED_OBJECT`   |        4 | `rtfObject`                              | Gömülü nesneler içeren bir RTF dosyası                             |
| `HTML_ATTACHMENT`       | 1 veya 3 | `htmlAttachment`, `activeHtmlAttachment` | Bir HTML dosyası; betik veya form içeriyorsa 3                     |
| `VIRUS`                 |      100 | `virus`                                  | ClamAV bir virüs buldu                                             |


## Kurallar

| Test                      | Puan | Anlamı                                                                                                             |
| ------------------------- | ---: | ------------------------------------------------------------------------------------------------------------------ |
| `GTUBE`                   | 1000 | GTUBE test dizisi                                                                                                  |
| `SEXTORTION_SUBJECT`      |    6 | Şantaj (sextortion) ve hesap ele geçirme dolandırıcılıklarında kullanılan bir konu                                 |
| `PAYPAL_INVOICE`          |    6 | Dolandırıcılık için kötüye kullanılan bir kanal olan PayPal faturası veya para talebi                              |
| `MICROSOFT_SPAM_VERDICT`  |    5 | Microsoft iletiyi aktarmadan önce spam olarak işaretlemiş (yalnızca Microsoft sunucularından geldiğinde güvenilir) |
| `MICROSOFT_HIGH_SCL`      |    3 | Microsoft iletiye yüksek bir spam güven düzeyi (SCL) vermiş (aynı koşulla)                                         |
| `PROMPT_INJECTION`        |    3 | Bir yapay zekâ filtresine hitap eden metin                                                                         |
| `SELF_SPOOF`              |    3 | Alıcının kendi alan adından geldiğini iddia ediyor ve kimlik doğrulamadan geçemiyor                                |
| `FROM_NAME_OTHER_ADDRESS` |  2,5 | Görünen ad farklı bir e-posta adresi içeriyor                                                                      |
| `FROM_NAME_BRAND`         |    2 | Görünen ad, adresin ait olmadığı bir markayı iddia ediyor                                                          |
| `DATE_IN_FUTURE`          |    1 | Tarihi bir günden daha ileride                                                                                     |
| `MISSING_DATE`            |  0,5 | Date üst bilgisi yok                                                                                               |
| `MISSING_MESSAGE_ID`      |  0,5 | Message-ID üst bilgisi yok                                                                                         |

En az spam eşiği değerinde olan kurallar, önceki sürümlerde olduğu gibi `results.arbitrary` içinde de görünür.


## Gizleme ve dil

| Test                   | Puan | Ayar anahtarı         | Anlamı                                                               |
| ---------------------- | ---: | --------------------- | -------------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |    2 | `invisibleCharacters` | Metnin içinde üç veya daha fazla görünmez karakter                   |
| `MIXED_SCRIPT_WORDS`   |  2,5 | `mixedScriptWords`    | İki veya daha fazla sözcük farklı alfabelerden harfleri karıştırıyor |
| `STYLED_LETTERS`       |  1,5 | `styledLetters`       | Düz metin kılığına girmiş matematiksel veya çerçeveli harfler        |
| `LANGUAGE_NOT_ALLOWED` |    3 | `languageNotAllowed`  | `allowedLanguages` içinde değil                                      |


## Kimlik doğrulama

İstemcinin IP adresini ve `authentication: true` ayarını gerektirir.

| Test           | Puan | Ayar anahtarı (`authentication.weights` içinde) |
| -------------- | ---: | ----------------------------------------------- |
| `SPF_PASS`     | -0,5 | `spfPass`                                       |
| `SPF_FAIL`     |    2 | `spfFail`                                       |
| `SPF_SOFTFAIL` |    1 | `spfSoftfail`                                   |
| `DKIM_PASS`    | -0,5 | `dkimPass`                                      |
| `DKIM_FAIL`    |    1 | `dkimFail`                                      |
| `DMARC_PASS`   | -1,5 | `dmarcPass`                                     |
| `DMARC_FAIL`   |  3,5 | `dmarcFail`                                     |
| `ARC_PASS`     | -0,5 | `arcPass`                                       |
| `ARC_FAIL`     |    1 | `arcFail`                                       |


## İtibar ve engelleme listeleri

| Test           | Puan | Ayar anahtarı | Anlamı                                                            |
| -------------- | ---: | ------------- | ----------------------------------------------------------------- |
| `DENYLISTED`   |  100 | `denylisted`  | Göndericinin IP adresi, alan adı veya adresi engelleme listesinde |
| `ALLOWLISTED`  |  -20 | `allowlisted` | İzin listesinde                                                   |
| `TRUTH_SOURCE` |   -5 | `truthSource` | Bir itibar hizmeti göndericiyi güvenilir olarak işaretliyor       |
| `RBL_<LIST>`   |    4 | `rblListed`   | İstemcinin IP adresi bir engelleme listesinde, örneğin `RBL_ZEN`  |


## Dil modeli ve isteğe bağlı modeller

| Test                                                  | Puan        | Ayar anahtarı | Anlamı                                                   |
| ----------------------------------------------------- | ----------- | ------------- | -------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | en fazla +6 | `llmSpam`     | Modelin kararı, güven değeriyle çarpılmış                |
| `LLM_HAM`                                             | en fazla -3 | `llmHam`      | Aynı şekilde                                             |
| `TOXIC_CONTENT`                                       | 3           | `toxicity`    | Sağladığınız bir zehirlilik modeli metni işaretledi      |
| `NSFW_IMAGE`                                          | 3           | `nsfw`        | Sağladığınız bir görüntü modeli bir görüntüyü işaretledi |
