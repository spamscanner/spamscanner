<!-- source: a59bc5927d86 -->

# Komut satırı

```text
spamscanner <command> [options]
```

| Komut                                      | Ne yapar                                                                                 |
| ------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Bir dosyadan veya standart girdiden gelen iletiyi tarar                                  |
| `filter -f <sender> -- <recipients...>`    | Postfix içerik filtresi: standart girdiyi tarar, üst bilgileri ekler, iletiyi aktarır    |
| `milter`                                   | Postfix ve Sendmail için milter, bağlantı noktası 7831                                   |
| `http`                                     | HTTP API, bağlantı noktası 7832                                                          |
| `server`                                   | Düz TCP sunucusu, bağlantı noktası 7830                                                  |
| `spamd`                                    | SpamAssassin uyumlu spamd sunucusu, bağlantı noktası 783                                 |
| `train`                                    | mbox dosyalarından, Maildir'lerden, klasörlerden veya veri kümelerinden bir model eğitir |
| `eval`                                     | Bir modeli etiketlenmiş posta üzerinde ölçer                                             |
| `learn spam\|ham [file\|-] --model <file>` | Bir modele bir ileti öğretir                                                             |
| `llm-test`                                 | Dil modeli ayarlarını üç örnek iletiyle denetler                                         |
| `models`                                   | Önerilen açık modelleri listeler                                                         |
| `version`, `help`                          |                                                                                          |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Seçenek                    | Anlamı                                                           |
| -------------------------- | ---------------------------------------------------------------- |
| `--json`                   | Sonucun tamamını JSON olarak yazdırır                            |
| `--headers`                | İletiyi `X-Spam-*` üst bilgileri eklenmiş olarak yazdırır        |
| `--subject-tag <tag>`      | Ayrıca spamın konusunun başına ekler                             |
| `--verbose`                | Her testi ve sınıflandırıcının en güçlü ipuçlarını gösterir      |
| `--threshold <n>`          | Postanın spam sayıldığı puan (varsayılan 5)                      |
| `--reject-threshold <n>`   | Postanın reddedildiği puan (varsayılan 15)                       |
| `--model <file>`           | Paketle gelen model yerine bir model dosyası                     |
| `--no-classifier`          | Sınıflandırıcıyı kullanmaz                                       |
| `--config <file>`          | [Kitaplık seçeneklerini](api.md#options) içeren bir JSON dosyası |
| `--allow-language <codes>` | Kabul edilen diller, örneğin `en,de,fr`                          |

Çıkış kodları: 0 ham, 1 spam, 2 hata.

### SMTP oturumu

| Seçenek             | Anlamı                                          |
| ------------------- | ----------------------------------------------- |
| `--ip <address>`    | İletiyi gönderen istemcinin IP adresi           |
| `--hostname <name>` | İstemcinin doğrulanmış ters DNS adı             |
| `--helo <name>`     | İstemcinin HELO veya EHLO'da verdiği ad         |
| `--from <address>`  | Zarf göndericisi (MAIL FROM)                    |
| `--to <address>`    | Zarf alıcısı; birden çok alıcı için tekrarlayın |

### Denetimler

| Seçenek               | Anlamı                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------- |
| `--auth`              | SPF, DKIM, DMARC ve ARC denetimi yapar (`--ip` gerektirir)                               |
| `--dnsbl <zone>`      | IP engelleme listesi, örneğin `zen.spamhaus.org`; tekrarlanabilir                        |
| `--uribl <zone>`      | Bağlantılar için alan adı engelleme listesi, örneğin `dbl.spamhaus.org`; tekrarlanabilir |
| `--dns-server <ip>`   | DNS denetimleri için ad sunucusu; tekrarlanabilir                                        |
| `--no-cloudflare`     | Bağlantıları Cloudflare'in filtreleme yapan çözümleyicilerine sormaz                     |
| `--clamav [socket]`   | Ekleri varsayılan soketindeki ya da belirtilen soketteki clamd ile tarar                 |
| `--allowlist <value>` | Bu IP adresini, alan adını veya adresi her zaman kabul eder; tekrarlanabilir             |
| `--denylist <value>`  | Bu IP adresini, alan adını veya adresi her zaman reddeder; tekrarlanabilir               |

### Dil modeli

| Seçenek                                                    | Anlamı                                                                             |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` ve diğerleri ([liste](llm.md#providers)) |
| `--llm-model <name>`                                       | Model, örneğin `qwen3.5:4b` veya `claude-haiku-4-5`                                |
| `--llm-url <url>`                                          | Temel URL, örneğin `http://10.0.0.5:11434`                                         |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Sağlayıcı URL'sinin bir parçasını değiştirir                                       |
| `--llm-api-key <key>`                                      | API anahtarı; aşağıdaki ortam değişkenlerine de bakın                              |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` veya `none`                    |
| `--llm-auth-header <name>`                                 | `--llm-auth header` ile birlikte anahtar için üst bilgi                            |
| `--llm-username`, `--llm-password`                         | `--llm-auth basic` için                                                            |
| `--llm-header "Name: value"`                               | Ek istek üst bilgisi; tekrarlanabilir                                              |
| `--llm-mode <mode>`                                        | `auto` (yalnızca sınırdaki durumlar, varsayılan) veya `always`                     |
| `--llm-timeout <ms>`                                       | Varsayılan 30000                                                                   |
| `--llm-policy <text>`                                      | Model için ek kurallar, örneğin "Asla e-postayla fatura göndermeyiz"               |
| `--llm-redact`, `--no-llm-redact`                          | Önce kişisel verileri çıkarır; uzak sağlayıcılar için varsayılan olarak açık       |


## filter

Bir [Postfix içerik filtresi](postfix.md#content-filter). Standart girdiden bir ileti okur, `X-Spam-*` üst bilgilerini ekler ve iletiyi aynı zarfla sendmail'e aktarır.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Seçenek               | Anlamı                                                    |
| --------------------- | --------------------------------------------------------- |
| `--sendmail <path>`   | Varsayılan `/usr/sbin/sendmail`                           |
| `--subject-tag <tag>` | Spamın konusunun başına ekler                             |
| `--reject`            | Reddetme eşiğindeki postayı aktarmak yerine geri döndürür |
| `--discard`           | Reddetme eşiğindeki postayı aktarmak yerine atar          |

Çıkış kodları, Postfix'in okuduğu sendmail kurallarını izler: 0 teslim edildi (veya atıldı), 64 alıcı belirtilmedi, 69 spam olarak reddedildi (Postfix iletiyi geri döndürür), 75 herhangi bir hata; böylece Postfix iletiyi saklar ve daha sonra yeniden dener.


## milter, http, server ve spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

783, SpamAssassin istemcilerinin varsayılan olarak kullandığı bağlantı noktasıdır. 1024'ün altındaki bağlantı noktaları root yetkisi veya `CAP_NET_BIND_SERVICE` yeteneği gerektirir; `--port 7833` gibi başka bir bağlantı noktası kullanın ve bunu istemciye bildirin.

| Seçenek               | Anlamı                                                                                |
| --------------------- | ------------------------------------------------------------------------------------- |
| `--port <n>`          | TCP bağlantı noktası                                                                  |
| `--host <ip>`         | Dinlenecek adres (varsayılan 127.0.0.1)                                               |
| `--socket <path>`     | Bunun yerine bir Unix soketini dinler                                                 |
| `--reject`            | Milter: reddetme eşiğindeki postayı geri çevirir                                      |
| `--reject-code <n>`   | Milter: 451, daha sonra yeniden dene (varsayılan) veya 550                            |
| `--quarantine`        | Milter: spamı posta sunucusunun karantinasında bekletir                               |
| `--name <hostname>`   | Milter: Authentication-Results içinde bu sunucunun adı                                |
| `--token <secret>`    | HTTP: `Authorization: Bearer <secret>` gerektirir; `/learn` için zorunludur           |
| `--allow-tell`        | spamd: öğrenmek için TELL isteklerini (`spamc -L spam`) kabul eder                    |
| `--out <file>`        | HTTP ve spamd: öğrenilenleri bu model dosyasına kaydeder                              |
| `--subject-tag <tag>` | Milter ve spamd: spamın konusunun başına ekler                                        |
| `--verbose`           | Milter: her taramayı günlüğe yazar. TCP sunucusu: tek bir metin satırıyla yanıt verir |

Yukarıdaki tarama seçenekleri sunucular için de geçerlidir. [Milter](postfix.md#milter), [HTTP API, TCP sunucusu ve spamd](http-api.md).


## train, eval ve learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Seçenek                                         | Anlamı                                                                                           |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `--spam <path>`                                 | Spam: bir mbox dosyası, bir Maildir veya `.eml` dosyalarından oluşan bir klasör; tekrarlanabilir |
| `--ham <path>`                                  | Ham, aynı şekilde; tekrarlanabilir                                                               |
| `--dataset <file>`                              | Metin ve etiket sütunları içeren bir CSV veya JSON Lines dosyası; tekrarlanabilir                |
| `--text-column <name>`, `--label-column <name>` | Kendiliğinden tespit edilmediklerinde sütun adları                                               |
| `--out <file>`                                  | Modelin yazılacağı yer (varsayılan `spamscanner-model.json`)                                     |
| `--merge`                                       | Boş bir model yerine paketle gelen modelden (veya `--model`) başlar                              |

`learn` model dosyasını yerinde günceller; ilk seferde dosyayı paketle gelen modelden oluşturur. [Eğitim](training.md)


## llm-test ve models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` modele İngilizce ve İtalyanca olarak bir sıradan ileti ve iki dolandırıcılık iletisi gönderir, kararlarını yazdırır ve yalnızca üçü de doğruysa 0 koduyla çıkar.


## Yapılandırma dosyası

`--config file.json` (veya `SPAMSCANNER_CONFIG` ortam değişkeni) [kitaplık seçeneklerini](api.md#options) yükler. Komut satırı seçenekleri dosyadakileri geçersiz kılar.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Ortam değişkenleri

| Değişken                                                                                                                                                                                                                                             | Anlamı                                                |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | Yapılandırma dosyası                                  |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | Paketle gelen model yerine kullanılan model dosyası   |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | HTTP API için belirteç                                |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | Herhangi bir dil modeli sağlayıcısı için API anahtarı |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Her sağlayıcının kendi anahtarı                       |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | Hata ayıklama günlüğü                                 |
