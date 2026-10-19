<!-- source: 988243aec4f3 -->

<!--
label: Kendi sunucunuzda spam filtresi
title: Kendi posta sunucunuz için kendi barındırdığınız spam filtresi
description: Kendi sunucunuzda bir spam filtresi. Spam Scanner postayı makinede tutar, modeli pakette gelir, telemetri göndermez ve Postfix veya Exim ile çalışır.
keywords: kendi barındırılan spam filtresi, şirket içi spam filtresi, özel spam filtresi, yerel spam filtresi, posta sunucusu için spam filtresi, bulutsuz spam filtresi
-->

# Kendi barındırdığınız spam filtresi

Spam Scanner kendi sunucunuzda çalışır ve postayı orada tutar. Sınıflandırıcının modeli paketin içindedir, telemetri ya da güncelleme denetimi yoktur ve varsayılan olarak gönderdiği tek şey her bağlantının ana bilgisayar adı için bir DNS sorgusudur.


## Sunucudan ne çıkar

Varsayılan olarak yalnızca bir iletideki bağlantıların ana bilgisayar adları. Bunlar Cloudflare'in filtreleyen çözümleyicilerinde (1.1.1.2 ve 1.1.1.3) sıradan DNS sorgularıyla aranır ve iletinin ya da adreslerinin hiçbir parçası gönderilmez. `--no-cloudflare` bunu da kapatır.

Ağı kullanan diğer tüm denetimler siz açana kadar kapalıdır:

| Denetim                 | Açmak için           | Ne gönderir                                                          |
| ----------------------- | -------------------- | -------------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC   | `--auth`             | Gönderenin kayıtları için DNS sorguları                              |
| DNS engelleme listeleri | `--dnsbl`, `--uribl` | İstemcinin IP adresini ve bağlantı alan adlarını, DNS sorgusu olarak |
| ClamAV                  | `--clamav`           | Ekleri, kendi clamd'nize                                             |
| Bir dil modeli          | `--llm`              | İletinin bir özetini, belirttiğiniz sunucuya                         |

Taramalar kaydedilmez ve saklanmaz. [Güvenlik ve gizlilik](../../docs/security.md)


## Bir sunucuya kurun

```sh
npm install --global spamscanner
```

Ya da Node.js ve modelin içinde olduğu bağımsız ikili dosya:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Kurulum betiği, ikili dosyayı kurmadan önce sürümün `SHA256SUMS` dosyasıyla doğrular ve her ikili dosyanın `gh attestation verify` ile denetlenen imzalı bir derleme kaynağı onayı vardır. İkili dosyalar Linux (x64 ve arm64), macOS ve Windows içindir. Linux ikili dosyaları glibc gerektirir, bu yüzden Alpine'de npm ile kurun. [Başlarken](../../docs/getting-started.md)

Güncelleme denetimi yoktur. Güncellemek için kurulum komutunu yeniden çalıştırın: iki komut da en son sürümü kurar.


## Hizmet olarak çalıştırın

Milter, HTTP, TCP ve spamd sunucuları, `--host` aksini söylemedikçe 127.0.0.1 üzerinde dinler. Onları yetkisiz bir kullanıcı olarak, örneğin systemd altında çalıştırın:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

[Tam birim ve kurulumu](../../docs/postfix.md#1-run-the-milter) Postfix kılavuzundadır. Sunucuların hiçbiri TLS konuşmaz; başka bir makineden erişmek için özel bir ağ, SSH tüneli veya TLS'li bir ters vekil sunucu kullanın.


## Posta sunucunuzu bağlayın

| Posta sunucusu                          | Komut                                     | Bağlantı noktası |
| --------------------------------------- | ----------------------------------------- | ---------------- |
| Postfix veya Sendmail                   | `spamscanner milter`                      | 7831             |
| Postfix, hiç posta reddetmeden          | `spamscanner filter`, bir içerik filtresi | yok              |
| Exim, Haraka veya spamc                 | `spamscanner spamd`                       | 783              |
| HTTP konuşan her şey                    | `spamscanner http`                        | 7832             |
| Basit bir TCP istemcisi                 | `spamscanner server`                      | 7830             |
| Node.js ile yazılmış bir posta sunucusu | `import SpamScanner from 'spamscanner'`   | yok              |

Sunucular iletiye `X-Spam-Flag`, `X-Spam-Score` ve `X-Spam-Status` başlıklarını ekleyebilir; kitaplık ise puanı ve tetiklenen her testi döndürür. Kılavuzlar: [Postfix spam filtresi](/postfix-spam-filter/), [diğer posta sunucuları](../../docs/mail-servers.md) ve [HTTP API'si](../../docs/http-api.md).


## Dil modellerini yerel tutun

Bir dil modeli isteğe bağlıdır ve yalnızca sınırdaki iletileri okur: açık spam ve açık ham ona hiç ulaşmaz. Ollama ile aynı sunucuda çalışır, böylece hiçbir ileti sunucudan çıkmaz:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` bir CPU üzerinde çalışır. Barındırılan bir sağlayıcı kullanırsanız kişisel veriler gönderilmeden önce iletiden çıkarılır. [Dil modelleri](../../docs/llm.md)


## Kendi postanızla eğitin

Paketle gelen model, herkese açık veri kümeleriyle eğitilmiştir. Sunucunuzun aldığı postayla eğitilen bir model daha iyi sonuç verir ve o sunucuda kalır:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Bir model dosyası özniteliklerin karma değerli sayımlarını tutar; sözcükleri veya ileti metnini tutmaz. [Eğitim](../../docs/training.md)


## Gereksinimler

Linux, macOS veya Windows üzerinde Node.js 18 veya üstü; bağımsız bir ikili dosyayla hiçbir şey. ClamAV ve Ollama isteğe bağlıdır ve kendi hizmetleri olarak çalışır.
