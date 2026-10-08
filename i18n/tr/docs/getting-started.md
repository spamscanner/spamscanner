<!-- source: 8263c06f1dab -->

# Başlarken

Spam Scanner, Node.js 18 veya üzerini gerektirir; bağımsız ikili dosyayla ise hiçbir şey gerektirmez.


## Kurulum

Komut satırı aracı olarak:

```sh
npm install --global spamscanner
spamscanner version
```

Bir Node.js projesinde kitaplık olarak:

```sh
npm install spamscanner
```

Node.js'i ve modeli içeren, Linux veya macOS için bağımsız bir ikili dosya olarak:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Linux (x64 ve arm64), macOS (Intel ve Apple silicon) ve Windows ikili dosyaları her [sürüme](https://github.com/spamscanner/spamscanner/releases) eklenir.


## Bir ileti tarayın

Bir iletiyi dosya olarak kaydedin (çoğu posta programı buna "Farklı kaydet" veya "Orijinali göster" der) ve tarayın:

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

Çıkış kodu ham için 0, spam için 1 ve hata için 2'dir; bu nedenle betikler onu doğrudan kullanabilir. `--json` sonucun tamamını yazdırır, `--headers` ise `X-Spam-*` üst bilgileri eklenmiş iletiyi yazdırır.

İletiler standart girdiden de gelebilir:

```sh
cat message.eml | spamscanner scan -
```


## Node.js'ten kullanın

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJS de çalışır:

```js
const SpamScanner = require('spamscanner');
```

`scan()` ham iletiyi bir Buffer, bir dize, bir Uint8Array veya okunabilir bir akış olarak alır. Dize her zaman ileti metnidir: Spam Scanner bir dize dosya yoluna benziyor diye hiçbir zaman dosya okumaz. Dosyalar için `scanner.scanFile(path)` kullanın.


## SMTP oturumunu bildirin

İstemcinin IP adresi, doğrulanmış ana makine adı, HELO adı ve zarf bilgisi sonucu daha doğru kılar: kimlik doğrulama IP adresine, kendi alan adını taklit etme kuralı ise alıcılara ihtiyaç duyar.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

Komut satırından aynısı:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Daha fazla denetimi açın

Bunların hiçbiri varsayılan olarak açık değildir, çünkü her biri bir hizmet veya bir karar gerektirir:

| Denetim                                     | Kitaplık seçeneği                                | Komut satırı                |
| ------------------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC                       | `authentication: true`                           | `--auth`                    |
| IP engelleme listesi                        | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Bağlantılar için alan adı engelleme listesi | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                                      | `clamav: true` veya `clamav: {socket}`           | `--clamav [socket]`         |
| Bir dil modeli                              | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| İzin ve engelleme listeleri                 | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Cloudflare'in filtreleme yapan çözümleyicilerine (kötü amaçlı yazılım için 1.1.1.2, yetişkin içerik için 1.1.1.3) bağlantı ana makineleri varsayılan olarak sorulur. Bunu `phishing: {cloudflare: false}` veya `--no-cloudflare` ile kapatın. [Makineden ne çıkar](security.md)

Spamhaus ve diğer bazı engelleme listeleri, 8.8.8.8 veya 1.1.1.1 gibi herkese açık çözümleyiciler üzerinden gönderilen sorgulara yanıt vermez. Bunları yerel bir önbellekli çözümleyiciyle kullanın ve hacminiz için kullanım koşullarını denetleyin.


## Sonraki adımlar

* Bir posta sunucusunun önüne koyun: [Postfix ve Sendmail](postfix.md), [diğer sunucular](mail-servers.md).
* Ona kendi postanızı öğretin: [eğitim](training.md).
* Kararsız kalınan durumlar için bir dil modeli ekleyin: [dil modelleri](llm.md).
