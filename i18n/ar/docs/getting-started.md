<!-- source: 8263c06f1dab -->

# البدء

يحتاج Spam Scanner إلى Node.js 18 أو أحدث، أو لا يحتاج إلى أي شيء مع الملف التنفيذي المستقل.


## التثبيت

كأداة سطر أوامر:

```sh
npm install --global spamscanner
spamscanner version
```

كمكتبة في مشروع Node.js:

```sh
npm install spamscanner
```

كملف تنفيذي مستقل لـ Linux أو macOS، مع Node.js والنموذج مدمجين فيه:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

الملفات التنفيذية لـ Linux (x64 وarm64) وmacOS (Intel وApple silicon) وWindows مرفقة بكل [إصدار](https://github.com/spamscanner/spamscanner/releases).


## افحص رسالة

احفظ رسالة كملف (تسمي معظم برامج البريد هذا «حفظ باسم» أو «إظهار الأصل») ثم افحصها:

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

رمز الخروج 0 للبريد المرغوب، و1 للبريد المزعج، و2 للخطأ، فتستطيع السكربتات استخدامه مباشرة. يطبع `--json` النتيجة كاملة، ويطبع `--headers` الرسالة مع إضافة ترويسات `X-Spam-*`.

يمكن أن تأتي الرسائل أيضًا من الإدخال القياسي:

```sh
cat message.eml | spamscanner scan -
```


## استخدمه من Node.js

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

يعمل CommonJS أيضًا:

```js
const SpamScanner = require('spamscanner');
```

تأخذ `scan()` الرسالة الخام على شكل Buffer أو سلسلة نصية أو Uint8Array أو تدفق قابل للقراءة. السلسلة النصية دائمًا نص رسالة: لا يقرأ Spam Scanner ملفًا أبدًا لمجرد أن السلسلة تشبه مسارًا. استخدم `scanner.scanFile(path)` للملفات.


## أخبره عن جلسة SMTP

عنوان IP للعميل، واسم مضيفه الموثَّق، واسم HELO، والمغلّف تجعل النتيجة أدق: تحتاج المصادقة إلى عنوان IP، وتحتاج قاعدة الانتحال الذاتي إلى المستلمين.

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

الشيء نفسه من سطر الأوامر:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## فعّل مزيدًا من الفحوص

لا يعمل أي منها افتراضيًا، لأن كلًا منها يحتاج إلى خدمة أو إلى قرار:

| الفحص                    | خيار المكتبة                                     | سطر الأوامر                 |
| ------------------------ | ------------------------------------------------ | --------------------------- |
| SPF وDKIM وDMARC وARC    | `authentication: true`                           | `--auth`                    |
| قائمة حظر IP             | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| قائمة حظر نطاقات للروابط | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                   | `clamav: true` أو `clamav: {socket}`             | `--clamav [socket]`         |
| نموذج لغوي               | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| قوائم السماح والمنع      | `allowlist: [...]`، `denylist: [...]`            | `--allowlist`، `--denylist` |

تُسأل محلِّلات Cloudflare الترشيحية (1.1.1.2 للبرمجيات الخبيثة، و1.1.1.3 لمحتوى البالغين) عن مضيفي الروابط افتراضيًا. أوقف ذلك بـ `phishing: {cloudflare: false}` أو `--no-cloudflare`. [ما الذي يغادر الجهاز](security.md)

لا تجيب Spamhaus وبعض قوائم الحظر الأخرى عن الاستعلامات المرسلة عبر المحلِّلات العامة مثل 8.8.8.8 أو 1.1.1.1. استخدمها مع محلِّل تخزين مؤقت محلي، وراجع شروط استخدامها بما يناسب حجم بريدك.


## الخطوات التالية

* ضعه أمام خادم بريد: [Postfix وSendmail](postfix.md)، [خوادم أخرى](mail-servers.md).
* علّمه بريدك: [التدريب](training.md).
* أضف نموذجًا لغويًا للحالات المتقاربة: [النماذج اللغوية](llm.md).
