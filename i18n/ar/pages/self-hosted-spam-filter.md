<!-- source: 988243aec4f3 -->

<!--
label: مرشِّح بريد مزعج مستضاف ذاتيًا
title: مرشِّح بريد مزعج مستضاف ذاتيًا لخادم بريدك
description: مرشِّح بريد مزعج على خادمك. يُبقي Spam Scanner البريد على الجهاز، ويأتي نموذجه داخل الحزمة، ولا يرسل قياسات عن بُعد، ويتصل بـ Postfix أو Exim.
keywords: مرشِّح بريد مزعج مستضاف ذاتيًا، مرشِّح بريد مزعج محلي، مرشِّح بريد مزعج خاص، مرشِّح بريد مزعج لخادم البريد، مرشِّح بريد مزعج بلا سحابة
-->

# مرشِّح بريد مزعج مستضاف ذاتيًا

يعمل Spam Scanner على خادمك ويُبقي البريد هناك. نموذج المصنِّف داخل الحزمة، ولا توجد قياسات عن بُعد ولا تحقق من التحديثات، وافتراضيًا لا يرسل سوى استعلام DNS عن اسم المضيف في كل رابط.


## ما الذي يغادر الخادم

افتراضيًا، أسماء المضيفين في روابط الرسالة فقط. يُبحث عنها لدى محلِّلات Cloudflare المرشِّحة (1.1.1.2 و1.1.1.3) باستعلامات DNS عادية، ولا يُرسل أي جزء من الرسالة أو عناوينها. ويُوقف `--no-cloudflare` هذا أيضًا.

كل فحص آخر يستخدم الشبكة يبقى متوقفًا حتى تشغّله:

| الفحص                 | يُشغَّل بـ           | ما الذي يرسله                                   |
| --------------------- | -------------------- | ----------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | استعلامات DNS عن سجلات المرسل                   |
| قوائم حظر DNS         | `--dnsbl`, `--uribl` | عنوان IP للعميل ونطاقات الروابط، كاستعلامات DNS |
| ClamAV                | `--clamav`           | المرفقات، إلى clamd الخاص بك                    |
| نموذج لغوي            | `--llm`              | ملخّص للرسالة، إلى الخادم الذي تحدده            |

لا تُسجَّل عمليات الفحص ولا تُحفظ. [الأمان والخصوصية](../../docs/security.md)


## التثبيت على خادم

```sh
npm install --global spamscanner
```

أو الملف التنفيذي المستقل، مع Node.js والنموذج مدمجين:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

يتحقق سكربت التثبيت من الملف التنفيذي مقابل ملف `SHA256SUMS` الخاص بالإصدار قبل تثبيته، ولكل ملف تنفيذي شهادة موقَّعة بمصدر البناء يتحقق منها `gh attestation verify`. تتوفر ملفات لـ Linux (x64 وarm64) وmacOS وWindows. تحتاج ملفات Linux إلى glibc، لذا ثبّت عبر npm على Alpine. [البدء](../../docs/getting-started.md)

لا يوجد تحقق من التحديثات. للتحديث، شغّل أمر التثبيت مرة أخرى: كلا الأمرين يثبّت أحدث إصدار.


## التشغيل كخدمة

تستمع خوادم milter وHTTP وTCP وspamd على 127.0.0.1 ما لم يحدد `--host` غير ذلك. شغّلها بمستخدم بلا صلاحيات، مثلًا تحت systemd:

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

[الوحدة الكاملة وإعدادها](../../docs/postfix.md#1-run-the-milter) في دليل Postfix. لا يدعم أي من الخوادم TLS، فللوصول إلى أحدها من جهاز آخر استخدم شبكة خاصة أو نفق SSH أو وكيلًا عكسيًا مع TLS.


## ربط خادم بريدك

| خادم البريد                   | الأمر                                   | المنفذ  |
| ----------------------------- | --------------------------------------- | ------- |
| Postfix أو Sendmail           | `spamscanner milter`                    | 7831    |
| Postfix دون رفض أي بريد أبدًا | `spamscanner filter`، مرشِّح محتوى      | لا يوجد |
| Exim أو Haraka أو spamc       | `spamscanner spamd`                     | 783     |
| أي شيء يتحدث HTTP             | `spamscanner http`                      | 7832    |
| عميل TCP بسيط                 | `spamscanner server`                    | 7830    |
| خادم بريد مكتوب بـ Node.js    | `import SpamScanner from 'spamscanner'` | لا يوجد |

يمكن للخوادم إضافة الترويسات `X-Spam-Flag` و`X-Spam-Score` و`X-Spam-Status` إلى الرسالة، وتعيد المكتبة الدرجة وكل اختبار انطبق. الأدلة: [مرشِّح بريد مزعج لـ Postfix](/postfix-spam-filter/)، و[خوادم بريد أخرى](../../docs/mail-servers.md)، و[واجهة HTTP](../../docs/http-api.md).


## إبقاء النماذج اللغوية محلية

النموذج اللغوي اختياري ولا يقرأ إلا الحالات الملتبسة: البريد المزعج الواضح والـ ham الواضح لا يصلان إليه أبدًا. مع Ollama يعمل على الخادم نفسه، فلا تغادره أي رسالة:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

يعمل `qwen3.5:4b` على معالج CPU. أما مع مزوّد مستضاف فتُزال البيانات الشخصية من الرسالة قبل إرسالها. [النماذج اللغوية](../../docs/llm.md)


## تدريبه على بريدك

النموذج المرفق مدرَّب على مجموعات بيانات عامة. النموذج المدرَّب على البريد الذي يستقبله خادمك أفضل أداءً، ويبقى على ذلك الخادم:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

يحتوي ملف النموذج على أعداد مجزّأة للسمات، لا على كلمات أو نصوص رسائل. [التدريب](../../docs/training.md)


## المتطلبات

Node.js 18 أو أحدث على Linux أو macOS أو Windows، أو لا شيء مع ملف تنفيذي مستقل. ClamAV وOllama اختياريان ويعملان كخدمتين مستقلتين.
