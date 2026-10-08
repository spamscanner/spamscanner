<!-- source: 1562b843d858 -->

<!--
label: بديل SpamAssassin
title: بديل لـ SpamAssassin يتحدث بروتوكول spamd
description: استبدل spamd من SpamAssassin بـ Spam Scanner. يستمر spamc وExim وHaraka في العمل، وتحتفظ ترويسات X-Spam بأسمائها، وكل لغة مدعومة.
keywords: بديل SpamAssassin, بديل spamd, spamc, فلتر بريد مزعج Exim, Haraka spamassassin, بديل rspamd, X-Spam-Status, فلتر بريد مزعج مفتوح المصدر
-->

# بديل لـ SpamAssassin يتحدث بروتوكول spamd

يجيب Spam Scanner ببروتوكول spamd الخاص بـ SpamAssassin، فتستخدمه البرامج المكتوبة لـ SpamAssassin دون تغيير: spamc، وشرط `spam` في Exim، وإضافة `spamassassin` في Haraka، وغيرها.


## استبدله

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

يجيب عن `CHECK` و`SYMBOLS` و`REPORT` و`REPORT_IFSPAM` و`PROCESS` و`HEADERS` و`PING`، وعن `TELL` للتعلّم مع `--allow-tell`. تشغّل الاختبارات الشاملة للمشروع أداة spamc الأصلية من SpamAssassin عليه.


## ما يبقى كما هو

* الترويسات: `X-Spam-Flag` و`X-Spam-Score` و`X-Spam-Level` و`X-Spam-Status` بصيغة SpamAssassin، فتستمر قواعد Sieve وprocmail وبرامج البريد الحالية في العمل.
* درجة بعتبة 5، مكوّنة من اختبارات مسمّاة لها نقاط: `BAYES_99` و`RBL_ZEN` و`SPF_FAIL` و`DKIM_PASS` وغيرها.
* يمكن تغيير درجات كل اختبار باسمه.


## ما يختلف

* **اللغات.** تُقسَّم الكلمات وفق قواعد Unicode، فتُقرأ الصينية واليابانية والتايلاندية كلمات لا سلسلة طويلة واحدة، ويُلغى أولًا التنكّر مثل المحارف غير المرئية أو الحروف السيريلية في الكلمات اللاتينية.
* **التصيّد الاحتيالي.** تُفحص النطاقات المشابهة والروابط المخادعة وأسماء العلامات التجارية في أسماء العرض دون قواعد إضافية.
* **المرفقات** تُعرَّف من بايتاتها: الملف التنفيذي المعاد تسميته إلى `.pdf` يبقى ملفًا تنفيذيًا.
* **النماذج اللغوية.** يمكن إرسال الحالات المتقاربة إلى نموذج محلي عبر Ollama أو إلى نموذج مستضاف.
* **Node.js.** أمر `npm install` واحد، أو ملف تنفيذي مستقل؛ لا وحدات Perl ولا تحديثات قواعد لإدارتها.

لا يشغّل Spam Scanner ملفات قواعد SpamAssassin، وصيغة قاعدة بيانات Bayes الخاصة به مختلفة: درّبه من البريد نفسه باستخدام `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim وHaraka وDovecot وprocmail](../../docs/mail-servers.md)
