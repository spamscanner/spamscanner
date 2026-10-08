<!-- source: f33722183f00 -->

<!--
label: مرشِّح بريد مزعج لـ Postfix
title: فلتر بريد مزعج لـ Postfix باستخدام milter أو مرشِّح محتوى
description: رشّح البريد المزعج على خادم Postfix باستخدام milter أو مرشِّح المحتوى في Spam Scanner: الإعداد، ووحدة systemd، والرفض بـ 4xx أو 5xx، ومجلد Junk.
keywords: فلتر بريد مزعج Postfix, Postfix milter, smtpd_milters, مرشح محتوى Postfix, مكافحة البريد المزعج في Postfix, رفض البريد المزعج في Postfix, فلتر سبام Postfix
-->

# مرشِّح بريد مزعج لـ Postfix

يرشّح Spam Scanner خادم Postfix في نحو خمس دقائق. يعمل كـ milter، فيسأله Postfix عن كل رسالة أثناء جلسة SMTP ويستطيع رفض البريد المزعج قبل قبوله.


## التثبيت والتشغيل

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

يفحص `--auth` كلًا من SPF وDKIM وDMARC وARC؛ ويَسِم `--subject-tag` البريد المزعج في العنوان. تحصل كل رسالة على ترويسات `X-Spam-Flag` و`X-Spam-Score` و`X-Spam-Status` و`X-Spam-Action`، وتُحذف أولًا أي ترويسة `X-Spam-*` وضعها المرسل.


## اربط Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

يسمح `milter_default_action = accept` بمرور البريد دون ترشيح إذا كان الـ milter متوقفًا؛ أما `tempfail` فيطلب من المرسلين إعادة المحاولة بدلًا من ذلك.


## ارفض البريد المزعج أثناء جلسة SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

تُرفض الرسائل التي تبلغ عتبة الرفض (15 نقطة) بالرد `451 4.7.1 Message rejected as spam`. الرد 451 مؤقت: يحتفظ المرسل بالرسالة ويعيد المحاولة، فالقرار الخاطئ يكلّف تأخيرًا لا رسالة مفقودة. بعد أن تبدو النتائج صحيحة، يجعل `--reject-code 550` الرفض دائمًا.


## دون milter

يعمل مرشِّح المحتوى بعد أن يقبل Postfix الرسالة: يمرّرها Postfix عبر أنبوب إلى `spamscanner filter`، الذي يضيف الترويسات ويعيدها. لا يُرفض أي شيء أبدًا أثناء الجلسة، والفشل يؤجل التسليم دائمًا بدل ارتداد البريد. [إعداد مرشِّح المحتوى](../../docs/postfix.md#content-filter)


## البريد المزعج إلى Junk

مع Dovecot، تنقل قاعدة Sieve البريد الموسوم:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## مُختبَر مع Postfix حقيقي

تشغّل الاختبارات الشاملة للمشروع Postfix مع الـ milter ومرشِّح المحتوى: يُسلَّم البريد المرغوب مع الترويسات وتُحذف ترويسة `X-Spam-Flag` المزوّرة، ويُوسم البريد المزعج، ويُرفض GTUBE بالرد 550 أثناء جلسة SMTP.

التالي: [دليل Postfix وSendmail الكامل](../../docs/postfix.md)، مع وحدة systemd و`INPUT_MAIL_FILTER` الخاص بـ Sendmail.
