<!-- source: 599bd320e55a -->

<!--
label: حول
title: حول Spam Scanner وترخيصه والخصوصية
description: من يصنع Spam Scanner، وكيف تبلّغ عن خطأ أو ثغرة، وترخيصه، وما الذي يجمعه هذا الموقع: لا ملفات تعريف ارتباط ولا تحليلات.
keywords: حول Spam Scanner، Forward Email، ترخيص Spam Scanner، BUSL-1.1، التواصل مع Spam Scanner، خصوصية Spam Scanner
-->

# حول Spam Scanner

Spam Scanner مرشِّح بريد مزعج صنعته [Forward Email](https://forwardemail.net)، خدمة البريد التي تركّز على الخصوصية، لخوادم بريدها. الشيفرة المصدرية والبلاغات والإصدارات على [GitHub](https://github.com/spamscanner/spamscanner)، والحزمة على [npm](https://www.npmjs.com/package/spamscanner).


## من يصنعه

يكتب فريق Forward Email برنامج Spam Scanner ويصونه. لا تحتفظ Forward Email بسجلات لمحتوى الرسائل، لذا لم يكن بوسعها إرسال البريد إلى خدمة ترشيح خارجية: كان على المرشِّح أن يعمل على خوادمها وأن يشرح كل قرار دون أن يقرأ أحد البريد. [كيف تستخدمه Forward Email](../../docs/forward-email.md)

Forward Email مفتوحة المصدر أيضًا، على [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). كان مؤسسها من أوائل موظفي DuckDuckGo.


## التواصل

* **الأسئلة والأخطاء وطلبات الميزات:** افتح بلاغًا على [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **الثغرات الأمنية:** أبلغ عنها بشكل خاص عبر [نظام الإبلاغ عن الثغرات في GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new)، لا في البلاغات العامة. العنوان نفسه موجود في [security.txt](https://spamscanner.net/.well-known/security.txt).
* **تراخيص أخرى:** تواصل مع [Forward Email](https://forwardemail.net).


## شروط الترخيص

[ترخيص](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) Spam Scanner هو Business Source License 1.1، وترخيص التغيير (Change License) فيه هو Apache License 2.0. وقد مضى تاريخ التغيير (Change Date) المذكور في الترخيص، ومنذ ذلك التاريخ يمنحك الترخيص حقوقًا بموجب Apache License 2.0.


## الخصوصية

لا يضع هذا الموقع ملفات تعريف ارتباط ولا يحمّل تحليلات أو أدوات تتبع أو إعلانات أو خطوطًا أو سكربتات من مواقع أخرى. كل ملف يأتي من spamscanner.net.

* يُحفظ المظهر واللغة التي تختارها وخادم Mastodon الذي تشارك إليه في التخزين المحلي لمتصفحك، ولا تُرسل إلى أي مكان.
* لا يُحمَّل الفيديو إلا عند تشغيله.
* روابط المشاركة روابط عادية، فلا يُحمَّل شيء من تلك الشبكات حتى تتبع أحدها.
* الموقع مستضاف على GitHub Pages، ويسجّل GitHub عنوان IP لكل زائر لأغراض أمنية. انظر [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) و[بيان الخصوصية العام لـ GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## ما الذي يرسله البرنامج

لا يرسل Spam Scanner قياسات عن بُعد ولا يبحث عن تحديثات. افتراضيًا يبحث عن أسماء المضيفين في روابط الرسالة لدى محلِّلات DNS المرشِّحة من Cloudflare، ولا يغادر الجهاز شيء آخر. فحوصه الشبكية الأخرى متوقفة حتى تشغّلها. [الأمان والخصوصية](../../docs/security.md)


## الإصدارات

يبني GitHub Actions الملفات التنفيذية المستقلة من المستودع العام. يسرد كل إصدار تجزئاتها في ملف `SHA256SUMS` يتحقق منه سكربت التثبيت، ويحمل كل ملف تنفيذي شهادة موقَّعة بمصدر البناء. الإصدارات وملاحظاتها على [GitHub](https://github.com/spamscanner/spamscanner/releases).
