<!-- source: 0378a5e0f12b -->

<!--
label: كشف التصيّد الاحتيالي
title: كشف التصيّد في البريد: النطاقات المشابهة والروابط المخادعة
description: كيف يكشف Spam Scanner بريد التصيّد: النطاقات المشابهة في Unicode، والروابط التي تُظهر عنوانًا وتذهب إلى آخر، وانتحال العلامات التجارية، وCloudflare وDMARC.
keywords: كشف التصيد الاحتيالي, فلتر التصيد في البريد الإلكتروني, هجوم الحروف المتشابهة, IDN homograph, كشف النطاقات المشابهة, الروابط المخادعة, انتحال العلامات التجارية في البريد
-->

# كشف التصيّد الاحتيالي في البريد الإلكتروني

يعمل التصيّد الاحتيالي بالتظاهر بأنه شخص آخر. يفحص Spam Scanner المواضع التي يظهر فيها التنكّر.


## النطاقات المشابهة

يُختزل كل نطاق في رابط إلى هيكل باستخدام جدول المحارف الملتبسة في Unicode ويُقارن بنحو 100 علامة تجارية من أكثر العلامات انتحالًا:

| النطاق                              | يُلتقط على أنه               |
| ----------------------------------- | ---------------------------- |
| `pаypal.com` (حرف а سيريلي)         | محارف ملتبسة                 |
| `paypa1-secure.top`                 | محارف مبدّلة                 |
| `xn--pple-43d.com`                  | Punycode لـ `аpple.com`      |
| `paypal.com.account-verify.example` | علامة تجارية في نطاق طرف آخر |
| `paypall.com`                       | فرق حرف واحد                 |

يمكن إضافة علامات تجارية، ويمكن إضافة النطاقات التي تملكها إلى قائمة السماح.


## الروابط المخادعة

رابط HTML يكون نصه عنوانًا وهدفه عنوانًا آخر، مثل النص `https://www.paypal.com/signin` الذي يشير إلى `http://paypa1-secure.top/login`، يضيف 3 نقاط.


## أسماء العرض والانتحال

* اسم عرض يحتوي علامة تجارية («PayPal Security») من عنوان في نطاق آخر.
* اسم عرض يحتوي عنوان بريد إلكتروني مختلفًا.
* بريد يدّعي أنه آتٍ من نطاق المستلم نفسه ويفشل في SPF وDKIM وDMARC.


## المواقع الضارة المعروفة

يُبحث عن مضيفي الروابط على محلِّل Cloudflare 1.1.1.2، الذي يحظر مواقع البرمجيات الخبيثة والتصيّد الاحتيالي المعروفة، واختياريًا في قوائم حظر النطاقات مثل Spamhaus DBL.


## المرفقات

يصل التصيّد الاحتيالي أيضًا كمرفقات HTML ترسم صفحة تسجيل دخول مزيفة دون اتصال، وكملفات تنفيذية أُعيدت تسميتها إلى `.pdf`. كلاهما يُكتشف من محتواه.

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

[كيف تعمل الفحوص](../../docs/how-it-works.md#phishing)
