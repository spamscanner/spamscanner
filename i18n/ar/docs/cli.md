<!-- source: c061da9312ad -->

# سطر الأوامر

```text
spamscanner <command> [options]
```

| الأمر                                      | ما يفعله                                                                |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| `scan [file\|-]`                           | فحص رسالة من ملف أو من الإدخال القياسي                                  |
| `filter -f <sender> -- <recipients...>`    | مرشِّح محتوى لـ Postfix: يفحص الإدخال القياسي، ويضيف الترويسات، ويمرّره |
| `milter`                                   | Milter لـ Postfix وSendmail، المنفذ 7831                                |
| `http`                                     | HTTP API، المنفذ 7832                                                   |
| `server`                                   | خادم TCP بسيط، المنفذ 7830                                              |
| `spamd`                                    | خادم spamd متوافق مع SpamAssassin، المنفذ 783                           |
| `train`                                    | تدريب نموذج من ملفات mbox أو مجلدات Maildir أو مجلدات أو مجموعات بيانات |
| `eval`                                     | قياس أداء نموذج على بريد مصنَّف                                         |
| `learn spam\|ham [file\|-] --model <file>` | تعليم نموذج رسالة واحدة                                                 |
| `llm-test`                                 | فحص إعدادات النموذج اللغوي بثلاث رسائل نموذجية                          |
| `models`                                   | سرد النماذج المفتوحة الموصى بها                                         |
| `version`، `help`                          |                                                                         |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| الخيار                     | المعنى                                             |
| -------------------------- | -------------------------------------------------- |
| `--json`                   | طباعة النتيجة كاملة بصيغة JSON                     |
| `--headers`                | طباعة الرسالة مع إضافة ترويسات `X-Spam-*`          |
| `--subject-tag <tag>`      | إضافة بادئة إلى عنوان البريد المزعج أيضًا          |
| `--verbose`                | إظهار كل اختبار، وأقوى قرائن المصنِّف              |
| `--threshold <n>`          | الدرجة التي يصبح عندها البريد مزعجًا (الافتراضي 5) |
| `--reject-threshold <n>`   | الدرجة التي يُرفض عندها البريد (الافتراضي 15)      |
| `--model <file>`           | ملف نموذج بدل النموذج المرفق                       |
| `--no-classifier`          | عدم استخدام المصنِّف                               |
| `--config <file>`          | ملف JSON يحتوي [خيارات المكتبة](api.md#options)    |
| `--allow-language <codes>` | اللغات المقبولة، مثل `en,de,fr`                    |

رموز الخروج: 0 مرغوب، 1 مزعج، 2 خطأ.

### جلسة SMTP

| الخيار              | المعنى                            |
| ------------------- | --------------------------------- |
| `--ip <address>`    | عنوان IP للعميل الذي أرسل الرسالة |
| `--hostname <name>` | اسم DNS العكسي الموثَّق للعميل    |
| `--helo <name>`     | الاسم الذي قدّمه في HELO أو EHLO  |
| `--from <address>`  | مرسل المغلّف (MAIL FROM)          |
| `--to <address>`    | مستلم المغلّف؛ كرّره لعدة مستلمين |

### الفحوص

| الخيار                | المعنى                                                          |
| --------------------- | --------------------------------------------------------------- |
| `--auth`              | فحص SPF وDKIM وDMARC وARC (يحتاج إلى `--ip`)                    |
| `--dnsbl <zone>`      | قائمة حظر IP، مثل `zen.spamhaus.org`؛ قابل للتكرار              |
| `--uribl <zone>`      | قائمة حظر نطاقات للروابط، مثل `dbl.spamhaus.org`؛ قابل للتكرار  |
| `--dns-server <ip>`   | خادم أسماء لفحوص DNS؛ قابل للتكرار                              |
| `--no-cloudflare`     | عدم سؤال محلِّلات Cloudflare الترشيحية عن الروابط               |
| `--clamav [socket]`   | فحص المرفقات بـ clamd، على مقبسه الافتراضي أو على المقبس المحدد |
| `--allowlist <value>` | قبول عنوان IP أو النطاق أو العنوان هذا دائمًا؛ قابل للتكرار     |
| `--denylist <value>`  | رفض عنوان IP أو النطاق أو العنوان هذا دائمًا؛ قابل للتكرار      |

### النموذج اللغوي

| الخيار                                                     | المعنى                                                                                                                     |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama` و`clef-flash` و`jev` و`openai` و`anthropic` وغيرها ([القائمة](llm.md#providers))                                  |
| `--llm-model <name>`                                       | النموذج، مثل `qwen3.5:4b` أو `claude-haiku-4-5`                                                                            |
| `--llm-method <method>`                                    | `decision` (احتمال لكل حكم، في خطوة واحدة؛ الافتراضي حيث يتوفر) أو `generate` ([الطريقتان](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | معرّف حساب Cloudflare، لـ `clef` و`clef-flash`                                                                             |
| `--llm-url <url>`                                          | عنوان URL الأساسي، مثل `http://10.0.0.5:11434`                                                                             |
| `--llm-host`، `--llm-port`، `--llm-path`، `--llm-protocol` | تغيير جزء واحد من عنوان URL للمزوّد                                                                                        |
| `--llm-api-key <key>`                                      | مفتاح API؛ انظر أيضًا متغيرات البيئة أدناه                                                                                 |
| `--llm-auth <type>`                                        | `bearer` أو `x-api-key` أو `api-key` أو `basic` أو `header` أو `none`                                                      |
| `--llm-auth-header <name>`                                 | الترويسة التي تحمل المفتاح، مع `--llm-auth header`                                                                         |
| `--llm-username`، `--llm-password`                         | لـ `--llm-auth basic`                                                                                                      |
| `--llm-header "Name: value"`                               | ترويسة طلب إضافية؛ قابل للتكرار                                                                                            |
| `--llm-mode <mode>`                                        | `auto` (الحالات المتقاربة فقط، وهو الافتراضي) أو `always`                                                                  |
| `--llm-timeout <ms>`                                       | الافتراضي 30000                                                                                                            |
| `--llm-policy <text>`                                      | قواعد إضافية للنموذج، مثل «لا نرسل فواتير أبدًا»                                                                           |
| `--llm-redact`، `--no-llm-redact`                          | حذف البيانات الشخصية أولًا؛ مفعَّل افتراضيًا للمزوّدين البعيدين                                                            |


## filter

[مرشِّح محتوى لـ Postfix](postfix.md#content-filter). يقرأ رسالة من الإدخال القياسي، ويضيف ترويسات `X-Spam-*`، ويمرّرها إلى sendmail بالمغلّف نفسه.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| الخيار                | المعنى                                  |
| --------------------- | --------------------------------------- |
| `--sendmail <path>`   | الافتراضي `/usr/sbin/sendmail`          |
| `--subject-tag <tag>` | إضافة بادئة إلى عنوان البريد المزعج     |
| `--reject`            | ارتداد البريد عند عتبة الرفض بدل تمريره |
| `--discard`           | إسقاط البريد عند عتبة الرفض بدل تمريره  |

تتبع رموز الخروج أعراف sendmail التي يقرؤها Postfix: 0 سُلّمت (أو أُسقطت)، و64 لم يُحدَّد أي مستلم، و69 رُفضت لأنها مزعجة (يرتدّها Postfix)، و75 أي فشل، فيحتفظ Postfix بالرسالة ويعيد المحاولة لاحقًا.


## milter وhttp وserver وspamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

المنفذ 783 هو المنفذ الذي يستخدمه عملاء SpamAssassin افتراضيًا. تحتاج المنافذ الأقل من 1024 إلى صلاحيات root أو إلى قدرة `CAP_NET_BIND_SERVICE`؛ استخدم منفذًا آخر، مثل `--port 7833`، وأخبر العميل به.

| الخيار                | المعنى                                                          |
| --------------------- | --------------------------------------------------------------- |
| `--port <n>`          | منفذ TCP                                                        |
| `--host <ip>`         | العنوان الذي يُستمع عليه (الافتراضي 127.0.0.1)                  |
| `--socket <path>`     | الاستماع على مقبس Unix بدلًا من ذلك                             |
| `--reject`            | Milter: رفض البريد عند عتبة الرفض                               |
| `--reject-code <n>`   | Milter: 451، أعد المحاولة لاحقًا (الافتراضي)، أو 550            |
| `--quarantine`        | Milter: حجز البريد المزعج في الحجر الصحي لخادم البريد           |
| `--name <hostname>`   | Milter: اسم هذا الخادم في Authentication-Results                |
| `--token <secret>`    | HTTP: اشتراط `Authorization: Bearer <secret>`؛ لازم لـ `/learn` |
| `--allow-tell`        | spamd: قبول طلبات TELL (`spamc -L spam`) للتعلّم                |
| `--out <file>`        | HTTP وspamd: حفظ ما يُتعلَّم في ملف النموذج هذا                 |
| `--subject-tag <tag>` | Milter وspamd: إضافة بادئة إلى عنوان البريد المزعج              |
| `--verbose`           | Milter: تسجيل كل فحص. خادم TCP: الإجابة بسطر نصي واحد           |

تنطبق خيارات الفحص أعلاه على الخوادم أيضًا. [الـ milter](postfix.md#milter)، [واجهة HTTP API وخادم TCP وspamd](http-api.md).


## train وeval وlearn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| الخيار                                          | المعنى                                                                  |
| ----------------------------------------------- | ----------------------------------------------------------------------- |
| `--spam <path>`                                 | البريد المزعج: ملف mbox، أو Maildir، أو مجلد ملفات `.eml`؛ قابل للتكرار |
| `--ham <path>`                                  | البريد المرغوب، بالطريقة نفسها؛ قابل للتكرار                            |
| `--dataset <file>`                              | ملف CSV أو JSON Lines بعمودي نص وتصنيف؛ قابل للتكرار                    |
| `--text-column <name>`، `--label-column <name>` | أسماء الأعمدة، عندما لا تُكتشف تلقائيًا                                 |
| `--out <file>`                                  | مكان كتابة النموذج (الافتراضي `spamscanner-model.json`)                 |
| `--merge`                                       | البدء من النموذج المرفق (أو `--model`) بدل نموذج فارغ                   |

يحدّث `learn` ملف النموذج في مكانه، وينشئه من النموذج المرفق في المرة الأولى. [التدريب](training.md)


## llm-test وmodels

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

يرسل `llm-test` رسالة عادية واحدة ورسالتي احتيال، بالإنجليزية والإيطالية، إلى النموذج، ويطبع أحكامه، والوقت الذي استغرقه كل منها، والطريقة المستخدمة، والعتاد، ولا يخرج بالرمز 0 إلا إذا كانت الأحكام الثلاثة صحيحة.


## ملف الإعدادات

يحمّل `--config file.json` (أو متغير البيئة `SPAMSCANNER_CONFIG`) [خيارات المكتبة](api.md#options). خيارات سطر الأوامر تتقدّم على الملف.

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


## متغيرات البيئة

| المتغير                                                                                                                                                                                                                                                                                                                   | المعنى                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                      | ملف الإعدادات                           |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                       | ملف النموذج المستخدم بدل النموذج المرفق |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                       | الرمز المميز لواجهة HTTP API            |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                 | مفتاح API لأي مزوّد نماذج لغوية         |
| `CLOUDFLARE_API_TOKEN` و`CLOUDFLARE_ACCOUNT_ID`، `TYPESAFE_API_KEY`، `OPENAI_API_KEY`، `ANTHROPIC_API_KEY`، `GEMINI_API_KEY`، `MISTRAL_API_KEY`، `GROQ_API_KEY`، `OPENROUTER_API_KEY`، `DEEPSEEK_API_KEY`، `XAI_API_KEY`، `TOGETHER_API_KEY`، `FIREWORKS_API_KEY`، `CEREBRAS_API_KEY`، `HF_TOKEN`، `AZURE_OPENAI_API_KEY` | المفتاح الخاص بكل مزوّد                 |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                 | سجلات التصحيح                           |
