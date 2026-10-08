<!-- source: f1043eb5fc58 -->

# Postfix وSendmail

يتصل Spam Scanner بـ Postfix بطريقتين:

* **كـ milter** (موصى به). يسأله Postfix عن كل رسالة أثناء جلسة SMTP، قبل قبولها. يمكن رفض البريد المزعج برد 4xx أو 5xx، فيتعامل معه الخادم المرسل لا خادمك. يستخدم Sendmail البروتوكول نفسه.
* **كمرشِّح محتوى.** يقبل Postfix الرسالة، ويمرّرها عبر أنبوب إلى `spamscanner filter`، الذي يضيف الترويسات ويعيدها باستخدام sendmail. لا يُرفض أي شيء أبدًا أثناء جلسة SMTP.

كلتا الطريقتين تضيف هذه الترويسات إلى كل رسالة:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

تُحذف أولًا ترويسات `X-Spam-*` الموجودة في الرسالة مسبقًا، فلا يستطيع المرسل أن يَسِم بريده بأنه نظيف.


## Milter

### 1. شغّل الـ milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

مع `--reject`، تُرفض الرسائل التي تبلغ عتبة الرفض (15 نقطة) بالرد `451 4.7.1 Message rejected as spam`. الرد 451 مؤقت: يعيد المرسل المحاولة لاحقًا ويظل ممكنًا تصحيح الخطأ بتغيير إعداد. استخدم `--reject-code 550` للرفض الدائم بعد أن تبدو النتائج صحيحة. مع `--quarantine`، يذهب البريد المزعج إلى طابور الحجز في Postfix بدلًا من ذلك.

كخدمة systemd، في `/etc/systemd/system/spamscanner-milter.service`:

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. وجّه Postfix إليه

في `/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

يغطي `smtpd_milters` البريد الوارد عبر SMTP. اترك `non_smtpd_milters` فارغًا ما لم يكن البريد المُرسل بالأمر `sendmail` يحتاج إلى فحص أيضًا.

### 3. اختبره

يرسل [swaks](https://www.jetmore.org/john/code/swaks/) رسائل اختبار. GTUBE سلسلة اختبار يعاملها كل مرشِّح بريد مزعج على أنها مزعجة:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

دون `--reject` تُسلَّم الرسالة مع `X-Spam-Flag: YES` وعنوان موسوم. ومع `--reject`، يعرض swaks الرد 451 أو 550.


## مرشِّح المحتوى

استخدمه عندما يجب ألا يُرفض البريد أبدًا أثناء جلسة SMTP، أو لخادم لا يستطيع استخدام الـ milters.

في `/etc/postfix/master.cf`، أضف خدمة ترشيح واستخدمها على مستمع SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

يشغّل Postfix المرشِّح ببيئة شبه فارغة، ولذلك يسمّي `argv` كلًا من Node.js والسكربت بمساريهما الكاملين (يعرضهما `command -v node` و`npm root --global`). ثم:

```sh
sudo postfix reload
```

يعيد المرشِّح الرسالة باستخدام `sendmail -G -i`. البريد المُرسل بهذه الطريقة لا يمر عبر مستمع `smtp` مرة أخرى، فلا يُرشَّح مرتين.

تخبر رموز الخروج Postfix بما حدث: 0 سُلّمت، و69 رُفضت (مع `--reject`: يرتدّها Postfix إلى المرسل)، و75 فشل مؤقت (يحتفظ Postfix بالرسالة ويعيد المحاولة). أي فشل في الفحص أو التسليم هو 75، فلا يتسبب إعداد معطوب أبدًا في فقدان البريد أو ارتداده.


## Sendmail

في `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

يجعل `F=T` Sendmail يجيب بفشل مؤقت ما دام الـ milter غير متاح؛ احذفه لقبول البريد دون ترشيح بدلًا من ذلك. أعد بناء `sendmail.cf` وأعد تشغيل Sendmail.


## فرز البريد المزعج إلى مجلد Junk

الوسم وحده يسلّم البريد المزعج إلى صندوق الوارد. مع Dovecot، تنقله قاعدة Sieve:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

تغطي صفحة [خوادم بريد أخرى](mail-servers.md) كلًا من Dovecot وExim وHaraka وprocmail، وتعرض صفحة [التدريب](training.md#learning-from-reports) كيفية التعلّم من البريد الذي ينقله المستخدمون إلى Junk ومنه.


## مُختبَر

تشغّل الاختبارات الشاملة في المستودع خادم Postfix حقيقيًا: يُسلَّم البريد المرغوب مع الترويسات، وتُحذف ترويسة `X-Spam-Flag` المزوّرة، ويُوسم البريد المزعج، ويُرفض GTUBE بالرد 550 أثناء جلسة SMTP، ويَسِم مرشِّح المحتوى البريد على منفذ ثانٍ. يُعدّ `scripts/e2e-postfix.sh` خادم Postfix هذا، ويرسل `test/e2e/postfix.test.js` البريد.
