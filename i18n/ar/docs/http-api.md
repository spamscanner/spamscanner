<!-- source: faf44f093f8b -->

# HTTP API وخادم TCP وspamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

يستمع على 127.0.0.1 ما لم يحدّد `--host` غير ذلك. مع رمز مميز، يحتاج كل طلب باستثناء `/health` إلى `Authorization: Bearer <token>`. ضعه خلف وكيل عكسي مع TLS قبل إتاحته خارج الجهاز.

| الطريقة والمسار    | المتن         | الإجابة                                                    |
| ------------------ | ------------- | ---------------------------------------------------------- |
| `GET /health`      |               | `{"ok": true, "version": "7.0.0"}`                         |
| `POST /scan`       | الرسالة الخام | [نتيجة الفحص](api.md#the-result) بصيغة JSON                |
| `POST /check`      | الرسالة الخام | الرسالة مع إضافة ترويسات `X-Spam-*`، بنوع `message/rfc822` |
| `POST /learn/spam` | الرسالة الخام | `{"ok": true, "learned": "spam"}`؛ يحتاج إلى رمز مميز      |
| `POST /learn/ham`  | الرسالة الخام | `{"ok": true, "learned": "ham"}`؛ يحتاج إلى رمز مميز       |

تصف معاملات الاستعلام جلسة SMTP:

| المعامل      | المعنى                                                          |
| ------------ | --------------------------------------------------------------- |
| `ip`         | عنوان IP للعميل                                                 |
| `hostname`   | اسم DNS العكسي الموثَّق له                                      |
| `helo`       | اسمه في HELO أو EHLO                                            |
| `from`       | مرسل المغلّف                                                    |
| `to`         | مستلم؛ كرّره أو افصل بين عدة مستلمين بفواصل                     |
| `verbose=1`  | `/scan`: إرجاع قائمة الكلمات والعنوان أيضًا                     |
| `subjectTag` | `/check`: إضافة بادئة إلى عنوان البريد المزعج، مثل `%5BSPAM%5D` |

تُرجع `/check` أيضًا `X-Spam-Flag` و`X-Spam-Score` و`X-Spam-Action` كترويسات استجابة، فيستطيع العميل أن يقرر دون تحليل الرسالة.

الرسائل الأكبر من 25 ميغابايت تحصل على `413`. والفحص الذي يفشل يحصل على `500` مع `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

مع `--out model.json`، يُحفظ ما تعلّمه `/learn` في ذلك الملف بعد كل طلب. ودونه، يدوم التعلّم حتى إعادة تشغيل الخادم.

من Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

من Python:

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## خادم TCP

```sh
spamscanner server --port 7830
```

أرسل الرسالة الخام، وأغلق جانب الإرسال من الاتصال، واقرأ سطرًا واحدًا من JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

مع `--verbose`، تكون الإجابة سطرًا نصيًا بدلًا من ذلك: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` أو `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

خادم متوافق مع SpamAssassin لـ spamc وExim وHaraka وغيرها من عملاء SpamAssassin. [إعداد Exim وHaraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| الأمر           | الإجابة                                                              |
| --------------- | -------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                            |
| `SYMBOLS`       | الحكم وأسماء الاختبارات التي انطبقت                                  |
| `REPORT`        | الحكم وجدول بالاختبارات والنقاط والأسباب                             |
| `REPORT_IFSPAM` | مثل `REPORT`، مع تقرير فارغ للبريد المرغوب                           |
| `PROCESS`       | الحكم والرسالة مع ترويسات `X-Spam-*`                                 |
| `HEADERS`       | الحكم وكتلة ترويسات الرسالة مع ترويسات `X-Spam-*`                    |
| `PING`          | `PONG`                                                               |
| `SKIP`          | لا شيء                                                               |
| `TELL`          | يتعلّم بريدًا مزعجًا أو مرغوبًا، مع `--allow-tell`؛ ويحفظ في `--out` |

تُرفض الطلبات المضغوطة (`Compress: zlib`).
