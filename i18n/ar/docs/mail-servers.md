<!-- source: 1151282f29d3 -->

# خوادم بريد أخرى

يتحدث Spam Scanner أربعة بروتوكولات، فيستطيع معظم برامج البريد استخدامه دون إضافة خاصة به:

| البروتوكول | الأمر                                    | يستخدمه                                           |
| ---------- | ---------------------------------------- | ------------------------------------------------- |
| Milter     | `spamscanner milter`                     | Postfix وSendmail وOpenSMTPD (مع filter-milter)   |
| spamd      | `spamscanner spamd`                      | spamc وExim وHaraka وأي شيء مكتوب لـ SpamAssassin |
| HTTP       | `spamscanner http`                       | السكربتات وwebhooks ووكلاء MTA المخصصة والخدمات   |
| الأنابيب   | `spamscanner scan`، `spamscanner filter` | أنابيب Postfix وprocmail وmaildrop ومهام cron     |

لـ [Postfix وSendmail](postfix.md) صفحة خاصة بهما.


## بديل مباشر لـ spamd من SpamAssassin

يجيب `spamscanner spamd` ببروتوكول spamd الخاص بـ SpamAssassin: `CHECK` و`SYMBOLS` و`REPORT` و`REPORT_IFSPAM` و`PROCESS` و`HEADERS` و`PING`، و`TELL` مع `--allow-tell`. تعمل البرامج المكتوبة لـ SpamAssassin دون تغيير؛ أوقف `spamd` وشغّل Spam Scanner على المنفذ نفسه.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

مع spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

تشغّل الاختبارات الشاملة في المستودع أداة spamc الأصلية من SpamAssassin عليه.


## Exim

يتحدث شرط ACL المسمى `spam` في Exim مع spamd. في الإعدادات الرئيسية:

```text
spamd_address = 127.0.0.1 783
```

في ACL الخاص بـ DATA (`acl_check_data` في exim4 على Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

يجيب `defer` بخطأ 4xx مؤقت، فيعيد المرسلون المحاولة ويمكن تصحيح الخطأ. غيّره إلى `deny` للرفض الدائم بعد أن تبدو النتائج صحيحة.


## Haraka

تتحدث إضافة `spamassassin` في Haraka مع spamd. فعّلها في `config/plugins` واضبط في `config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: مجلد Junk والتعلّم

تنقل قاعدة Sieve البريد الموسوم إلى Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

مع IMAPSieve، يمكن لنقل رسالة إلى Junk أو منه أن يعلّم النموذج. شغّل HTTP API مع رمز مميز وملف نموذج:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

ووجّه خادم الـ milter أو spamd إلى النموذج نفسه بـ `--model /var/lib/spamscanner/model.json` (أو `SPAMSCANNER_MODEL`). أعد تشغيله من حين لآخر ليلتقط ما تعلّمه. يرسل سكربت يشغّله `sieve_pipe` الرسالة:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

يعرض [دليل الإبلاغ عن البريد المزعج](https://doc.dovecot.org/main/core/config/spam_reporting.html) في Dovecot بقية الإعداد، وهو نفسه لأي مرشِّح بريد مزعج يتعلّم من سكربت.


## procmail وmaildrop

```text
# ~/.procmailrc
:0fw
| spamscanner scan - --headers

:0:
* ^X-Spam-Flag: YES
Junk/
```

maildrop:

```text
xfilter "spamscanner scan - --headers"
if (/^X-Spam-Flag: YES/)
{
  to "$HOME/Maildir/.Junk/"
}
```

يخرج `scan --headers` بالرمز 1 للبريد المزعج. يستخدم procmail وmaildrop المخرجات، لا رمز الخروج، مع القواعد أعلاه.


## HTTP API

يستطيع أي برنامج قادر على إرسال طلب HTTP أن يفحص البريد:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

تسرد [HTTP API](http-api.md) كل نقطة نهاية.


## داخل خادم بريد Node.js

مع [smtp-server](https://nodemailer.com/extras/smtp-server/)، أو إضافات Haraka، أو أي خادم Node.js آخر، استدعِ المكتبة مباشرة:

```js
import SpamScanner from 'spamscanner';

const scanner = new SpamScanner({authentication: true});

// smtp-server's onData handler
async function onData(stream, session, callback) {
  const result = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (result.action === 'reject') {
    const error = new Error('Message rejected as spam');
    error.responseCode = 451;
    return callback(error);
  }

  // Deliver, with result.isSpam deciding the folder.
  callback();
}
```

يحمل `session.envelope` من smtp-server مسبقًا شكل `mailFrom` و`rcptTo` الذي يقرؤه Spam Scanner.
