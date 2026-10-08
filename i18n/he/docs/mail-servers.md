<!-- source: 1151282f29d3 -->

# שרתי דואר אחרים

Spam Scanner מדבר ארבעה פרוטוקולים, כך שרוב תוכנות הדואר יכולות להשתמש בו בלי תוסף ייעודי:

| פרוטוקול     | פקודה                                    | בשימוש על ידי                                          |
| ------------ | ---------------------------------------- | ------------------------------------------------------ |
| Milter       | `spamscanner milter`                     | Postfix,‏ Sendmail,‏ OpenSMTPD (עם filter-milter)      |
| spamd        | `spamscanner spamd`                      | spamc,‏ Exim,‏ Haraka, וכל דבר שנכתב עבור SpamAssassin |
| HTTP         | `spamscanner http`                       | סקריפטים, webhooks, שרתי MTA ושירותים מותאמים אישית    |
| צינור (Pipe) | `spamscanner scan`, `spamscanner filter` | צינורות של Postfix,‏ procmail,‏ maildrop, משימות cron  |

ל-[Postfix ו-Sendmail](postfix.md) יש דף משלהם.


## תחליף ישיר ל-spamd של SpamAssassin

`spamscanner spamd` עונה בפרוטוקול spamd של SpamAssassin: `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` ו, עם `--allow-tell`, גם `TELL`. תוכנות שנכתבו עבור SpamAssassin עובדות בלי שינוי; עוצרים את `spamd` ומפעילים את Spam Scanner על אותו פורט.

```sh
sudo systemctl disable --now spamd    # or spamassassin, depending on the distribution
spamscanner spamd --port 783 --auth
```

עם spamc:

```sh
spamc -c < message.eml          # prints "16.3/5.0", exits 1 for spam
spamc -R < message.eml          # the report
spamc < message.eml > out.eml   # the message with X-Spam-* headers
spamc -L spam < message.eml     # learn (needs --allow-tell)
```

בדיקות הקצה-לקצה של המאגר מריצות מולו את ה-spamc של SpamAssassin עצמו.


## Exim

תנאי ה-ACL‏ `spam` של Exim מדבר עם spamd. בתצורה הראשית:

```text
spamd_address = 127.0.0.1 783
```

ב-ACL של DATA (`acl_check_data` ב-exim4 של Debian):

```text
  warn    spam       = nobody:true
          add_header = X-Spam-Score: $spam_score
          add_header = X-Spam-Report: $spam_report

  # Refuse mail at the reject threshold: 15 points is 150 in $spam_score_int.
  defer   spam       = nobody:true
          condition  = ${if >={$spam_score_int}{150}}
          message    = Message rejected as spam ($spam_score points)
```

`defer` עונה בשגיאת 4xx זמנית, כך ששולחים מנסים שוב ואפשר לתקן טעות. כשהתוצאות נראות נכונות, אפשר לשנות ל-`deny` לדחייה קבועה.


## Haraka

התוסף `spamassassin` של Haraka מדבר עם spamd. יש להפעיל אותו ב-`config/plugins` ולהגדיר ב-`config/spamassassin.ini`:

```ini
spamd_socket=127.0.0.1:783
munge_subject_threshold=5
subject_prefix=[SPAM]
reject_threshold=15
old_headers_action=drop
```


## Dovecot: תיקיית Junk ולמידה

כלל Sieve מתייק דואר מסומן ב-Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

עם IMAPSieve, העברת הודעה אל Junk או ממנה יכולה ללמד את המודל. מפעילים את ה-HTTP API עם אסימון וקובץ מודל:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN" --out /var/lib/spamscanner/model.json
```

ומפנים את שרת ה-milter או ה-spamd לאותו מודל עם `--model /var/lib/spamscanner/model.json` (או `SPAMSCANNER_MODEL`). מדי פעם יש להפעיל אותו מחדש כדי שיטען את מה שנלמד. סקריפט שמורץ על ידי `sieve_pipe` שולח את ההודעה:

```sh
#!/bin/sh
# /usr/local/lib/dovecot/report-spam.sh (report-ham.sh is the same with /learn/ham)
exec curl -fsS -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @- http://127.0.0.1:7832/learn/spam
```

[המדריך לדיווח על ספאם](https://doc.dovecot.org/main/core/config/spam_reporting.html) של Dovecot מציג את שאר ההגדרה, שזהה לכל מסנן ספאם שלומד מסקריפט.


## procmail ו-maildrop

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

`scan --headers` יוצא עם 1 לספאם. עם הכללים שלמעלה, procmail ו-maildrop משתמשים בפלט, לא בקוד היציאה.


## HTTP API

כל תוכנה שיכולה לשלוח בקשת HTTP יכולה לסרוק דואר:

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"

curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&from=alice@example.com&to=bob@example.org"
```

[ה-HTTP API](http-api.md) מפרט כל נקודת קצה.


## בתוך שרת דואר ב-Node.js

עם [smtp-server](https://nodemailer.com/extras/smtp-server/), תוספים של Haraka או כל שרת Node.js אחר, קוראים לספרייה ישירות:

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

ל-`session.envelope` של smtp-server כבר יש את המבנה של `mailFrom` ו-`rcptTo` ש-Spam Scanner קורא.
