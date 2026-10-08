<!-- source: faf44f093f8b -->

# HTTP API, שרת TCP ו-spamd


## HTTP API

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

הוא מאזין על 127.0.0.1, אלא אם `--host` קובע אחרת. כשמוגדר אסימון, כל בקשה חוץ מ-`/health` צריכה `Authorization: Bearer <token>`. לפני שחושפים אותו מחוץ למחשב, יש להציב אותו מאחורי reverse proxy עם TLS.

| שיטה ונתיב         | גוף הבקשה      | תשובה                                                     |
| ------------------ | -------------- | --------------------------------------------------------- |
| `GET /health`      |                | `{"ok": true, "version": "7.0.0"}`                        |
| `POST /scan`       | ההודעה הגולמית | [תוצאת הסריקה](api.md#the-result) כ-JSON                  |
| `POST /check`      | ההודעה הגולמית | ההודעה עם כותרות `X-Spam-*` שנוספו לה, כ-`message/rfc822` |
| `POST /learn/spam` | ההודעה הגולמית | `{"ok": true, "learned": "spam"}`; דורש אסימון            |
| `POST /learn/ham`  | ההודעה הגולמית | `{"ok": true, "learned": "ham"}`; דורש אסימון             |

פרמטרי השאילתה מתארים את שיחת ה-SMTP:

| פרמטר        | משמעות                                             |
| ------------ | -------------------------------------------------- |
| `ip`         | כתובת ה-IP של הלקוח                                |
| `hostname`   | שם ה-DNS ההפוך המאומת שלו                          |
| `helo`       | שם ה-HELO או ה-EHLO שלו                            |
| `from`       | שולח המעטפה                                        |
| `to`         | נמען; אפשר לחזור עליו או להפריד כמה נמענים בפסיקים |
| `verbose=1`  | `/scan`: מחזיר גם את רשימת המילים ואת הנושא        |
| `subjectTag` | `/check`: קידומת לנושא של ספאם, למשל `%5BSPAM%5D`  |

`/check` מחזיר גם את `X-Spam-Flag`, ‏`X-Spam-Score` ו-`X-Spam-Action` ככותרות תגובה, כך שלקוח יכול להחליט בלי לפענח את ההודעה.

הודעות גדולות מ-25 MB מקבלות `413`. סריקה שנכשלת מקבלת `500` עם `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

עם `--out model.json`, מה ש-`/learn` מלמד נשמר לקובץ הזה אחרי כל בקשה. בלי זה, הלמידה נשמרת עד שהשרת מופעל מחדש.

מתוך Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

מתוך Python:

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


## שרת TCP

```sh
spamscanner server --port 7830
```

שולחים את ההודעה הגולמית, סוגרים את צד השליחה של החיבור, וקוראים שורה אחת של JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

עם `--verbose`, התשובה היא שורת טקסט: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` או `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

שרת תואם SpamAssassin עבור spamc,‏ Exim,‏ Haraka ולקוחות SpamAssassin אחרים. [הגדרת Exim ו-Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| פקודה           | תשובה                                                |
| --------------- | ---------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                            |
| `SYMBOLS`       | פסק הדין ושמות הבדיקות שהופעלו                       |
| `REPORT`        | פסק הדין וטבלה של בדיקות, נקודות וסיבות              |
| `REPORT_IFSPAM` | כמו `REPORT`, עם דוח ריק ל-ham                       |
| `PROCESS`       | פסק הדין וההודעה עם כותרות `X-Spam-*`                |
| `HEADERS`       | פסק הדין וגוש הכותרות של ההודעה עם כותרות `X-Spam-*` |
| `PING`          | `PONG`                                               |
| `SKIP`          | כלום                                                 |
| `TELL`          | לומד ספאם או ham, עם `--allow-tell`; שומר ל-`--out`  |

בקשות דחוסות (`Compress: zlib`) נדחות.
