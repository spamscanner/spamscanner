<!-- source: 988243aec4f3 -->

<!--
label: מסנן ספאם באירוח עצמי
title: מסנן ספאם באירוח עצמי לשרת הדואר שלכם
description: מסנן ספאם על השרת שלכם. Spam Scanner משאיר את הדואר על המכונה, המודל שלו כלול בחבילה, הוא לא שולח טלמטריה ומתחבר ל-Postfix או ל-Exim.
keywords: מסנן ספאם באירוח עצמי, מסנן ספאם מקומי, מסנן ספאם פרטי, מסנן ספאם לשרת דואר, מסנן ספאם בלי ענן
-->

# מסנן ספאם באירוח עצמי

Spam Scanner רץ על השרת שלכם ומשאיר שם את הדואר. מודל המסווג כלול בחבילה, אין טלמטריה ואין בדיקת עדכונים, וכברירת מחדל הדבר היחיד שהוא שולח הוא שאילתת DNS על שם המארח של כל קישור.


## מה יוצא מהשרת

כברירת מחדל, רק שמות המארחים של הקישורים בהודעה. הם נבדקים במנגנוני הרזולוציה המסננים של Cloudflare ‏(1.1.1.2 ו-1.1.1.3) כשאילתות DNS רגילות, ושום חלק מההודעה או מהכתובות שלה לא נשלח. `--no-cloudflare` מכבה גם את זה.

כל בדיקה אחרת שמשתמשת ברשת כבויה עד שתפעילו אותה:

| בדיקה                 | מפעילים עם           | מה היא שולחת                                        |
| --------------------- | -------------------- | --------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | שאילתות DNS על הרשומות של השולח                     |
| רשימות חסימה של DNS   | `--dnsbl`, `--uribl` | כתובת ה-IP של הלקוח ודומייני הקישורים, כשאילתות DNS |
| ClamAV                | `--clamav`           | קבצים מצורפים, ל-clamd שלכם                         |
| מודל שפה              | `--llm`              | תקציר של ההודעה, לשרת שתציינו                       |

סריקות לא נרשמות ביומן ולא נשמרות. [אבטחה ופרטיות](../../docs/security.md)


## התקנה על שרת

```sh
npm install --global spamscanner
```

או קובץ ההרצה העצמאי, עם Node.js והמודל בפנים:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

סקריפט ההתקנה בודק את קובץ ההרצה מול קובץ `SHA256SUMS` של הגרסה לפני ההתקנה, ולכל קובץ הרצה יש אישור חתום על מקור הבנייה ש-`gh attestation verify` בודק. יש קובצי הרצה ל-Linux ‏(x64 ו-arm64), ל-macOS ול-Windows. קובצי Linux דורשים glibc, ולכן ב-Alpine התקינו עם npm. [תחילת העבודה](../../docs/getting-started.md)

אין בדיקת עדכונים. כדי לעדכן, הריצו שוב את פקודת ההתקנה: שתי הפקודות מתקינות את הגרסה האחרונה.


## הרצה כשירות

שרתי ה-milter,‏ HTTP,‏ TCP ו-spamd מאזינים ב-127.0.0.1 אלא אם `--host` קובע אחרת. הריצו אותם כמשתמש ללא הרשאות, למשל תחת systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

[היחידה המלאה וההגדרה שלה](../../docs/postfix.md#1-run-the-milter) נמצאות במדריך ל-Postfix. אף אחד מהשרתים לא תומך ב-TLS, ולכן כדי להגיע אליהם ממכונה אחרת השתמשו ברשת פרטית, במנהרת SSH או ב-reverse proxy עם TLS.


## חיבור שרת הדואר שלכם

| שרת דואר                       | פקודה                                   | פורט |
| ------------------------------ | --------------------------------------- | ---- |
| Postfix או Sendmail            | `spamscanner milter`                    | 7831 |
| Postfix, בלי לדחות דואר אף פעם | `spamscanner filter`, מסנן תוכן         | אין  |
| Exim,‏ Haraka או spamc         | `spamscanner spamd`                     | 783  |
| כל מה שמדבר HTTP               | `spamscanner http`                      | 7832 |
| לקוח TCP פשוט                  | `spamscanner server`                    | 7830 |
| שרת דואר שנכתב ב-Node.js       | `import SpamScanner from 'spamscanner'` | אין  |

השרתים יכולים להוסיף להודעה את הכותרות `X-Spam-Flag`,‏ `X-Spam-Score` ו-`X-Spam-Status`, והספרייה מחזירה את הציון ואת כל בדיקה שהופעלה. מדריכים: [מסנן ספאם ל-Postfix](/postfix-spam-filter/), [שרתי דואר אחרים](../../docs/mail-servers.md) ו-[ה-HTTP API](../../docs/http-api.md).


## מודלי שפה מקומיים

מודל שפה הוא אופציונלי וקורא רק מקרים גבוליים: ספאם ברור ו-ham ברור לא מגיעים אליו אף פעם. עם Ollama הוא רץ על אותו שרת, כך שאף הודעה לא יוצאת ממנו:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` רץ על CPU. עם ספק מתארח, מידע אישי מוסר מההודעה לפני שהיא נשלחת. [מודלי שפה](../../docs/llm.md)


## אימון על הדואר שלכם

המודל המצורף אומן על מערכי נתונים ציבוריים. מודל שאומן על הדואר שהשרת שלכם מקבל עובד טוב יותר, ונשאר על השרת:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

קובץ מודל מכיל ספירות מגובבות של מאפיינים, לא מילים או טקסט של הודעות. [אימון](../../docs/training.md)


## דרישות

Node.js 18 ומעלה ב-Linux, ב-macOS או ב-Windows, או כלום עם קובץ הרצה עצמאי. ClamAV ו-Ollama הם אופציונליים ורצים כשירותים נפרדים.
