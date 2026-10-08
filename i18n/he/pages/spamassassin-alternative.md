<!-- source: 1562b843d858 -->

<!--
label: חלופה ל-SpamAssassin
title: חלופה ל-SpamAssassin שמדברת spamd
description: החלפת ה-spamd של SpamAssassin ב-Spam Scanner. ‏spamc,‏ Exim ו-Haraka ממשיכים לעבוד, כותרות X-Spam שומרות על שמותיהן, וכל שפה נתמכת.
keywords: חלופה ל-SpamAssassin, תחליף ל-spamd, spamc, מסנן ספאם Exim, Haraka spamassassin, חלופה ל-rspamd, X-Spam-Status, מסנן ספאם בקוד פתוח
-->

# חלופה ל-SpamAssassin שמדברת spamd

Spam Scanner עונה בפרוטוקול spamd של SpamAssassin, כך שתוכנות שנכתבו עבור SpamAssassin משתמשות בו בלי שינוי: spamc, תנאי ה-`spam` של Exim, התוסף `spamassassin` של Haraka ואחרות.


## החלפה

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

הוא עונה ל-`CHECK`, ‏`SYMBOLS`, ‏`REPORT`, ‏`REPORT_IFSPAM`, ‏`PROCESS`, ‏`HEADERS`, ‏`PING`, ועם `--allow-tell` גם ל-`TELL` ללמידה. בדיקות הקצה-לקצה של הפרויקט מריצות מולו את ה-spamc של SpamAssassin עצמו.


## מה נשאר אותו הדבר

* הכותרות: `X-Spam-Flag`, ‏`X-Spam-Score`, ‏`X-Spam-Level` ו-`X-Spam-Status` בפורמט של SpamAssassin, כך שכללי Sieve,‏ procmail ותוכנות דואר קיימים ממשיכים לעבוד.
* ניקוד עם סף של 5, שמורכב מבדיקות בעלות שמות ונקודות: `BAYES_99`, ‏`RBL_ZEN`, ‏`SPF_FAIL`, ‏`DKIM_PASS` וכן הלאה.
* אפשר לשנות את הניקוד של כל בדיקה לפי שם הבדיקה.


## מה שונה

* **שפות.** המילים מפוצלות לפי כללי Unicode, כך שסינית, יפנית ותאית נקראות כמילים ולא כמחרוזת ארוכה אחת, והסוואות כמו תווים בלתי נראים או אותיות קיריליות במילים לטיניות מבוטלות קודם.
* **פישינג.** דומיינים מתחזים, קישורים מטעים ושמות מותגים בשמות תצוגה נבדקים בלי כללים נוספים.
* **קבצים מצורפים** מזוהים לפי הבתים שלהם: קובץ הרצה ששמו שונה ל-`.pdf` הוא עדיין קובץ הרצה.
* **מודלי שפה.** מקרים גבוליים יכולים לעבור למודל מקומי דרך Ollama או למודל מתארח.
* **Node.js.** ‏`npm install` אחד, או קובץ בינארי עצמאי; בלי מודולי Perl או עדכוני כללים לנהל.

Spam Scanner לא מריץ את קובצי הכללים של SpamAssassin, ולמסד הנתונים של Bayes שלו יש פורמט משלו: מאמנים אותו מאותו דואר עם `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim,‏ Haraka,‏ Dovecot ו-procmail](../../docs/mail-servers.md)
