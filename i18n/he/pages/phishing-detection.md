<!-- source: 0378a5e0f12b -->

<!--
label: זיהוי פישינג
title: זיהוי פישינג בדואר: דומיינים מתחזים, קישורים מטעים וזיוף
description: איך Spam Scanner מזהה פישינג: דומיינים מתחזים ב-Unicode, קישורים שמציגים כתובת אחת ומובילים לאחרת, שמות מותגים, חסימת הנוזקות של Cloudflare ו-DMARC.
keywords: זיהוי פישינג, מסנן פישינג לדואר אלקטרוני, התקפת הומוגרף, הומוגרף IDN, זיהוי דומיינים מתחזים, קישור מטעה, התחזות למותג בדואר אלקטרוני, דיוג
-->

# זיהוי פישינג בדואר אלקטרוני

פישינג עובד בכך שהוא נראה כמו מישהו אחר. Spam Scanner בודק את המקומות שבהם ההסוואה נחשפת.


## דומיינים מתחזים

כל דומיין בקישור מצומצם ל„שלד” בעזרת טבלת התווים המבלבלים של Unicode ומושווה לכמעט 100 מותגים שנפוץ להתחזות אליהם:

| דומיין                              | נתפס בתור                 |
| ----------------------------------- | ------------------------- |
| `pаypal.com` (а קירילית)            | תווים מבלבלים             |
| `paypa1-secure.top`                 | תווים מוחלפים             |
| `xn--pple-43d.com`                  | Punycode של `аpple.com`   |
| `paypal.com.account-verify.example` | מותג בדומיין של מישהו אחר |
| `paypall.com`                       | אות אחת הבדל              |

אפשר להוסיף מותגים, ולהכניס לרשימת ההיתר דומיינים שבבעלותכם.


## קישורים מטעים

קישור HTML שהטקסט שלו הוא כתובת אחת והיעד שלו הוא אחר, למשל הטקסט `https://www.paypal.com/signin` שמפנה ל-`http://paypa1-secure.top/login`, מוסיף 3 נקודות.


## שמות תצוגה וזיוף

* שם תצוגה שמכיל מותג („PayPal Security”) מכתובת בדומיין אחר.
* שם תצוגה שמכיל כתובת דואר אלקטרוני אחרת.
* דואר שמתיימר להגיע מהדומיין של הנמען עצמו ונכשל ב-SPF,‏ DKIM ו-DMARC.


## אתרים זדוניים ידועים

המארחים שבקישורים נבדקים מול שרת ה-DNS‏ 1.1.1.2 של Cloudflare, שחוסם אתרי נוזקות ופישינג ידועים, ובאופן אופציונלי מול רשימות שחורות של דומיינים כמו Spamhaus DBL.


## קבצים מצורפים

פישינג מגיע גם כקבצים מצורפים מסוג HTML שמציגים דף התחברות מזויף במצב לא מקוון, וכקבצי הרצה ששמם שונה ל-`.pdf`. שניהם מזוהים לפי התוכן שלהם.

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

[איך הבדיקות עובדות](../../docs/how-it-works.md#phishing)
