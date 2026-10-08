<!-- source: f33722183f00 -->

<!--
label: מסנן ספאם ל-Postfix
title: מסנן ספאם ל-Postfix עם milter או מסנן תוכן
description: סינון ספאם בשרת Postfix עם ה-milter או מסנן התוכן של Spam Scanner: התקנה, יחידת systemd, דחייה עם 4xx או 5xx, ותיקיית Junk.
keywords: מסנן ספאם Postfix, Postfix milter, smtpd_milters, מסנן תוכן Postfix, אנטי ספאם Postfix, דחיית ספאם Postfix, סינון ספאם בשרת דואר
-->

# מסנן ספאם ל-Postfix

Spam Scanner מסנן שרת Postfix בתוך כחמש דקות. הוא רץ כ-milter, כך ש-Postfix שואל אותו על כל הודעה במהלך שיחת ה-SMTP ויכול לדחות ספאם לפני שהוא מקבל אותו.


## התקנה והפעלה

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` בודקת SPF,‏ DKIM,‏ DMARC ו-ARC; ‏`--subject-tag` מסמנת ספאם בשורת הנושא. כל הודעה מקבלת כותרות `X-Spam-Flag`, ‏`X-Spam-Score`, ‏`X-Spam-Status` ו-`X-Spam-Action`, וכל כותרת `X-Spam-*` שהשולח הכניס מוסרת קודם.


## חיבור Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` מעביר דואר בלי סינון אם ה-milter לא פועל; `tempfail` מבקש במקום זאת משולחים לנסות שוב.


## דחיית ספאם במהלך שיחת ה-SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

הודעות שמגיעות לסף הדחייה (15 נקודות) נדחות עם `451 4.7.1 Message rejected as spam`. ‏451 הוא זמני: השולח שומר את ההודעה ומנסה שוב, כך שהחלטה שגויה עולה בעיכוב ולא בהודעה שאבדה. כשהתוצאות נראות נכונות, `--reject-code 550` הופך את הדחייה לקבועה.


## בלי milter

מסנן תוכן רץ אחרי ש-Postfix מקבל הודעה: Postfix מעביר אותה בצינור ל-`spamscanner filter`, שמוסיף כותרות ומחזיר אותה. שום דבר לא נדחה אף פעם במהלך השיחה, וכישלון תמיד דוחה את המסירה למועד מאוחר יותר במקום להחזיר את ההודעה לשולח. [הגדרת מסנן התוכן](../../docs/postfix.md#content-filter)


## ספאם לתיקיית Junk

עם Dovecot, כלל Sieve מתייק דואר מסומן:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## נבדק מול Postfix אמיתי

בדיקות הקצה-לקצה של הפרויקט מריצות Postfix עם ה-milter ועם מסנן התוכן: ham נמסר עם כותרות ו-`X-Spam-Flag` מזויף מוסר, ספאם מסומן, ו-GTUBE נדחה עם 550 במהלך שיחת ה-SMTP.

הצעד הבא: [המדריך המלא ל-Postfix ול-Sendmail](../../docs/postfix.md), עם יחידת systemd ועם `INPUT_MAIL_FILTER` של Sendmail.
