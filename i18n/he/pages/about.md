<!-- source: 599bd320e55a -->

<!--
label: אודות
title: אודות Spam Scanner, הרישיון והפרטיות
description: מי מפתח את Spam Scanner, איך לדווח על באג או על פרצת אבטחה, מה הרישיון שלו ומה האתר הזה אוסף: בלי עוגיות ובלי אנליטיקה.
keywords: אודות Spam Scanner, Forward Email, רישיון Spam Scanner, BUSL-1.1, יצירת קשר Spam Scanner, פרטיות Spam Scanner
-->

# אודות Spam Scanner

Spam Scanner הוא מסנן ספאם לדואר שבנתה [Forward Email](https://forwardemail.net), שירות הדואר שמתמקד בפרטיות, עבור שרתי הדואר שלה. קוד המקור, הדיווחים והגרסאות נמצאים ב-[GitHub](https://github.com/spamscanner/spamscanner), והחבילה נמצאת ב-[npm](https://www.npmjs.com/package/spamscanner).


## מי מפתח אותו

הצוות של Forward Email כותב ומתחזק את Spam Scanner. ‏Forward Email לא שומרת יומנים של תוכן ההודעות, ולכן לא יכלה לשלוח דואר לשירות סינון חיצוני: המסנן היה צריך לרוץ על השרתים שלה ולהסביר כל החלטה בלי שאדם יקרא את הדואר. [איך Forward Email משתמשת בו](../../docs/forward-email.md)

גם Forward Email היא קוד פתוח, ב-[github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). המייסד שלה היה מהעובדים הראשונים של DuckDuckGo.


## יצירת קשר

* **שאלות, באגים ובקשות לתכונות:** פתחו דיווח ב-[GitHub](https://github.com/spamscanner/spamscanner/issues).
* **פרצות אבטחה:** דווחו עליהן באופן פרטי דרך [מנגנון דיווח הפרצות של GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), לא בדיווחים ציבוריים. אותה כתובת מופיעה ב-[security.txt](https://spamscanner.net/.well-known/security.txt).
* **רישיונות אחרים:** פנו אל [Forward Email](https://forwardemail.net).


## תנאי הרישיון

[הרישיון](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) של Spam Scanner הוא Business Source License 1.1, ורישיון השינוי (Change License) שלו הוא Apache License 2.0. תאריך השינוי (Change Date) שמצוין ברישיון כבר עבר, ומאותו תאריך הרישיון מעניק לכם זכויות לפי Apache License 2.0.


## פרטיות

האתר הזה לא שומר עוגיות ולא טוען אנליטיקה, רכיבי מעקב, פרסומות, גופנים או סקריפטים מאתרים אחרים. כל קובץ מגיע מ-spamscanner.net.

* ערכת הנושא, השפה שבחרתם ושרת Mastodon שאליו אתם משתפים נשמרים באחסון המקומי של הדפדפן, ולא נשלחים לשום מקום.
* הסרטון נטען רק כשמפעילים אותו.
* קישורי השיתוף הם קישורים רגילים, ולכן שום דבר מהרשתות האלה לא נטען עד שתלחצו על אחד מהם.
* האתר מתארח ב-GitHub Pages, ו-GitHub רושמת את כתובת ה-IP של כל מבקר לצורכי אבטחה. ראו [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) ואת [הצהרת הפרטיות של GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## מה התוכנה שולחת

Spam Scanner לא שולח טלמטריה ולא בודק עדכונים. כברירת מחדל הוא בודק את שמות המארחים של הקישורים בהודעה במנגנוני רזולוציית ה-DNS המסננים של Cloudflare, ושום דבר אחר לא יוצא מהמכונה. שאר בדיקות הרשת שלו כבויות עד שתפעילו אותן. [אבטחה ופרטיות](../../docs/security.md)


## גרסאות

‏GitHub Actions בונה את קובצי ההרצה העצמאיים מהמאגר הציבורי. כל גרסה מפרטת את הגיבובים שלהם בקובץ `SHA256SUMS`, שסקריפט ההתקנה בודק, ולכל קובץ הרצה יש אישור חתום על מקור הבנייה. הגרסאות וההערות שלהן נמצאות ב-[GitHub](https://github.com/spamscanner/spamscanner/releases).
