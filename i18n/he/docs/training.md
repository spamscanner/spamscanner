<!-- source: 7cc30ff4ad91 -->

# אימון

המודל המצורף עובד מיד. מודל שאומן על הדואר שלכם עובד טוב יותר, כי הוא לומד איך ה-ham שלכם נראה: הניוזלטרים שלכם, סגנון הכתיבה של העמיתים שלכם, השפות שאתם מקבלים.


## אימון מודל

מפנים את `train` לתיקיות של ספאם ו-ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

המקורות יכולים להיות:

* קובצי **mbox**, גם דחוסים ב-gzip‏ (`.mbox.gz`),
* **Maildir** (התיקיות `cur` ו-`new` שלו נקראות, ו-`tmp` מדולגת),
* **תיקייה** של קובצי `.eml`, שנקראת באופן רקורסיבי,
* **מאגר נתונים**: קובץ CSV או JSON Lines עם עמודת טקסט ועמודת תווית (`--dataset`). עמודות בשם `text`, ‏`message`, ‏`body`, ‏`email` או `content`, ו-`label`, ‏`category`, ‏`class`, ‏`spam` או `is_spam` מזוהות לבד; אחרת יש להשתמש ב-`--text-column` וב-`--label-column`. תוויות כמו `spam`, ‏`1`, ‏`phishing` ו-`ham`, ‏`0`, ‏`not_spam`, ‏`legitimate` מובנות.

הודעות כפולות נספרות פעם אחת. כדי לבנות על המודל המצורף במקום להתחיל ממודל ריק, מוסיפים `--merge`.

שימוש במודל:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

כמה דואר מספיק: כמה מאות הודעות מכל סוג נותנות מודל שימושי, כמה אלפים נותנים מודל טוב. כדאי לשמור על איזון בערך בין השניים, ולהשאיר ב-ham דואר שאין רצון לסנן (איפוסי סיסמה, חשבוניות מהספקים שלכם).


## מדידה

שומרים חלק מהדואר מחוץ לאימון ומודדים עליו:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

המודל המצורף על הודעות SMS ב-21 שפות שמעולם לא ראה, רובן בשפות שהוא כמעט לא מכיר:

```text
Messages: 13028 spam, 92406 ham
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
```

דיוק (Precision) הוא כמה ממה שהוא קורא לו ספאם הוא באמת ספאם; רגישות (Recall), כמה מהספאם הוא תופס. כאן הודעות „לא בטוח” נספרות כספאם שהוחמץ, אף שבסריקה שאר הבדיקות ומודל השפה עדיין יכולים לתפוס אותן. המספר שכדאי לעקוב אחריו הוא החיוביות השגויות: ham שסומן כספאם. בהרצה שלמעלה, המודל לא בטוח לגבי רוב ההודעות האלה במקום לטעות בהן, וזו ההתנהגות המכוונת בשפות שיש לו בהן מעט דואר.

`--json` נותן את אותם מספרים עבור סקריפטים.


## למידה מדיווחים

כשמשתמשים מעבירים דואר אל תיקיית Junk או ממנה, מלמדים את המודל הודעה אחת בכל פעם:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

ה-`learn` הראשון יוצר את הקובץ מהמודל המצורף. דרך HTTP, ‏`POST /learn/spam` ו-`/learn/ham` ב-[HTTP API](http-api.md) עושים אותו הדבר, ו-`spamc -L spam` עובד מול [שרת ה-spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) עם `--allow-tell`. [ה-IMAPSieve של Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) יכול לקרוא לכל אחד מהם כשהודעה מועברת.

מתוך Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

הודעה שדווחה כמסווגת בטעות צריכה לעבור „ביטול למידה” מהסוג השגוי לפני שהיא נלמדת בסוג הנכון, אם היא נלמדה קודם.


## המודל המצורף

`model/classifier.json` נבנה על ידי `npm run model:train` ממאגרי הנתונים הציבוריים האלה ב-Hugging Face, כולם ברישיונות פתוחים:

| מאגר נתונים                                                                                                                                                                                                                                                                                                                | רישיון             | תוכן                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | ------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0         | הודעות ודואר אלקטרוני ב-43 שפות |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | קורפוס מחקר ציבורי | קורפוס Enron-Spam               |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0            | הודעות Telegram ברוסית          |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                | הודעות סינתטיות                 |

הוא למד מ-62,480 הודעות ספאם ו-76,489 הודעות ham. הסקריפט מחזיק בצד כל הודעה עשירית, מאמן על השאר ומודד את המסווג לבדו, בלי שאר הבדיקות:

| מבחן על הודעות שהוחזקו בצד | הודעות |   דיוק | רגישות | חיוביות שגויות | לא בטוח |
| -------------------------- | -----: | -----: | -----: | -------------: | ------: |
| אנגלית                     |  6,564 | 100.0% |  97.0% |           0.0% |    2.4% |
| רוסית                      |  1,682 | 100.0% |  97.4% |           0.0% |    2.2% |
| איטלקית                    |  1,389 |  98.1% |  85.3% |           1.8% |   10.9% |
| גרמנית                     |  1,309 |  97.7% |  76.1% |           2.2% |   20.7% |
| ספרדית                     |  1,281 |  97.5% |  82.5% |           2.6% |   16.8% |
| Enron-Spam                 |  2,888 | 100.0% |  93.1% |           0.0% |    4.5% |
| all-scam-spam              |  4,236 | 100.0% |  88.8% |           0.0% |   11.2% |
| הכול                       | 13,840 |  99.2% |  85.1% |           0.5% |   12.4% |

כאן ספאם פירושו הסתברות מסווג של 99% ומעלה, הנקודה שבה המסווג לבדו מגיע לסף הספאם. בסריקה, ספאם שהוא פחות בטוח לגביו עדיין מקבל נקודות, ושאר הבדיקות מוסיפות את שלהן.

התוצאות בגרמנית, בספרדית ובאיטלקית מגיעות ממאגרי נתונים סינתטיים, שמכילים הודעות כמעט זהות שתויגו גם כספאם וגם כ-ham: חלק מהשגיאה הזו נמצא בתוויות, לא במודל. דואר בשפות שלכם הוא התיקון הטוב ביותר. המספרים, לכל שפה ולכל מאגר נתונים, נמצאים ב-`metadata.metrics` של המודל.

### שפות נוספות

`npm run model:train -- --with multilingual-sms` מוסיף את [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): אוסף SMS Spam Collection בתרגום מכונה ל-21 שפות. הוא לא נכלל במודל המצורף כי כרטיס המאגר שלו מציין רישיון GPL; כדאי לבדוק שזה מתאים לדרך שבה אתם משתפים את המודל. באימון איתו, התוצאות על הודעות שהוחזקו בצד, בשפות שהמודל המצורף כמעט לא מכיר, היו:

| שפה      | הודעות |   דיוק | רגישות | חיוביות שגויות |
| -------- | -----: | -----: | -----: | -------------: |
| סינית    |    430 | 100.0% |  82.3% |           0.0% |
| ערבית    |    430 | 100.0% |  84.6% |           0.0% |
| קוריאנית |    412 | 100.0% |  80.4% |           0.0% |
| יפנית    |    486 |  96.0% |  85.7% |           0.5% |
| הינדי    |    412 | 100.0% |  63.9% |           0.0% |
| צרפתית   |    480 |  98.6% |  94.2% |           0.6% |
| טורקית   |    220 | 100.0% |  73.1% |           0.0% |

### אימון מחדש

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## קובץ המודל

מודל הוא קובץ JSON: מספר הודעות הספאם וה-ham שנלמדו, ולכל מאפיין מגובב, בכמה הודעות ספאם ו-ham הוא הופיע, ממוין ומקודד ב-base64. אין בו מילים ואין בו טקסט של הודעות. `--max-features` שומר רק את המאפיינים השכיחים ביותר ו-`--min-count` משמיט מאפיינים נדירים, במחיר של דיוק תמורת גודל; המודל המצורף שומר 400,000 מאפיינים בכ-6 MB.

אי אפשר לטעון מודלים מ-Spam Scanner 6 ומגרסאות קודמות: הם גיבבו מאפיינים אחרים. יש לאמן מודל חדש מאותו דואר.
