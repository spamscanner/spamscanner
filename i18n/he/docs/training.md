<!-- source: 6f344039ec5d -->

# אימון

המודל המצורף עובד מיד. מודל שאומן על הדואר שלכם עובד טוב יותר, כי הוא לומד איך ה-ham שלכם נראה: הניוזלטרים שלכם, סגנון הכתיבה של העמיתים שלכם, השפות שאתם מקבלים.


## אימון מודל

מפנים את `train` לתיקיות של ספאם ו-ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

המקורות יכולים להיות:

* קובצי **mbox**, גם דחוסים ב-gzip‏ (`.mbox.gz`; קובצי `.gz` אחרים מדולגים),
* **Maildir** (התיקיות `cur` ו-`new` שלו נקראות, ו-`tmp` מדולגת),
* **תיקייה** של קובצי `.eml`, שנקראת באופן רקורסיבי,
* **מאגר נתונים**: קובץ CSV או JSON Lines עם עמודת טקסט ועמודת תווית (`--dataset`). עמודות, או שדות JSON, בשם `text`, ‏`message`, ‏`body`, ‏`email text`, ‏`email`, ‏`content`, ‏`sms` או `v2`, ו-`label`, ‏`category`, ‏`is_spam`, ‏`spam`, ‏`email type`, ‏`class`, ‏`type`, ‏`label_text`, ‏`v1` או `labels`, בכל צורת אותיות, מזוהות לבד (ב-JSON Lines, ‏`label_text` לפני `label`); אחרת יש להשתמש ב-`--text-column` וב-`--label-column`. שורת JSON שאינה אובייקט מדולגת. תוויות כמו `spam`, ‏`1`, ‏`phishing` ו-`ham`, ‏`0`, ‏`not_spam`, ‏`legitimate` מובנות.

הודעות כפולות נספרות פעם אחת. הודעה שנמצאת גם במקורות ה-spam וגם במקורות ה-ham נשמרת כ-spam, כי מקורות ה-spam נקראים ראשונים. כדי לבנות על המודל המצורף במקום להתחיל ממודל ריק, מוסיפים `--merge`.

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
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
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

| מאגר נתונים                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | רישיון                     | תוכן                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ----------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | הודעות ודואר אלקטרוני ב-43 שפות                             |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | קורפוס מחקר ציבורי         | קורפוס Enron-Spam                                           |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | הודעות Telegram ברוסית                                      |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | הודעות סינתטיות                                             |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | רשימות תפוצה, ניוזלטרים, ספאם, פישינג והודעות הונאה         |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | הודעות ב-14 משפות הודו                                      |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | הודעות דוא"ל באינדונזית לפי קטגוריה                         |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | דואר של חברה בספרדית                                        |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | דואר רגיל: חשבונות, הזמנות, ניוזלטרים, מבצעים והודעות חשבון |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | מה שאנשים מבקשים מעוזר קולי, ב-20 שפות                      |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                  | דואר של חברה בדויה בצרפתית                                  |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | עם הפרויקט הזה             | דואר יומיומי והונאות ב-23 שפות, שנכתבו עבור הפרויקט הזה     |

ה-ham כולל דואר רגיל של עסקים וחנויות (חשבוניות, הודעות על הזמנות וחשבונות, ניוזלטרים, מבצעים), כך שדואר כזה לבדו אינו נקרא כספאם.

הודעות החזרה (bounce) שבמערכי הנתונים מושמטות: הן נמצאות רק בין הודעות הספאם, וזה היה מלמד את המסווג שכל הודעת החזרה היא ספאם.

שלוש השורות האחרונות הן טקסט רגיל בשפות שבמערכי הנתונים האחרים יש מהן בעיקר ספאם (צרפתית, פורטוגזית, הולנדית, השפות הנורדיות, פולנית, טורקית, ערבית, יפנית, קוריאנית, סינית ועוד), שבהן כל מילה רגילה הייתה נקראת אחרת כספאם. מתוך 10,000 טקסטים רגילים ב-20 שפות שהמודל לא אומן עליהם, 1.4% מקבלים הסתברות של 80% או יותר (4.8% בלי השורות האלה) ו-0.1% הסתברות של 99% או יותר. הטקסט הזה אינו דואר אמיתי, וההונאות שנכתבו לכל שפה מעטות: המסווג בטוח יותר בדואר רגיל בשפות האלה, ותופס רק מעט יותר מהספאם שלהן.

הוא למד מ-81,254 הודעות ספאם ו-133,317 הודעות ham. הסקריפט מחזיק בצד כל הודעה עשירית, מאמן על השאר ומודד את המסווג לבדו, בלי שאר הבדיקות:

| מבחן על הודעות שהוחזקו בצד | הודעות |   דיוק | רגישות | חיוביות שגויות | לא בטוח |
| -------------------------- | -----: | -----: | -----: | -------------: | ------: |
| אנגלית                     |  8,481 | 100.0% |  96.3% |           0.0% |    2.6% |
| רוסית                      |  1,680 | 100.0% |  97.4% |           0.0% |    2.2% |
| איטלקית                    |  1,392 |  99.0% |  81.0% |           0.9% |   12.6% |
| גרמנית                     |  1,314 |  97.9% |  71.4% |           1.9% |   22.3% |
| ספרדית                     |  2,088 |  98.7% |  53.3% |           0.4% |   16.2% |
| Enron-Spam                 |  2,870 | 100.0% |  95.2% |           0.0% |    2.6% |
| all-scam-spam              |  4,222 |  99.9% |  92.2% |           0.0% |    9.1% |
| הכול                       | 21,329 |  99.6% |  76.6% |           0.2% |   14.2% |

כאן ספאם פירושו הסתברות מסווג של 99% ומעלה, הנקודה שבה המסווג לבדו מגיע לסף הספאם. בסריקה, ספאם שהוא פחות בטוח לגביו עדיין מקבל נקודות, ושאר הבדיקות מוסיפות את שלהן.

התוצאות בגרמנית, בספרדית ובאיטלקית מגיעות ממאגרי נתונים סינתטיים, שמכילים הודעות כמעט זהות שתויגו גם כספאם וגם כ-ham: חלק מהשגיאה הזו נמצא בתוויות, לא במודל. דואר בשפות שלכם הוא התיקון הטוב ביותר. המספרים, לכל שפה ולכל מאגר נתונים, נמצאים ב-`metadata.metrics` של המודל.

### שפות נוספות

`npm run model:train -- --with multilingual-sms` מוסיף את [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): אוסף SMS Spam Collection בתרגום מכונה ל-21 שפות. הוא לא נכלל במודל המצורף כי כרטיס המאגר שלו מציין רישיון GPL; כדאי לבדוק שזה מתאים לדרך שבה אתם משתפים את המודל. באימון איתו, התוצאות על הודעות שהוחזקו בצד, בשפות שהמודל המצורף כמעט לא מכיר, היו:

| שפה      | הודעות |   דיוק | רגישות | חיוביות שגויות |
| -------- | -----: | -----: | -----: | -------------: |
| סינית    |    432 | 100.0% |  86.1% |           0.0% |
| ערבית    |    432 | 100.0% |  83.1% |           0.0% |
| קוריאנית |    412 | 100.0% |  78.3% |           0.0% |
| יפנית    |    486 |  96.1% |  87.5% |           0.5% |
| הינדי    |    494 | 100.0% |  76.2% |           0.0% |
| צרפתית   |    511 |  98.7% |  88.6% |           0.6% |
| טורקית   |    222 | 100.0% |  70.4% |           0.0% |

### אימון מחדש

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## קובץ המודל

מודל הוא קובץ JSON: מספר הודעות הספאם וה-ham שנלמדו, ולכל מאפיין מגובב, בכמה הודעות ספאם ו-ham הוא הופיע, ממוין ומקודד ב-base64. אין בו מילים ואין בו טקסט של הודעות. `--max-features` שומר רק את המאפיינים השכיחים ביותר ו-`--min-count` משמיט מאפיינים נדירים, במחיר של דיוק תמורת גודל; המודל המצורף שומר 400,000 מאפיינים בכ-6 MB.

אי אפשר לטעון מודלים מ-Spam Scanner 6 ומגרסאות קודמות: הם גיבבו מאפיינים אחרים. יש לאמן מודל חדש מאותו דואר.
