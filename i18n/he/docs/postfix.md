<!-- source: f1043eb5fc58 -->

# Postfix ו-Sendmail

Spam Scanner מתחבר ל-Postfix בשתי דרכים:

* **כ-milter** (מומלץ). Postfix שואל אותו על כל הודעה במהלך שיחת ה-SMTP, לפני שהוא מקבל אותה. אפשר לדחות ספאם בתשובת 4xx או 5xx, כך שהשרת השולח, ולא השרת שלכם, מטפל בה. Sendmail משתמש באותו פרוטוקול.
* **כמסנן תוכן.** Postfix מקבל את ההודעה ומעביר אותה דרך צינור ל-`spamscanner filter`, שמוסיף כותרות ומחזיר אותה בעזרת sendmail. שום דבר לא נדחה אף פעם במהלך שיחת ה-SMTP.

שתי הדרכים מוסיפות את הכותרות האלה לכל הודעה:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

כותרות `X-Spam-*` שכבר נמצאות בהודעה מוסרות קודם, כך ששולח לא יכול לסמן את הדואר שלו כנקי.


## Milter

### 1. הפעלת ה-milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

עם `--reject`, הודעות שמגיעות לסף הדחייה (15 נקודות) נדחות עם `451 4.7.1 Message rejected as spam`. ‏451 הוא זמני: השולח מנסה שוב מאוחר יותר, ועדיין אפשר לתקן טעות על ידי שינוי הגדרה. כשהתוצאות נראות נכונות, אפשר להשתמש ב-`--reject-code 550` לדחייה קבועה. עם `--quarantine`, ספאם עובר במקום זאת לתור ההשהיה (hold) של Postfix.

כשירות systemd, ב-`/etc/systemd/system/spamscanner-milter.service`:

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. חיבור Postfix אליו

ב-`/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters` מכסה דואר שמגיע דרך SMTP. יש להשאיר את `non_smtpd_milters` ריק, אלא אם גם דואר שנשלח בפקודה `sendmail` צריך להיסרק.

### 3. בדיקה

[swaks](https://www.jetmore.org/john/code/swaks/) שולח הודעות בדיקה. GTUBE היא מחרוזת בדיקה שכל מסנן ספאם מתייחס אליה כספאם:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

בלי `--reject`, ההודעה נמסרת עם `X-Spam-Flag: YES` ועם נושא מסומן. עם `--reject`, ‏swaks מציג את תשובת ה-451 או ה-550.


## מסנן תוכן

יש להשתמש בזה כשאסור לעולם לדחות דואר במהלך שיחת ה-SMTP, או בשרת שלא יכול להשתמש ב-milters.

ב-`/etc/postfix/master.cf`, יש להוסיף שירות סינון ולהשתמש בו במאזין ה-SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix מריץ את המסנן עם סביבה כמעט ריקה, ולכן `argv` מציין את Node.js ואת הסקריפט בנתיבים המלאים שלהם (`command -v node` ו-`npm root --global` מציגים אותם). אחר כך:

```sh
sudo postfix reload
```

המסנן מחזיר את ההודעה עם `sendmail -G -i`. דואר שנשלח בדרך הזו לא עובר שוב דרך המאזין `smtp`, כך שהוא לא מסונן פעמיים.

קודי היציאה אומרים ל-Postfix מה קרה: 0 נמסר, 69 נדחה (עם `--reject`: ‏Postfix מחזיר אותו לשולח), 75 כישלון זמני (Postfix שומר את ההודעה ומנסה שוב). כל כישלון בסריקה או במסירה הוא 75, כך שהגדרה שבורה לעולם לא גורמת לאובדן דואר או להחזרתו.


## Sendmail

ב-`sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` גורם ל-Sendmail לענות בכישלון זמני כל עוד ה-milter לא זמין; בלעדיו, הדואר מתקבל בלי סינון. יש לבנות מחדש את `sendmail.cf` ולהפעיל מחדש את Sendmail.


## מיון ספאם לתיקיית Junk

סימון לבדו מוסר ספאם לתיבת הדואר הנכנס. עם Dovecot, כלל Sieve מעביר אותו:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[שרתי דואר אחרים](mail-servers.md) מכסה את Dovecot,‏ Exim,‏ Haraka ו-procmail, ו[אימון](training.md#learning-from-reports) מראה איך ללמוד מדואר שמשתמשים מעבירים אל תיקיית Junk וממנה.


## נבדק

בדיקות הקצה-לקצה של המאגר מריצות Postfix אמיתי: ham נמסר עם כותרות, `X-Spam-Flag` מזויף מוסר, ספאם מסומן, GTUBE נדחה עם 550 במהלך שיחת ה-SMTP, ומסנן התוכן מסמן דואר בפורט שני. `scripts/e2e-postfix.sh` מקים את ה-Postfix הזה, ו-`test/e2e/postfix.test.js` שולח את הדואר.
