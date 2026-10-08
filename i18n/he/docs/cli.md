<!-- source: a59bc5927d86 -->

# שורת הפקודה

```text
spamscanner <command> [options]
```

| פקודה                                      | מה היא עושה                                                             |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| `scan [file\|-]`                           | סורקת הודעה מקובץ או מהקלט הסטנדרטי                                     |
| `filter -f <sender> -- <recipients...>`    | מסנן תוכן ל-Postfix: סורקת את הקלט הסטנדרטי, מוסיפה כותרות ומעבירה הלאה |
| `milter`                                   | Milter ל-Postfix ול-Sendmail, פורט 7831                                 |
| `http`                                     | HTTP API, פורט 7832                                                     |
| `server`                                   | שרת TCP פשוט, פורט 7830                                                 |
| `spamd`                                    | שרת spamd תואם SpamAssassin, פורט 783                                   |
| `train`                                    | מאמנת מודל מקובצי mbox, מתיקיות Maildir, מתיקיות או ממאגרי נתונים       |
| `eval`                                     | מודדת מודל על דואר מתויג                                                |
| `learn spam\|ham [file\|-] --model <file>` | מלמדת מודל הודעה אחת                                                    |
| `llm-test`                                 | בודקת את הגדרות מודל השפה עם שלוש הודעות לדוגמה                         |
| `models`                                   | מציגה מודלים פתוחים מומלצים                                             |
| `version`, `help`                          |                                                                         |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| אפשרות                     | משמעות                                             |
| -------------------------- | -------------------------------------------------- |
| `--json`                   | מדפיסה את התוצאה המלאה כ-JSON                      |
| `--headers`                | מדפיסה את ההודעה עם כותרות `X-Spam-*` שנוספו לה    |
| `--subject-tag <tag>`      | מוסיפה גם קידומת לנושא של ספאם                     |
| `--verbose`                | מציגה כל בדיקה, ואת הסימנים החזקים ביותר של המסווג |
| `--threshold <n>`          | הניקוד שבו דואר הוא ספאם (ברירת מחדל 5)            |
| `--reject-threshold <n>`   | הניקוד שבו דואר נדחה (ברירת מחדל 15)               |
| `--model <file>`           | קובץ מודל במקום המודל המצורף                       |
| `--no-classifier`          | לא להשתמש במסווג                                   |
| `--config <file>`          | קובץ JSON עם [אפשרויות ספרייה](api.md#options)     |
| `--allow-language <codes>` | שפות מקובלות, למשל `en,de,fr`                      |

קודי יציאה: 0 ham, ‏1 ספאם, 2 שגיאה.

### שיחת SMTP

| אפשרות              | משמעות                                   |
| ------------------- | ---------------------------------------- |
| `--ip <address>`    | כתובת ה-IP של הלקוח ששלח את ההודעה       |
| `--hostname <name>` | שם ה-DNS ההפוך המאומת של הלקוח           |
| `--helo <name>`     | השם שהלקוח מסר ב-HELO או ב-EHLO          |
| `--from <address>`  | שולח המעטפה (MAIL FROM)                  |
| `--to <address>`    | נמען המעטפה; חוזרים עליה עבור כמה נמענים |

### בדיקות

| אפשרות                | משמעות                                                                     |
| --------------------- | -------------------------------------------------------------------------- |
| `--auth`              | בודקת SPF,‏ DKIM,‏ DMARC ו-ARC (דורשת `--ip`)                              |
| `--dnsbl <zone>`      | רשימה שחורה של IP, למשל `zen.spamhaus.org`; אפשר לחזור עליה                |
| `--uribl <zone>`      | רשימה שחורה של דומיינים לקישורים, למשל `dbl.spamhaus.org`; אפשר לחזור עליה |
| `--dns-server <ip>`   | שרת שמות לבדיקות DNS; אפשר לחזור עליה                                      |
| `--no-cloudflare`     | לא לשאול את שרתי ה-DNS המסננים של Cloudflare על קישורים                    |
| `--clamav [socket]`   | סורקת קבצים מצורפים עם clamd, ב-socket ברירת המחדל שלו או ב-socket שצוין   |
| `--allowlist <value>` | תמיד לקבל את כתובת ה-IP, הדומיין או הכתובת האלה; אפשר לחזור עליה           |
| `--denylist <value>`  | תמיד לדחות את כתובת ה-IP, הדומיין או הכתובת האלה; אפשר לחזור עליה          |

### מודל שפה

| אפשרות                                                     | משמעות                                                                       |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` ואחרים ([רשימה](llm.md#providers)) |
| `--llm-model <name>`                                       | מודל, למשל `qwen3.5:4b` או `claude-haiku-4-5`                                |
| `--llm-url <url>`                                          | כתובת URL בסיסית, למשל `http://10.0.0.5:11434`                               |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | משנות חלק אחד מכתובת ה-URL של הספק                                           |
| `--llm-api-key <key>`                                      | מפתח API; ראו גם את משתני הסביבה בהמשך                                       |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` או `none`                |
| `--llm-auth-header <name>`                                 | הכותרת שבה נשלח המפתח, עם `--llm-auth header`                                |
| `--llm-username`, `--llm-password`                         | עבור `--llm-auth basic`                                                      |
| `--llm-header "Name: value"`                               | כותרת בקשה נוספת; אפשר לחזור עליה                                            |
| `--llm-mode <mode>`                                        | `auto` (רק מקרים גבוליים, ברירת המחדל) או `always`                           |
| `--llm-timeout <ms>`                                       | ברירת מחדל 30000                                                             |
| `--llm-policy <text>`                                      | כללים נוספים למודל, למשל „אנחנו אף פעם לא שולחים חשבוניות”                   |
| `--llm-redact`, `--no-llm-redact`                          | מסירות קודם מידע אישי; מופעל כברירת מחדל לספקים מרוחקים                      |


## filter

[מסנן תוכן ל-Postfix](postfix.md#content-filter). הוא קורא הודעה מהקלט הסטנדרטי, מוסיף כותרות `X-Spam-*` ומעביר אותה ל-sendmail עם אותה מעטפה.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| אפשרות                | משמעות                                                    |
| --------------------- | --------------------------------------------------------- |
| `--sendmail <path>`   | ברירת מחדל `/usr/sbin/sendmail`                           |
| `--subject-tag <tag>` | קידומת לנושא של ספאם                                      |
| `--reject`            | מחזירה לשולח דואר שמגיע לסף הדחייה במקום להעביר אותו הלאה |
| `--discard`           | משמיטה דואר שמגיע לסף הדחייה במקום להעביר אותו הלאה       |

קודי היציאה עוקבים אחרי המוסכמות של sendmail, ש-Postfix קורא: 0 נמסר (או הושמט), 64 לא צוינו נמענים, 69 נדחה כספאם (Postfix מחזיר אותו לשולח), 75 כל כישלון, כך ש-Postfix שומר את ההודעה ומנסה שוב מאוחר יותר.


## milter, http, server ו-spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

פורט 783 הוא הפורט שלקוחות SpamAssassin משתמשים בו כברירת מחדל. פורטים מתחת ל-1024 דורשים root או את היכולת `CAP_NET_BIND_SERVICE`; אפשר להשתמש בפורט אחר, כמו `--port 7833`, ולעדכן את הלקוח.

| אפשרות                | משמעות                                                           |
| --------------------- | ---------------------------------------------------------------- |
| `--port <n>`          | פורט TCP                                                         |
| `--host <ip>`         | הכתובת להאזנה (ברירת מחדל 127.0.0.1)                             |
| `--socket <path>`     | האזנה על Unix socket במקום זאת                                   |
| `--reject`            | Milter: דוחה דואר שמגיע לסף הדחייה                               |
| `--reject-code <n>`   | Milter: ‏451, לנסות שוב מאוחר יותר (ברירת המחדל), או 550         |
| `--quarantine`        | Milter: מחזיקה ספאם בהסגר של שרת הדואר                           |
| `--name <hostname>`   | Milter: השם של השרת הזה ב-Authentication-Results                 |
| `--token <secret>`    | HTTP: דורשת `Authorization: Bearer <secret>`; נדרש עבור `/learn` |
| `--allow-tell`        | spamd: מקבלת בקשות TELL‏ (`spamc -L spam`) ללמידה                |
| `--out <file>`        | HTTP ו-spamd: שומרת את מה שנלמד לקובץ המודל הזה                  |
| `--subject-tag <tag>` | Milter ו-spamd: קידומת לנושא של ספאם                             |
| `--verbose`           | Milter: רושמת ביומן כל סריקה. שרת TCP: עונה בשורת טקסט אחת       |

אפשרויות הסריקה שלמעלה חלות גם על השרתים. [ה-milter](postfix.md#milter), [ה-HTTP API, שרת ה-TCP ו-spamd](http-api.md).


## train, eval ו-learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| אפשרות                                          | משמעות                                                               |
| ----------------------------------------------- | -------------------------------------------------------------------- |
| `--spam <path>`                                 | ספאם: קובץ mbox, ‏Maildir או תיקייה של קובצי `.eml`; אפשר לחזור עליה |
| `--ham <path>`                                  | Ham, באותו אופן; אפשר לחזור עליה                                     |
| `--dataset <file>`                              | קובץ CSV או JSON Lines עם עמודות טקסט ותווית; אפשר לחזור עליה        |
| `--text-column <name>`, `--label-column <name>` | שמות העמודות, כשהן לא מזוהות                                         |
| `--out <file>`                                  | לאן לכתוב את המודל (ברירת מחדל `spamscanner-model.json`)             |
| `--merge`                                       | להתחיל מהמודל המצורף (או מ-`--model`) במקום ממודל ריק                |

`learn` מעדכנת את קובץ המודל במקום, ויוצרת אותו מהמודל המצורף בפעם הראשונה. [אימון](training.md)


## llm-test ו-models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` שולחת למודל הודעה רגילה אחת ושתי הונאות, באנגלית ובאיטלקית, מדפיסה את פסקי הדין שלו ויוצאת עם 0 רק אם שלושתם נכונים.


## קובץ תצורה

`--config file.json` (או משתנה הסביבה `SPAMSCANNER_CONFIG`) טוען [אפשרויות ספרייה](api.md#options). אפשרויות שורת הפקודה גוברות על הקובץ.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## משתני סביבה

| משתנה                                                                                                                                                                                                                                                | משמעות                             |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | קובץ תצורה                         |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | קובץ מודל שמשמש במקום המודל המצורף |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | אסימון ל-HTTP API                  |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | מפתח API לכל ספק של מודל שפה       |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | המפתח של כל ספק                    |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | רישום ביומן לצורכי ניפוי באגים     |
