<!-- source: f33722183f00 -->

<!--
label: Спам-фільтр для Postfix
title: Спам-фільтр для Postfix через milter або контент-фільтр
description: Фільтрація спаму на сервері Postfix за допомогою milter або контент-фільтра Spam Scanner: налаштування, юніт systemd, відхилення з 4xx чи 5xx і тека «Спам».
keywords: спам-фільтр Postfix, Postfix milter, smtpd_milters, контент-фільтр Postfix, Postfix антиспам, налаштування антиспаму Postfix, відхилення спаму Postfix
-->

# Спам-фільтр для Postfix

Spam Scanner налаштовується як фільтр для сервера Postfix приблизно за п’ять хвилин. Він працює як milter, тож Postfix запитує його про кожен лист під час сеансу SMTP і може відхилити спам до прийняття.


## Встановлення й запуск

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` перевіряє SPF, DKIM, DMARC і ARC; `--subject-tag` позначає спам у темі. Кожен лист отримує заголовки `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` і `X-Spam-Action`, а будь-який заголовок `X-Spam-*`, доданий відправником, спершу видаляється.


## Підключення Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` пропускає пошту без фільтрації, якщо milter недоступний; `tempfail` натомість просить відправників повторити спробу.


## Відхилення спаму під час сеансу SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

Листи, що досягли порогу відхилення (15 балів), відхиляються з відповіддю `451 4.7.1 Message rejected as spam`. Код 451 тимчасовий: відправник зберігає лист і повторює спробу, тож хибне рішення коштує затримки, а не втраченого листа. Коли результати виглядатимуть правильними, `--reject-code 550` робить відхилення постійним.


## Без milter

Контент-фільтр працює після того, як Postfix прийняв лист: Postfix передає його до `spamscanner filter`, який додає заголовки й повертає лист назад. Під час сеансу нічого не відхиляється, а збій завжди відкладає доставку, а не повертає лист відправнику. [Налаштування контент-фільтра](../../docs/postfix.md#content-filter)


## Спам у теку «Спам»

З Dovecot правило Sieve розкладає позначену пошту:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Перевірено на справжньому Postfix

Наскрізні тести проєкту запускають Postfix із milter і контент-фільтром: ham (бажані листи) доставляється із заголовками та без підробленого `X-Spam-Flag`, спам позначається, а GTUBE відхиляється з кодом 550 під час сеансу SMTP.

Далі: [повний посібник з Postfix і Sendmail](../../docs/postfix.md), з юнітом systemd і `INPUT_MAIL_FILTER` для Sendmail.
