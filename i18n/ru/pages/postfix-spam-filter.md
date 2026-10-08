<!-- source: f33722183f00 -->

<!--
label: Спам-фильтр для Postfix
title: Спам-фильтр для Postfix: milter или контент-фильтр
description: Фильтрация спама на сервере Postfix через milter или контент-фильтр Spam Scanner: установка, модуль systemd, отклонение с 4xx или 5xx и папка Junk.
keywords: спам-фильтр Postfix, milter для Postfix, smtpd_milters, контент-фильтр Postfix, антиспам для Postfix, отклонение спама в Postfix, настройка Postfix против спама
-->

# Спам-фильтр для Postfix

Spam Scanner начинает фильтровать сервер Postfix примерно за пять минут. Он работает как milter, поэтому Postfix спрашивает его о каждом письме во время SMTP-сессии и может отклонить спам до приёма.


## Установка и запуск

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` проверяет SPF, DKIM, DMARC и ARC; `--subject-tag` помечает спам в теме. Каждое письмо получает заголовки `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` и `X-Spam-Action`, а любой заголовок `X-Spam-*`, добавленный отправителем, сначала удаляется.


## Подключение Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` пропускает почту без фильтрации, если milter недоступен; `tempfail` вместо этого просит отправителей повторить попытку.


## Отклонение спама во время SMTP-сессии

```sh
spamscanner milter --port 7831 --auth --reject
```

Письма на пороге отклонения (15 баллов) отклоняются ответом `451 4.7.1 Message rejected as spam`. Код 451 временный: отправитель сохраняет письмо и повторяет попытку, поэтому неверное решение стоит задержки, а не потерянного письма. Когда результаты выглядят правильно, `--reject-code 550` делает отказ окончательным.


## Без milter

Контент-фильтр работает после того, как Postfix принял письмо: Postfix передаёт его по конвейеру в `spamscanner filter`, который добавляет заголовки и возвращает письмо. Во время сессии ничего не отклоняется, а при сбое доставка всегда откладывается, а не возвращается отправителю. [Настройка контент-фильтра](../../docs/postfix.md#content-filter)


## Спам в Junk

С Dovecot помеченную почту раскладывает правило Sieve:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Проверено на настоящем Postfix

Сквозные тесты проекта запускают Postfix с milter и контент-фильтром: ham доставляется с заголовками, а поддельный `X-Spam-Flag` удаляется, спам помечается, а GTUBE отклоняется с кодом 550 во время SMTP-сессии.

Далее: [полное руководство по Postfix и Sendmail](../../docs/postfix.md) с модулем systemd и `INPUT_MAIL_FILTER` для Sendmail.
