<!-- source: f1043eb5fc58 -->

# Postfix и Sendmail

Spam Scanner подключается к Postfix двумя способами:

* **Как milter** (рекомендуется). Postfix спрашивает его о каждом письме во время SMTP-сессии, до приёма. Спам можно отклонить ответом 4xx или 5xx, и тогда с ним разбирается отправляющий сервер, а не ваш. Sendmail использует тот же протокол.
* **Как контент-фильтр.** Postfix принимает письмо и передаёт его по конвейеру в `spamscanner filter`, который добавляет заголовки и возвращает письмо через sendmail. Во время SMTP-сессии ничего не отклоняется.

Оба способа добавляют к каждому письму такие заголовки:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Заголовки `X-Spam-*`, уже имеющиеся в письме, сначала удаляются, поэтому отправитель не может пометить собственную почту как чистую.


## Milter

### 1. Запуск milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

С `--reject` письма на пороге отклонения (15 баллов) отклоняются ответом `451 4.7.1 Message rejected as spam`. Код 451 временный: отправитель повторит попытку позже, а ошибку ещё можно исправить, изменив настройку. Когда результаты выглядят правильно, используйте `--reject-code 550` для окончательного отказа. С `--quarantine` спам вместо этого попадает в очередь удержания (hold) Postfix.

Как служба systemd, в `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Подключение Postfix

В `/etc/postfix/main.cf`:

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

`smtpd_milters` охватывает почту, приходящую по SMTP. Оставьте `non_smtpd_milters` пустым, если только почта, отправленная командой `sendmail`, тоже не должна проверяться.

### 3. Проверка

[swaks](https://www.jetmore.org/john/code/swaks/) отправляет тестовые письма. GTUBE — тестовая строка, которую любой спам-фильтр считает спамом:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Без `--reject` письмо доставляется с `X-Spam-Flag: YES` и помеченной темой. С `--reject` swaks показывает ответ 451 или 550.


## Контент-фильтр

Используйте этот способ, когда почту нельзя отклонять во время SMTP-сессии, или для сервера, который не поддерживает milter.

В `/etc/postfix/master.cf` добавьте службу фильтра и используйте её на SMTP-слушателе:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix запускает фильтр почти с пустым окружением, поэтому в `argv` Node.js и скрипт указаны полными путями (их показывают `command -v node` и `npm root --global`). Затем:

```sh
sudo postfix reload
```

Фильтр возвращает письмо через `sendmail -G -i`. Почта, отправленная таким способом, повторно не проходит через слушатель `smtp`, поэтому не фильтруется дважды.

Коды выхода сообщают Postfix, что произошло: 0 — доставлено, 69 — отклонено (с `--reject`: Postfix возвращает письмо отправителю), 75 — временный сбой (Postfix сохраняет письмо и повторяет попытку). Любой сбой проверки или доставки даёт 75, поэтому ошибка в настройке никогда не приводит к потере или возврату почты.


## Sendmail

В `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` заставляет Sendmail отвечать временным сбоем, пока milter недоступен; уберите его, чтобы вместо этого принимать почту без фильтрации. Пересоберите `sendmail.cf` и перезапустите Sendmail.


## Сортировка спама в папку Junk

Одна только пометка доставляет спам во входящие. С Dovecot его перемещает правило Sieve:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

На странице [Другие почтовые серверы](mail-servers.md) описаны Dovecot, Exim, Haraka и procmail, а в разделе [Обучение](training.md#learning-from-reports) показано, как обучать модель на почте, которую пользователи перемещают в Junk и обратно.


## Проверено

Сквозные тесты репозитория запускают настоящий Postfix: ham доставляется с заголовками, поддельный `X-Spam-Flag` удаляется, спам помечается, GTUBE отклоняется с кодом 550 во время SMTP-сессии, а контент-фильтр помечает почту на втором порту. `scripts/e2e-postfix.sh` настраивает этот Postfix, а `test/e2e/postfix.test.js` отправляет почту.
