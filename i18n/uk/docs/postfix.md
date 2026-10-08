<!-- source: f1043eb5fc58 -->

# Postfix і Sendmail

Spam Scanner підключається до Postfix двома способами:

* **Як milter** (рекомендовано). Postfix запитує його про кожен лист під час сеансу SMTP, до прийняття. Спам можна відхилити відповіддю 4xx або 5xx, тож із ним розбирається сервер-відправник, а не ваш. Sendmail використовує той самий протокол.
* **Як контент-фільтр.** Postfix приймає лист і передає його до `spamscanner filter`, який додає заголовки й повертає лист через sendmail. Під час сеансу SMTP нічого не відхиляється.

Обидва способи додають до кожного листа такі заголовки:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Заголовки `X-Spam-*`, які вже є в листі, спершу видаляються, тож відправник не може позначити власну пошту як чисту.


## Milter

### 1. Запуск milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

З `--reject` листи, що досягли порогу відхилення (15 балів), відхиляються з відповіддю `451 4.7.1 Message rejected as spam`. Код 451 тимчасовий: відправник пробує пізніше, а помилку ще можна виправити зміною налаштування. Коли результати виглядатимуть правильними, використайте `--reject-code 550` для постійного відхилення. З `--quarantine` спам натомість потрапляє до черги утримання (hold) Postfix.

Як сервіс systemd, у `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Підключення Postfix

У `/etc/postfix/main.cf`:

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

`smtpd_milters` охоплює пошту, що надходить через SMTP. Залиште `non_smtpd_milters` порожнім, якщо пошту, надіслану командою `sendmail`, не треба перевіряти.

### 3. Перевірка

[swaks](https://www.jetmore.org/john/code/swaks/) надсилає тестові листи. GTUBE — тестовий рядок, який кожен спам-фільтр вважає спамом:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Без `--reject` лист доставляється з `X-Spam-Flag: YES` і позначеною темою. З `--reject` swaks показує відповідь 451 або 550.


## Контент-фільтр

Використовуйте його, коли пошту ніколи не можна відхиляти під час сеансу SMTP, або для сервера, що не підтримує milter.

У `/etc/postfix/master.cf` додайте сервіс фільтра й використайте його на слухачі SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix запускає фільтр майже з порожнім середовищем, тож `argv` вказує Node.js і скрипт повними шляхами (їх показують `command -v node` і `npm root --global`). Потім:

```sh
sudo postfix reload
```

Фільтр повертає лист через `sendmail -G -i`. Пошта, надіслана так, не проходить через слухач `smtp` удруге, тож не фільтрується двічі.

Коди виходу повідомляють Postfix, що сталося: 0 — доставлено, 69 — відхилено (з `--reject`: Postfix повертає лист відправнику), 75 — тимчасовий збій (Postfix зберігає лист і пробує знову). Будь-який збій перевірки чи доставки дає 75, тож хибне налаштування ніколи не призводить до втрати чи повернення пошти.


## Sendmail

У `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` змушує Sendmail відповідати тимчасовою помилкою, поки milter недоступний; приберіть його, щоб натомість приймати пошту без фільтрації. Перезберіть `sendmail.cf` і перезапустіть Sendmail.


## Розкладання спаму в теку «Спам»

Саме лише позначення доставляє спам у «Вхідні». З Dovecot його переміщує правило Sieve:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Інші поштові сервери](mail-servers.md) описують Dovecot, Exim, Haraka і procmail, а [навчання](training.md#learning-from-reports) показує, як учитися на пошті, яку користувачі переміщують у Junk і з нього.


## Перевірено

Наскрізні тести репозиторію запускають справжній Postfix: ham (бажані листи) доставляється із заголовками, підроблений `X-Spam-Flag` видаляється, спам позначається, GTUBE відхиляється з кодом 550 під час сеансу SMTP, а контент-фільтр позначає пошту на другому порту. `scripts/e2e-postfix.sh` налаштовує цей Postfix, а `test/e2e/postfix.test.js` надсилає пошту.
