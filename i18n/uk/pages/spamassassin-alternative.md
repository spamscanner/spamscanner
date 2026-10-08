<!-- source: 1562b843d858 -->

<!--
label: Альтернатива SpamAssassin
title: Альтернатива SpamAssassin, що підтримує протокол spamd
description: Замініть spamd від SpamAssassin на Spam Scanner. spamc, Exim і Haraka працюють далі, заголовки X-Spam зберігають назви, і підтримується будь-яка мова.
keywords: альтернатива SpamAssassin, заміна SpamAssassin, заміна spamd, spamc, спам-фільтр Exim, Haraka spamassassin, альтернатива rspamd, X-Spam-Status
-->

# Альтернатива SpamAssassin, що підтримує протокол spamd

Spam Scanner відповідає за протоколом spamd від SpamAssassin, тож програми, написані для SpamAssassin, використовують його без змін: spamc, умова `spam` в Exim, плагін `spamassassin` у Haraka та інші.


## Заміна

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

Він відповідає на `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING`, а з `--allow-tell` — і на `TELL` для навчання. Наскрізні тести проєкту запускають проти нього власний spamc від SpamAssassin.


## Що залишається незмінним

* Заголовки: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` і `X-Spam-Status` у форматі SpamAssassin, тож наявні правила Sieve, procmail і поштових клієнтів працюють далі.
* Бал із порогом 5, складений з іменованих тестів із балами: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` тощо.
* Бали окремих тестів можна змінювати за назвою тесту.


## Що відрізняється

* **Мови.** Слова виділяються за правилами Unicode, тож китайська, японська й тайська читаються як слова, а не як один довгий рядок, а маскування на кшталт невидимих символів чи кириличних літер у латинських словах спершу знімається.
* **Фішинг.** Схожі домени, оманливі посилання та назви брендів в іменах відправника перевіряються без додаткових правил.
* **Вкладення** розпізнаються за байтами: виконуваний файл, перейменований на `.pdf`, залишається виконуваним файлом.
* **Мовні моделі.** Спірні випадки можна передати локальній моделі через Ollama або хмарній.
* **Node.js.** Один `npm install` або окремий виконуваний файл; жодних модулів Perl чи оновлень правил, якими треба керувати.

Spam Scanner не виконує файли правил SpamAssassin, і формат його баєсової бази даних власний: навчіть його на тій самій пошті за допомогою `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot і procmail](../../docs/mail-servers.md)
