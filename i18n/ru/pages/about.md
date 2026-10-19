<!-- source: 599bd320e55a -->

<!--
label: О проекте
title: О Spam Scanner, лицензии и конфиденциальности
description: Кто делает Spam Scanner, как сообщить об ошибке или уязвимости, какая у него лицензия и что собирает этот сайт: ни cookie, ни аналитики.
keywords: о Spam Scanner, Forward Email, лицензия Spam Scanner, BUSL-1.1, контакты Spam Scanner, конфиденциальность Spam Scanner
-->

# О Spam Scanner

Spam Scanner является спам-фильтром для почты от [Forward Email](https://forwardemail.net), почтового сервиса с упором на конфиденциальность, который создал его для своих почтовых серверов. Исходный код, задачи и релизы находятся на [GitHub](https://github.com/spamscanner/spamscanner), а пакет опубликован в [npm](https://www.npmjs.com/package/spamscanner).


## Кто его делает

Команда Forward Email пишет и поддерживает Spam Scanner. Forward Email не хранит журналы содержимого писем, поэтому не мог отправлять почту внешнему сервису фильтрации: фильтр должен был работать на собственных серверах и объяснять каждое решение без того, чтобы человек читал почту. [Как его использует Forward Email](../../docs/forward-email.md)

Forward Email тоже открытый проект: [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Его основатель был одним из первых сотрудников DuckDuckGo.


## Контакты

* **Вопросы, ошибки и пожелания:** создайте задачу на [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Уязвимости:** сообщайте о них конфиденциально через [систему сообщений об уязвимостях GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), а не в открытых задачах. Тот же адрес указан в [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Другие лицензии:** свяжитесь с [Forward Email](https://forwardemail.net).


## Условия лицензии

[Лицензия](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) Spam Scanner — Business Source License 1.1, а её Change License — Apache License 2.0. Указанная в лицензии Change Date уже прошла, и с этой даты лицензия предоставляет вам права по Apache License 2.0.


## Конфиденциальность

Этот сайт не ставит cookie и не загружает аналитику, трекеры, рекламу, шрифты или скрипты с других сайтов. Все файлы приходят с spamscanner.net.

* Тема, выбранный язык и сервер Mastodon, куда вы делитесь, сохраняются в локальном хранилище браузера и никуда не отправляются.
* Видео загружается только при воспроизведении.
* Ссылки «Поделиться» являются обычными ссылками, поэтому ничего из этих сетей не загружается, пока вы не перейдёте по одной из них.
* Сайт размещён на GitHub Pages, и GitHub в целях безопасности записывает IP-адрес каждого посетителя. См. [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) и [Заявление GitHub о конфиденциальности](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Что отправляет программа

Spam Scanner не отправляет телеметрию и не проверяет обновления. По умолчанию он проверяет имена хостов из ссылок в письме на фильтрующих DNS-резолверах Cloudflare, и больше ничего машину не покидает. Остальные сетевые проверки выключены, пока вы их не включите. [Безопасность и конфиденциальность](../../docs/security.md)


## Релизы

Отдельные исполняемые файлы собирает GitHub Actions из открытого репозитория. Каждый релиз перечисляет их хеши в файле `SHA256SUMS`, который проверяет скрипт установки, и у каждого файла есть подписанная аттестация происхождения сборки. Релизы и их описания находятся на [GitHub](https://github.com/spamscanner/spamscanner/releases).
