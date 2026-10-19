<!-- source: 599bd320e55a -->

<!--
label: Про проєкт
title: Про Spam Scanner, ліцензію та конфіденційність
description: Хто робить Spam Scanner, як повідомити про помилку чи вразливість, яка в нього ліцензія і що збирає цей сайт: жодних cookie й жодної аналітики.
keywords: про Spam Scanner, Forward Email, ліцензія Spam Scanner, BUSL-1.1, контакти Spam Scanner, конфіденційність Spam Scanner
-->

# Про Spam Scanner

Spam Scanner є спам-фільтром для пошти від [Forward Email](https://forwardemail.net), поштового сервісу з наголосом на конфіденційності, який створив його для власних поштових серверів. Вихідний код, задачі й релізи розміщено на [GitHub](https://github.com/spamscanner/spamscanner), а пакет опубліковано в [npm](https://www.npmjs.com/package/spamscanner).


## Хто його робить

Команда Forward Email пише й підтримує Spam Scanner. Forward Email не зберігає журналів вмісту листів, тож не могла надсилати пошту зовнішньому сервісу фільтрації: фільтр мав працювати на власних серверах і пояснювати кожне рішення без того, щоб людина читала пошту. [Як його використовує Forward Email](../../docs/forward-email.md)

Forward Email теж має відкритий код: [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Його засновник був одним із перших працівників DuckDuckGo.


## Контакти

* **Запитання, помилки й побажання:** створіть задачу на [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Вразливості:** повідомляйте про них конфіденційно через [систему повідомлень про вразливості GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), а не у відкритих задачах. Та сама адреса є в [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Інші ліцензії:** зверніться до [Forward Email](https://forwardemail.net).


## Умови ліцензії

[Ліцензія](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) Spam Scanner — Business Source License 1.1, а її Change License — Apache License 2.0. Зазначена в ліцензії Change Date уже минула, і з цієї дати ліцензія надає вам права за Apache License 2.0.


## Конфіденційність

Цей сайт не встановлює cookie й не завантажує аналітику, трекери, рекламу, шрифти чи скрипти з інших сайтів. Усі файли надходять зі spamscanner.net.

* Тема, обрана мова й сервер Mastodon, куди ви ділитеся, зберігаються в локальному сховищі браузера й нікуди не надсилаються.
* Відео завантажується лише тоді, коли ви його відтворюєте.
* Посилання «Поділитися» є звичайними посиланнями, тож нічого з цих мереж не завантажується, доки ви не перейдете за одним із них.
* Сайт розміщено на GitHub Pages, і GitHub з міркувань безпеки записує IP-адресу кожного відвідувача. Див. [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) і [Заяву GitHub про конфіденційність](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Що надсилає програма

Spam Scanner не надсилає телеметрію й не перевіряє оновлення. За замовчуванням він перевіряє імена хостів із посилань у листі на фільтрувальних DNS-резолверах Cloudflare, і більше ніщо не залишає машину. Інші мережеві перевірки вимкнені, доки ви їх не ввімкнете. [Безпека та конфіденційність](../../docs/security.md)


## Релізи

Окремі виконувані файли збирає GitHub Actions з відкритого репозиторію. Кожен реліз перелічує їхні хеші у файлі `SHA256SUMS`, який перевіряє скрипт встановлення, і кожен файл має підписану атестацію походження збірки. Релізи та їхні описи розміщено на [GitHub](https://github.com/spamscanner/spamscanner/releases).
