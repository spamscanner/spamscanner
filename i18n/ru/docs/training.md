<!-- source: 6f344039ec5d -->

# Обучение

Встроенная модель работает сразу. Модель, обученная на вашей собственной почте, работает лучше, потому что узнаёт, как выглядит ваш ham: ваши рассылки, манеру письма ваших коллег, языки, на которых вам пишут.


## Обучение модели

Укажите `train` папки со спамом и ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Источниками могут быть:

* файлы **mbox**, в том числе сжатые gzip (`.mbox.gz`; другие файлы `.gz` пропускаются),
* каталог **Maildir** (читаются его папки `cur` и `new`, `tmp` пропускается),
* **папка** с файлами `.eml`, читаемая рекурсивно,
* **набор данных**: файл CSV или JSON Lines со столбцом текста и столбцом метки (`--dataset`). Столбцы или поля JSON с именами `text`, `message`, `body`, `email text`, `email`, `content`, `sms` или `v2` и `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` или `labels`, в любом регистре, находятся автоматически (в JSON Lines `label_text` раньше `label`); иначе используйте `--text-column` и `--label-column`. Строка JSON, которая не является объектом, пропускается. Распознаются такие метки, как `spam`, `1`, `phishing` и `ham`, `0`, `not_spam`, `legitimate`.

Повторяющиеся письма учитываются один раз. Письмо, которое есть и в источниках спама, и в источниках ham, остаётся спамом, поскольку источники спама читаются первыми. Чтобы дообучить встроенную модель, а не начинать с пустой, добавьте `--merge`.

Использование модели:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Сколько почты достаточно: несколько сотен писем каждого вида дают полезную модель, несколько тысяч — хорошую. Держите оба класса примерно в равновесии и включайте в ham почту, которую не нужно фильтровать (сброс пароля, счета от ваших поставщиков).


## Измерение качества

Отложите часть почты при обучении и измеряйте на ней:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Встроенная модель на SMS-сообщениях на 21 языке, которых она никогда не видела, причём большинство — на языках, которые она почти не знает:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Точность (precision) показывает, какая доля того, что модель называет спамом, действительно спам; полнота (recall) — какую долю спама она ловит. Неуверенные письма здесь считаются пропущенным спамом, хотя при проверке их всё ещё могут поймать остальные проверки и языковая модель. Следить нужно за ложными срабатываниями: ham, помеченным как спам. В прогоне выше модель не уверена в большинстве этих писем, а не ошибается в них, и это задуманное поведение для языков, на которых у неё мало почты.

`--json` выдаёт те же числа для скриптов.


## Обучение по жалобам

Когда пользователи перемещают почту в папку Junk или из неё, обучайте модель по одному письму:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Первый `learn` создаёт файл из встроенной модели. По HTTP то же делают `POST /learn/spam` и `/learn/ham` в [HTTP API](http-api.md), а `spamc -L spam` работает с [сервером spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) при `--allow-tell`. [IMAPSieve в Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) может вызывать любой из них при перемещении письма.

Из Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Если письмо, о котором сообщили как о неверно классифицированном, уже было выучено, его нужно сначала разучить из неверного класса, а затем выучить в правильном.


## Встроенная модель

`model/classifier.json` собирается командой `npm run model:train` из этих публичных наборов данных на Hugging Face, все под открытыми лицензиями:

| Набор данных                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Лицензия                           | Содержимое                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------- | ------------------------------------------------------------------------------------ |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                         | Сообщения и письма на 43 языках                                                      |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Публичный исследовательский корпус | Корпус Enron-Spam                                                                    |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                            | Русские сообщения из Telegram                                                        |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                                | Синтетические сообщения                                                              |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                          | Списки рассылки, новостные рассылки, спам, фишинг и мошеннические письма             |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                                | Сообщения на 14 языках Индии                                                         |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                         | Индонезийские письма по категориям                                                   |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                         | Почта одной компании на испанском языке                                              |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0         | Обычная почта: счета, бронирования, рассылки, акции и уведомления об аккаунте        |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                          | О чём люди просят голосового помощника, на 20 языках                                 |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                          | Почта вымышленной компании на французском языке                                      |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Вместе с этим проектом             | Повседневная почта и мошеннические письма на 23 языках, написанные для этого проекта |

В хам входит обычная деловая и магазинная почта (счета, уведомления о заказах и аккаунте, рассылки, акции), поэтому такая почта сама по себе не считается спамом.

Уведомления о недоставке (bounce) из наборов данных исключаются: они есть только среди спама, и это научило бы классификатор считать спамом любое такое уведомление.

Последние три строки — обычный текст на языках, на которых в остальных наборах данных есть в основном спам (французский, португальский, нидерландский, скандинавские языки, польский, турецкий, арабский, японский, корейский, китайский и другие) и на которых иначе каждое обычное слово читалось бы как спам. Из 10 000 обычных текстов на 20 языках, на которых модель не обучалась, 1,4 % получают вероятность 80 % и выше (4,8 % без этих строк), а 0,1 % — 99 % и выше. Этот текст не настоящая почта, а мошеннических писем, написанных для каждого языка, немного: классификатор увереннее распознаёт обычную почту на этих языках и ловит лишь немного больше их спама.

Она обучена на 81 254 письмах со спамом и 133 317 письмах ham. Скрипт откладывает каждое десятое письмо, обучается на остальных и измеряет только классификатор, без остальных проверок:

| Отложенный тест | Письма | Точность | Полнота | Ложные срабатывания | Unsure |
| --------------- | -----: | -------: | ------: | ------------------: | -----: |
| Английский      |  8 481 |  100,0 % |  96,3 % |               0,0 % |  2,6 % |
| Русский         |  1 680 |  100,0 % |  97,4 % |               0,0 % |  2,2 % |
| Итальянский     |  1 392 |   99,0 % |  81,0 % |               0,9 % | 12,6 % |
| Немецкий        |  1 314 |   97,9 % |  71,4 % |               1,9 % | 22,3 % |
| Испанский       |  2 088 |   98,7 % |  53,3 % |               0,4 % | 16,2 % |
| Enron-Spam      |  2 870 |  100,0 % |  95,2 % |               0,0 % |  2,6 % |
| all-scam-spam   |  4 222 |   99,9 % |  92,2 % |               0,0 % |  9,1 % |
| Всего           | 21 329 |   99,6 % |  76,6 % |               0,2 % | 14,2 % |

Спамом здесь считается вероятность по оценке классификатора 99 % и выше — точка, в которой один классификатор достигает порога спама. При проверке спам, в котором он менее уверен, всё равно получает баллы, а остальные проверки добавляют свои.

Результаты для немецкого, испанского и итальянского получены на синтетических наборах данных, где есть почти одинаковые письма, размеченные и как спам, и как ham: часть ошибки заключена в разметке, а не в модели. Лучшее решение — почта на ваших собственных языках. Числа для каждого языка и набора данных находятся в `metadata.metrics` модели.

### Больше языков

`npm run model:train -- --with multilingual-sms` добавляет [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): коллекцию SMS Spam Collection, машинно переведённую на 21 язык. Она не входит во встроенную модель, потому что в её карточке указана лицензия GPL; проверьте, подходит ли это для того, как вы распространяете модель. С ней результаты на отложенных письмах для языков, которые встроенная модель почти не знает, были такими:

| Язык        | Письма | Точность | Полнота | Ложные срабатывания |
| ----------- | -----: | -------: | ------: | ------------------: |
| Китайский   |    432 |  100,0 % |  86,1 % |               0,0 % |
| Арабский    |    432 |  100,0 % |  83,1 % |               0,0 % |
| Корейский   |    412 |  100,0 % |  78,3 % |               0,0 % |
| Японский    |    486 |   96,1 % |  87,5 % |               0,5 % |
| Хинди       |    494 |  100,0 % |  76,2 % |               0,0 % |
| Французский |    511 |   98,7 % |  88,6 % |               0,6 % |
| Турецкий    |    222 |  100,0 % |  70,4 % |               0,0 % |

### Переобучение

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Файл модели

Модель — это JSON-файл: количество выученных писем со спамом и ham, а для каждого хешированного признака — сколько писем со спамом и ham его содержали, в отсортированном виде и в кодировке base64. В нём нет ни слов, ни текста писем. `--max-features` оставляет только самые частые признаки, а `--min-count` отбрасывает редкие, жертвуя точностью ради размера; встроенная модель хранит 400 000 признаков примерно в 6 МБ.

Модели из Spam Scanner 6 и более ранних версий загрузить нельзя: они хешировали другие признаки. Обучите новую на той же почте.
