<!-- source: c4f8c2c7aa5a -->

# Навчання

Вбудована модель працює одразу. Модель, навчена на вашій власній пошті, працює краще, бо вивчає, як виглядає ваш ham (бажані листи): ваші розсилки, стиль ваших колег, мови, якими ви отримуєте пошту.


## Навчання моделі

Вкажіть `train` теки зі спамом і ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Джерелами можуть бути:

* файли **mbox**, зокрема стиснені gzip (`.mbox.gz`; інші файли `.gz` пропускаються),
* каталог **Maildir** (читаються його теки `cur` і `new`, `tmp` пропускається),
* **тека** з файлами `.eml`, яка читається рекурсивно,
* **набір даних**: файл CSV або JSON Lines зі стовпцем тексту й стовпцем мітки (`--dataset`). Стовпці або поля JSON з назвами `text`, `message`, `body`, `email text`, `email`, `content`, `sms` або `v2` і `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` або `labels`, у будь-якому регістрі, знаходяться автоматично (у JSON Lines `label_text` раніше за `label`); інакше використовуйте `--text-column` і `--label-column`. Рядок JSON, що не є об’єктом, пропускається. Розпізнаються мітки на кшталт `spam`, `1`, `phishing` і `ham`, `0`, `not_spam`, `legitimate`.

Дублікати листів ураховуються один раз. Лист, що є і в джерелах спаму, і в джерелах ham, залишається спамом, адже джерела спаму читаються першими. Щоб розвивати вбудовану модель, а не починати з порожньої, додайте `--merge`.

Використання моделі:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Скільки пошти достатньо: кілька сотень листів кожного типу дають корисну модель, кілька тисяч — добру. Тримайте обидва типи приблизно збалансованими й додавайте до ham пошту, яку не треба фільтрувати (скидання паролів, рахунки від ваших постачальників).


## Вимірювання

Залиште частину пошти поза навчанням і вимірюйте на ній:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Вбудована модель на SMS-повідомленнях 21 мовою, яких вона ніколи не бачила, здебільшого мовами, які вона ледве знає:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Точність (precision) показує, яка частка того, що модель називає спамом, справді є спамом; повнота (recall) — яку частку спаму вона виявляє. Невизначені листи тут зараховуються як пропущений спам, хоча під час перевірки їх ще можуть виявити інші перевірки та мовна модель. Стежити варто за хибнопозитивними результатами: ham, позначеним як спам. У наведеному запуску модель здебільшого не впевнена щодо цих листів, а не помиляється, і саме такої поведінки очікують для мов, у яких вона бачила мало пошти.

`--json` видає ті самі числа для скриптів.


## Навчання за скаргами

Коли користувачі переміщують пошту в теку Junk або з неї, навчайте модель по одному листу:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Перший `learn` створює файл із вбудованої моделі. Через HTTP те саме роблять `POST /learn/spam` і `/learn/ham` у [HTTP API](http-api.md), а `spamc -L spam` працює із [сервером spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) з `--allow-tell`. [IMAPSieve у Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) може викликати будь-який із них, коли лист переміщують.

З Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Лист, про який повідомили як про неправильно класифікований, слід спершу вилучити з навчання в хибному класі, а потім навчити в правильному, якщо його вже вивчали раніше.


## Вбудована модель

`model/classifier.json` збирається командою `npm run model:train` з таких відкритих наборів даних на Hugging Face, усі з вільними ліцензіями:

| Набір даних                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Ліцензія                       | Вміст                                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------ | -------------------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                     | Повідомлення й листи 43 мовами                                                         |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Відкритий дослідницький корпус | Корпус Enron-Spam                                                                      |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                        | Російські повідомлення з Telegram                                                      |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                            | Синтетичні повідомлення                                                                |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                      | Списки розсилки, новинні розсилки, спам, фішинг і шахрайські листи                     |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                            | Повідомлення 14 мовами Індії                                                           |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                     | Індонезійські листи за категоріями                                                     |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                     | Пошта однієї компанії іспанською мовою                                                 |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0     | Звичайна пошта: рахунки, бронювання, розсилки, акції та сповіщення про обліковий запис |

До хаму входить звичайна ділова та магазинна пошта (рахунки, сповіщення про замовлення й обліковий запис, розсилки, акції), тож така пошта сама по собі не вважається спамом.

Вона навчалася на 77 564 листах зі спамом і 112 586 листах ham. Скрипт відкладає кожен десятий лист, навчається на решті й вимірює лише класифікатор, без інших перевірок:

| Відкладений тест |  Листи | Точність | Повнота | Хибні спрацювання | Невизначені |
| ---------------- | -----: | -------: | ------: | ----------------: | ----------: |
| Англійська       |   8515 |  100,0 % |  96,4 % |             0,0 % |       2,6 % |
| Російська        |   1680 |  100,0 % |  97,4 % |             0,0 % |       2,3 % |
| Італійська       |   1392 |   98,6 % |  81,0 % |             1,2 % |      12,5 % |
| Німецька         |   1314 |   97,8 % |  72,5 % |             2,1 % |      22,6 % |
| Іспанська        |   2088 |   98,5 % |  56,1 % |             0,4 % |      15,7 % |
| Enron-Spam       |   2888 |  100,0 % |  92,4 % |             0,0 % |       4,4 % |
| all-scam-spam    |   4236 |  100,0 % |  89,3 % |             0,0 % |      11,6 % |
| Усі              | 18 967 |   99,6 % |  77,2 % |             0,2 % |      15,8 % |

Спамом тут вважається ймовірність за класифікатором 99 % або більше — точка, у якій сам класифікатор досягає порогу спаму. Під час перевірки спам, щодо якого він менш упевнений, усе одно отримує бали, а інші перевірки додають свої.

Результати для німецької, іспанської та італійської отримано із синтетичних наборів даних, які містять майже однакові листи з мітками і спаму, і ham: частина цієї помилки — у мітках, а не в моделі. Найкращий спосіб виправити це — пошта вашими власними мовами. Числа для кожної мови й набору даних містяться в `metadata.metrics` моделі.

### Більше мов

`npm run model:train -- --with multilingual-sms` додає [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection, машинно перекладену 21 мовою. Її не включено до вбудованої моделі, бо в її картці вказано ліцензію GPL; перевірте, чи це підходить для того, як ви поширюєте модель. Після навчання з нею результати на відкладених даних для мов, які вбудована модель ледве знає, були такими:

| Мова       | Листи | Точність | Повнота | Хибні спрацювання |
| ---------- | ----: | -------: | ------: | ----------------: |
| Китайська  |   432 |  100,0 % |  86,1 % |             0,0 % |
| Арабська   |   432 |  100,0 % |  83,1 % |             0,0 % |
| Корейська  |   412 |  100,0 % |  78,3 % |             0,0 % |
| Японська   |   486 |   96,1 % |  87,5 % |             0,5 % |
| Гінді      |   494 |  100,0 % |  76,2 % |             0,0 % |
| Французька |   511 |   98,7 % |  88,6 % |             0,6 % |
| Турецька   |   222 |  100,0 % |  70,4 % |             0,0 % |

### Перенавчання

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Файл моделі

Модель — це файл JSON: кількість вивчених листів зі спамом і з ham, а для кожної хешованої ознаки — скільки листів зі спамом і з ham її містили, у відсортованому вигляді й закодовано в base64. Він не містить ні слів, ні тексту листів. `--max-features` залишає лише найчастіші ознаки, а `--min-count` відкидає рідкісні, обмінюючи точність на розмір; вбудована модель зберігає 400 000 ознак приблизно в 6 МБ.

Моделі зі Spam Scanner 6 і раніших версій завантажити не можна: вони хешували інші ознаки. Навчіть нову на тій самій пошті.
