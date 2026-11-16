<!-- source: c4f8c2c7aa5a -->

# Trenowanie

Dołączony model działa od razu. Model wytrenowany na twojej własnej poczcie działa lepiej, bo uczy się, jak wygląda twój ham: twoje newslettery, styl pisania twoich współpracowników, języki, w których dostajesz pocztę.


## Trenowanie modelu

Wskaż poleceniu `train` foldery ze spamem i hamem:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Źródłami mogą być:

* pliki **mbox**, także skompresowane gzip (`.mbox.gz`; inne pliki `.gz` są pomijane),
* katalog **Maildir** (czytane są jego foldery `cur` i `new`, `tmp` jest pomijany),
* **folder** z plikami `.eml`, czytany rekurencyjnie,
* **zbiór danych**: plik CSV lub JSON Lines z kolumną tekstu i kolumną etykiety (`--dataset`). Kolumny lub pola JSON o nazwach `text`, `message`, `body`, `email text`, `email`, `content`, `sms` lub `v2` oraz `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` lub `labels`, bez względu na wielkość liter, są znajdowane automatycznie (w JSON Lines `label_text` przed `label`); w przeciwnym razie użyj `--text-column` i `--label-column`. Wiersz JSON, który nie jest obiektem, jest pomijany. Rozpoznawane są etykiety takie jak `spam`, `1`, `phishing` oraz `ham`, `0`, `not_spam`, `legitimate`.

Powtarzające się wiadomości są liczone raz. Wiadomość obecna zarówno w źródłach spamu, jak i ham jest zachowywana jako spam, bo źródła spamu są czytane jako pierwsze. Aby budować na dołączonym modelu zamiast zaczynać od pustego, dodaj `--merge`.

Użycie modelu:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Ile poczty wystarczy: kilkaset wiadomości każdego rodzaju daje użyteczny model, kilka tysięcy dobry. Utrzymuj mniej więcej równowagę między nimi i trzymaj w hamie pocztę, której nie chcesz filtrować (resety haseł, faktury od własnych dostawców).


## Pomiar

Odłóż część poczty z treningu i mierz na niej:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Dołączony model na wiadomościach SMS w 21 językach, których nigdy nie widział, w większości w językach, które zna słabo:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Precyzja (precision) mówi, jaka część tego, co model nazywa spamem, jest spamem; czułość (recall), jaką część spamu wyłapuje. Wiadomości niepewne liczą się tu jako pominięty spam, choć podczas skanowania inne kontrole i model językowy wciąż mogą je wyłapać. Najważniejszą liczbą są fałszywe alarmy: ham oznaczony jako spam. W powyższym przebiegu model jest niepewny co do większości tych wiadomości, a nie myli się co do nich, i tak ma się zachowywać w językach, w których ma mało poczty.

`--json` podaje te same liczby dla skryptów.


## Nauka ze zgłoszeń

Gdy użytkownicy przenoszą pocztę do folderu Junk lub z niego, ucz model po jednej wiadomości:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Pierwsze `learn` tworzy plik z dołączonego modelu. Przez HTTP to samo robią `POST /learn/spam` i `/learn/ham` w [HTTP API](http-api.md), a `spamc -L spam` działa z [serwerem spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) uruchomionym z `--allow-tell`. [IMAPSieve w Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) może wywołać jedno lub drugie, gdy wiadomość zostanie przeniesiona.

Z Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Wiadomość zgłoszoną jako źle sklasyfikowana, jeśli była wcześniej wyuczona, należy najpierw oduczyć z błędnej klasy, a dopiero potem wyuczyć w poprawnej.


## Dołączony model

`model/classifier.json` jest budowany przez `npm run model:train` z tych publicznych zbiorów danych na Hugging Face, wszystkich na otwartych licencjach:

| Zbiór danych                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Licencja                   | Zawartość                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ----------------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | Wiadomości i e-maile w 43 językach                                                  |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Publiczny korpus badawczy  | Korpus Enron-Spam                                                                   |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | Rosyjskie wiadomości z Telegrama                                                    |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Wiadomości syntetyczne                                                              |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Listy dyskusyjne, newslettery, spam, phishing i wiadomości z oszustwami             |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Wiadomości w 14 językach Indii                                                      |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | Indonezyjskie e-maile według kategorii                                              |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | Poczta jednej firmy po hiszpańsku                                                   |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | Zwykła poczta: rachunki, rezerwacje, newslettery, promocje i powiadomienia o koncie |

Ham obejmuje zwykłą pocztę firmową i sklepową (faktury, powiadomienia o zamówieniach i koncie, newslettery, promocje), więc taka poczta sama w sobie nie jest odczytywana jako spam.

Uczył się na 77 564 wiadomościach spamu i 112 586 wiadomościach hamu. Skrypt odkłada co dziesiątą wiadomość, trenuje na pozostałych i mierzy sam klasyfikator, bez innych kontroli:

| Test na odłożonych | Wiadomości | Precyzja | Czułość | Fałszywe alarmy | Niepewne |
| ------------------ | ---------: | -------: | ------: | --------------: | -------: |
| Angielski          |       8515 |   100,0% |   96,4% |            0,0% |     2,6% |
| Rosyjski           |       1680 |   100,0% |   97,4% |            0,0% |     2,3% |
| Włoski             |       1392 |    98,6% |   81,0% |            1,2% |    12,5% |
| Niemiecki          |       1314 |    97,8% |   72,5% |            2,1% |    22,6% |
| Hiszpański         |       2088 |    98,5% |   56,1% |            0,4% |    15,7% |
| Enron-Spam         |       2888 |   100,0% |   92,4% |            0,0% |     4,4% |
| all-scam-spam      |       4236 |   100,0% |   89,3% |            0,0% |    11,6% |
| Wszystkie          |     18 967 |    99,6% |   77,2% |            0,2% |    15,8% |

Spam oznacza tu prawdopodobieństwo według klasyfikatora wynoszące 99% lub więcej, czyli punkt, w którym sam klasyfikator osiąga próg spamu. Podczas skanowania spam, co do którego jest mniej pewny, nadal dostaje punkty, a inne kontrole dodają swoje.

Wyniki dla niemieckiego, hiszpańskiego i włoskiego pochodzą z syntetycznych zbiorów danych, które zawierają niemal identyczne wiadomości oznaczone zarówno jako spam, jak i ham: część tego błędu tkwi w etykietach, a nie w modelu. Najlepszym rozwiązaniem jest poczta w twoich własnych językach. Liczby dla każdego języka i zbioru danych są w `metadata.metrics` modelu.

### Więcej języków

`npm run model:train -- --with multilingual-sms` dodaje [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection przetłumaczone maszynowo na 21 języków. Nie ma go w dołączonym modelu, bo jego karta podaje licencję GPL; sprawdź, czy pasuje do tego, jak udostępniasz model. Po trenowaniu z nim wyniki na odłożonych wiadomościach dla języków, które dołączony model zna słabo, były następujące:

| Język     | Wiadomości | Precyzja | Czułość | Fałszywe alarmy |
| --------- | ---------: | -------: | ------: | --------------: |
| Chiński   |        432 |   100,0% |   86,1% |            0,0% |
| Arabski   |        432 |   100,0% |   83,1% |            0,0% |
| Koreański |        412 |   100,0% |   78,3% |            0,0% |
| Japoński  |        486 |    96,1% |   87,5% |            0,5% |
| Hindi     |        494 |   100,0% |   76,2% |            0,0% |
| Francuski |        511 |    98,7% |   88,6% |            0,6% |
| Turecki   |        222 |   100,0% |   70,4% |            0,0% |

### Ponowne trenowanie

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Plik modelu

Model to plik JSON: liczba wyuczonych wiadomości spamu i hamu oraz, dla każdej haszowanej cechy, w ilu wiadomościach spamu i hamu wystąpiła, posortowane i zakodowane w base64. Nie zawiera słów ani tekstu wiadomości. `--max-features` zachowuje tylko najczęstsze cechy, a `--min-count` odrzuca rzadkie, co zamienia dokładność na rozmiar; dołączony model zachowuje 400 000 cech w około 6 MB.

Modeli ze Spam Scanner 6 i starszych nie da się wczytać: haszowały inne cechy. Wytrenuj nowy na tej samej poczcie.
