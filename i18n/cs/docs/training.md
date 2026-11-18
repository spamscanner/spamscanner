<!-- source: 6f344039ec5d -->

# Trénování

Přibalený model funguje hned po instalaci. Model natrénovaný na vaší vlastní poště funguje lépe, protože se naučí, jak vypadá váš ham: vaše newslettery, styl psaní vašich kolegů, jazyky, ve kterých poštu dostáváte.


## Natrénování modelu

Nasměrujte `train` na složky se spamem a hamem:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Zdrojem mohou být:

* soubory **mbox**, i komprimované gzipem (`.mbox.gz`; jiné soubory `.gz` se přeskočí),
* **Maildir** (čtou se jeho složky `cur` a `new`, `tmp` se přeskakuje),
* **složka** souborů `.eml`, čtená rekurzivně,
* **datová sada**: soubor CSV nebo JSON Lines se sloupcem textu a sloupcem štítku (`--dataset`). Sloupce nebo pole JSON pojmenované `text`, `message`, `body`, `email text`, `email`, `content`, `sms` nebo `v2` a `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` nebo `labels`, bez ohledu na velikost písmen, se najdou samy (v JSON Lines `label_text` před `label`); jinak použijte `--text-column` a `--label-column`. Řádek JSON, který není objektem, se přeskočí. Rozumí štítkům jako `spam`, `1`, `phishing` a `ham`, `0`, `not_spam`, `legitimate`.

Duplicitní zprávy se počítají jednou. Zpráva, která je ve zdrojích spamu i hamu, se ponechá jako spam, protože zdroje spamu se čtou první. Chcete-li stavět na přibaleném modelu místo začátku od nuly, přidejte `--merge`.

Použití modelu:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Kolik pošty stačí: několik set zpráv každého druhu dá použitelný model, několik tisíc dobrý. Udržujte oba druhy přibližně vyvážené a poštu, kterou nechcete filtrovat (obnovení hesla, faktury od vašich vlastních dodavatelů), mějte v hamu.


## Změření

Část pošty vynechte z trénování a měřte na ní:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Přibalený model na zprávách SMS ve 21 jazycích, které nikdy neviděl, většinou v jazycích, které skoro nezná:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Přesnost (precision) udává, jaká část toho, co označí za spam, je skutečně spam; úplnost (recall), jakou část spamu zachytí. Nejisté zprávy se zde počítají jako nezachycený spam, i když při kontrole je ještě mohou zachytit ostatní kontroly a jazykový model. Sledovat je třeba falešně pozitivní výsledky: ham označený jako spam. Ve výše uvedeném běhu si model u většiny těchto zpráv není jistý, místo aby se v nich mýlil, což je zamýšlené chování u jazyků, ve kterých má málo pošty.

`--json` dává stejná čísla pro skripty.


## Učení z hlášení

Když uživatelé přesouvají poštu do složky Junk nebo z ní, učte model po jedné zprávě:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

První `learn` vytvoří soubor z přibaleného modelu. Přes HTTP dělají totéž `POST /learn/spam` a `/learn/ham` v [HTTP API](http-api.md) a `spamc -L spam` funguje proti [serveru spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) s `--allow-tell`. [IMAPSieve v Dovecotu](mail-servers.md#dovecot-junk-folder-and-learning) může při přesunu zprávy zavolat kterýkoli z nich.

Z Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Zprávu nahlášenou jako chybně zařazenou je třeba, pokud už byla naučena, nejprve odnaučit ze špatné třídy a teprve pak naučit ve správné.


## Přibalený model

`model/classifier.json` sestavuje `npm run model:train` z těchto veřejných datových sad na Hugging Face, všech pod otevřenými licencemi:

| Datová sada                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Licence                    | Obsah                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | Zprávy a e-maily ve 43 jazycích                                           |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Veřejný výzkumný korpus    | Korpus Enron-Spam                                                         |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | Ruské zprávy z Telegramu                                                  |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Syntetické zprávy                                                         |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | E-mailové konference, zpravodaje, spam, phishing a podvodné e-maily       |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Zprávy ve 14 jazycích Indie                                               |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | Indonéské e-maily podle kategorie                                         |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | Pošta jedné firmy ve španělštině                                          |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | Běžná pošta: účty, rezervace, zpravodaje, akční nabídky a oznámení o účtu |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Co lidé žádají po hlasovém asistentovi, ve 20 jazycích                    |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                  | Pošta smyšlené firmy ve francouzštině                                     |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | S tímto projektem          | Každodenní pošta a podvody ve 23 jazycích, napsané pro tento projekt      |

Ham zahrnuje běžnou firemní a obchodní poštu (faktury, oznámení o objednávkách a účtech, zpravodaje, akční nabídky), takže taková pošta sama o sobě nevypadá jako spam.

Nedoručenky v datových sadách se vynechávají: jsou jen mezi spamem, což by klasifikátor naučilo, že každá nedoručenka je spam.

Poslední tři řádky jsou běžný text v jazycích, z nichž ostatní datové sady obsahují hlavně spam (francouzština, portugalština, nizozemština, severské jazyky, polština, turečtina, arabština, japonština, korejština, čínština a další) a v nichž by se jinak každé běžné slovo četlo jako spam. Z 10 000 běžných textů ve 20 jazycích, na kterých se model neučil, dostane 1,4 % pravděpodobnost 80 % nebo vyšší (4,8 % bez těchto řádků) a 0,1 % pravděpodobnost 99 % nebo vyšší. Tento text není skutečná pošta a podvodů napsaných pro jeden jazyk je málo: klasifikátor si je v těchto jazycích jistější běžnou poštou a jejich spamu zachytí jen o málo víc.

Učil se z 81 254 spamových a 133 317 hamových zpráv. Skript odloží každou desátou zprávu, natrénuje model na zbytku a změří samotný klasifikátor bez ostatních kontrol:

| Odložený test | Zprávy | Přesnost | Úplnost | Falešně pozitivní | Nejisté |
| ------------- | -----: | -------: | ------: | ----------------: | ------: |
| Angličtina    |  8 481 |  100,0 % |  96,3 % |             0,0 % |   2,6 % |
| Ruština       |  1 680 |  100,0 % |  97,4 % |             0,0 % |   2,2 % |
| Italština     |  1 392 |   99,0 % |  81,0 % |             0,9 % |  12,6 % |
| Němčina       |  1 314 |   97,9 % |  71,4 % |             1,9 % |  22,3 % |
| Španělština   |  2 088 |   98,7 % |  53,3 % |             0,4 % |  16,2 % |
| Enron-Spam    |  2 870 |  100,0 % |  95,2 % |             0,0 % |   2,6 % |
| all-scam-spam |  4 222 |   99,9 % |  92,2 % |             0,0 % |   9,1 % |
| Vše           | 21 329 |   99,6 % |  76,6 % |             0,2 % |  14,2 % |

Spam zde znamená pravděpodobnost podle klasifikátoru 99 % nebo více, tedy bod, ve kterém samotný klasifikátor dosáhne prahu spamu. Při kontrole dostane body i spam, kterým si je méně jistý, a ostatní kontroly přidají své.

Výsledky pro němčinu, španělštinu a italštinu pocházejí ze syntetických datových sad, které obsahují téměř totožné zprávy označené jako spam i jako ham: část této chyby je ve štítcích, ne v modelu. Nejlepší nápravou je pošta ve vašich vlastních jazycích. Čísla pro všechny jazyky a datové sady jsou v `metadata.metrics` modelu.

### Další jazyky

`npm run model:train -- --with multilingual-sms` přidá [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection strojově přeloženou do 21 jazyků. V přibaleném modelu chybí, protože její karta uvádí licenci GPL; ověřte, že vyhovuje způsobu, jakým model sdílíte. Po natrénování s ní byly odložené výsledky pro jazyky, které přibalený model skoro nezná, tyto:

| Jazyk         | Zprávy | Přesnost | Úplnost | Falešně pozitivní |
| ------------- | -----: | -------: | ------: | ----------------: |
| Čínština      |    432 |  100,0 % |  86,1 % |             0,0 % |
| Arabština     |    432 |  100,0 % |  83,1 % |             0,0 % |
| Korejština    |    412 |  100,0 % |  78,3 % |             0,0 % |
| Japonština    |    486 |   96,1 % |  87,5 % |             0,5 % |
| Hindština     |    494 |  100,0 % |  76,2 % |             0,0 % |
| Francouzština |    511 |   98,7 % |  88,6 % |             0,6 % |
| Turečtina     |    222 |  100,0 % |  70,4 % |             0,0 % |

### Přetrénování

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Soubor modelu

Model je soubor JSON: počet naučených spamových a hamových zpráv a pro každý zahešovaný příznak počet spamových a hamových zpráv, které ho obsahovaly, seřazené a zakódované v base64. Neobsahuje žádná slova ani text zpráv. `--max-features` ponechá jen nejčastější příznaky a `--min-count` vypustí vzácné, čímž vyměníte přesnost za velikost; přibalený model uchovává 400 000 příznaků v zhruba 6 MB.

Modely ze Spam Scanneru 6 a starších nelze načíst: hešovaly jiné příznaky. Natrénujte nový ze stejné pošty.
