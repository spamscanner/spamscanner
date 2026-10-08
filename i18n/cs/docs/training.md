<!-- source: 7cc30ff4ad91 -->

# Trénování

Přibalený model funguje hned po instalaci. Model natrénovaný na vaší vlastní poště funguje lépe, protože se naučí, jak vypadá váš ham: vaše newslettery, styl psaní vašich kolegů, jazyky, ve kterých poštu dostáváte.


## Natrénování modelu

Nasměrujte `train` na složky se spamem a hamem:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Zdrojem mohou být:

* soubory **mbox**, i komprimované gzipem (`.mbox.gz`),
* **Maildir** (čtou se jeho složky `cur` a `new`, `tmp` se přeskakuje),
* **složka** souborů `.eml`, čtená rekurzivně,
* **datová sada**: soubor CSV nebo JSON Lines se sloupcem textu a sloupcem štítku (`--dataset`). Sloupce pojmenované `text`, `message`, `body`, `email` nebo `content` a `label`, `category`, `class`, `spam` nebo `is_spam` se najdou samy; jinak použijte `--text-column` a `--label-column`. Rozumí štítkům jako `spam`, `1`, `phishing` a `ham`, `0`, `not_spam`, `legitimate`.

Duplicitní zprávy se počítají jednou. Chcete-li stavět na přibaleném modelu místo začátku od nuly, přidejte `--merge`.

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
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
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

| Datová sada                                                                                                                                                                                                                                                                                                                | Licence                 | Obsah                           |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0              | Zprávy a e-maily ve 43 jazycích |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Veřejný výzkumný korpus | Korpus Enron-Spam               |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                 | Ruské zprávy z Telegramu        |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                     | Syntetické zprávy               |

Učil se z 62 480 spamových a 76 489 hamových zpráv. Skript odloží každou desátou zprávu, natrénuje model na zbytku a změří samotný klasifikátor bez ostatních kontrol:

| Odložený test | Zprávy | Přesnost | Úplnost | Falešně pozitivní | Nejisté |
| ------------- | -----: | -------: | ------: | ----------------: | ------: |
| Angličtina    |  6 564 |  100,0 % |  97,0 % |             0,0 % |   2,4 % |
| Ruština       |  1 682 |  100,0 % |  97,4 % |             0,0 % |   2,2 % |
| Italština     |  1 389 |   98,1 % |  85,3 % |             1,8 % |  10,9 % |
| Němčina       |  1 309 |   97,7 % |  76,1 % |             2,2 % |  20,7 % |
| Španělština   |  1 281 |   97,5 % |  82,5 % |             2,6 % |  16,8 % |
| Enron-Spam    |  2 888 |  100,0 % |  93,1 % |             0,0 % |   4,5 % |
| all-scam-spam |  4 236 |  100,0 % |  88,8 % |             0,0 % |  11,2 % |
| Vše           | 13 840 |   99,2 % |  85,1 % |             0,5 % |  12,4 % |

Spam zde znamená pravděpodobnost podle klasifikátoru 99 % nebo více, tedy bod, ve kterém samotný klasifikátor dosáhne prahu spamu. Při kontrole dostane body i spam, kterým si je méně jistý, a ostatní kontroly přidají své.

Výsledky pro němčinu, španělštinu a italštinu pocházejí ze syntetických datových sad, které obsahují téměř totožné zprávy označené jako spam i jako ham: část této chyby je ve štítcích, ne v modelu. Nejlepší nápravou je pošta ve vašich vlastních jazycích. Čísla pro všechny jazyky a datové sady jsou v `metadata.metrics` modelu.

### Další jazyky

`npm run model:train -- --with multilingual-sms` přidá [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): SMS Spam Collection strojově přeloženou do 21 jazyků. V přibaleném modelu chybí, protože její karta uvádí licenci GPL; ověřte, že vyhovuje způsobu, jakým model sdílíte. Po natrénování s ní byly odložené výsledky pro jazyky, které přibalený model skoro nezná, tyto:

| Jazyk         | Zprávy | Přesnost | Úplnost | Falešně pozitivní |
| ------------- | -----: | -------: | ------: | ----------------: |
| Čínština      |    430 |  100,0 % |  82,3 % |             0,0 % |
| Arabština     |    430 |  100,0 % |  84,6 % |             0,0 % |
| Korejština    |    412 |  100,0 % |  80,4 % |             0,0 % |
| Japonština    |    486 |   96,0 % |  85,7 % |             0,5 % |
| Hindština     |    412 |  100,0 % |  63,9 % |             0,0 % |
| Francouzština |    480 |   98,6 % |  94,2 % |             0,6 % |
| Turečtina     |    220 |  100,0 % |  73,1 % |             0,0 % |

### Přetrénování

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Soubor modelu

Model je soubor JSON: počet naučených spamových a hamových zpráv a pro každý zahešovaný příznak počet spamových a hamových zpráv, které ho obsahovaly, seřazené a zakódované v base64. Neobsahuje žádná slova ani text zpráv. `--max-features` ponechá jen nejčastější příznaky a `--min-count` vypustí vzácné, čímž vyměníte přesnost za velikost; přibalený model uchovává 400 000 příznaků v zhruba 6 MB.

Modely ze Spam Scanneru 6 a starších nelze načíst: hešovaly jiné příznaky. Natrénujte nový ze stejné pošty.
