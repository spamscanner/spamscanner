<!-- source: 6f344039ec5d -->

# Treinamento

O modelo incluído funciona sem configuração. Um modelo treinado com os seus próprios e-mails funciona melhor, porque aprende como é o seu ham: as suas newsletters, a escrita dos seus colegas, os idiomas que você recebe.


## Treinar um modelo

Aponte o `train` para pastas de spam e de ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

As fontes podem ser:

* arquivos **mbox**, também compactados com gzip (`.mbox.gz`; outros arquivos `.gz` são ignorados),
* um **Maildir** (as pastas `cur` e `new` são lidas, e a `tmp` é ignorada),
* uma **pasta** de arquivos `.eml`, lida de forma recursiva,
* um **conjunto de dados**: um arquivo CSV ou JSON Lines com uma coluna de texto e uma coluna de rótulo (`--dataset`). Colunas, ou campos JSON, chamados `text`, `message`, `body`, `email text`, `email`, `content`, `sms` ou `v2`, e `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` ou `labels`, em maiúsculas ou minúsculas, são encontrados automaticamente (em JSON Lines, `label_text` antes de `label`); caso contrário, use `--text-column` e `--label-column`. Uma linha JSON que não é um objeto é ignorada. Rótulos como `spam`, `1`, `phishing` e `ham`, `0`, `not_spam`, `legitimate` são entendidos.

Mensagens duplicadas são contadas uma vez. Uma mensagem presente tanto nas fontes de spam quanto nas de ham é mantida como spam, já que as fontes de spam são lidas primeiro. Para partir do modelo incluído em vez de começar do zero, adicione `--merge`.

Use o modelo:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Quanto e-mail basta: algumas centenas de mensagens de cada tipo dão um modelo útil, e alguns milhares, um modelo bom. Mantenha os dois tipos mais ou menos equilibrados e mantenha no ham os e-mails que você não quer filtrar (redefinições de senha, faturas dos seus próprios fornecedores).


## Medir o modelo

Deixe alguns e-mails fora do treinamento e meça com eles:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

O modelo incluído com mensagens SMS em 21 idiomas que ele nunca viu, a maioria em idiomas que ele mal conhece:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

A precisão é quanto do que ele chama de spam é spam; a revocação, quanto do spam ele pega. Aqui, as mensagens incertas contam como spam não detectado, embora, em uma análise, as outras verificações e o modelo de linguagem ainda possam pegá-las. O número a acompanhar é o de falsos positivos: ham marcado como spam. Na execução acima, o modelo fica incerto sobre a maioria dessas mensagens em vez de errar sobre elas, que é o comportamento esperado para idiomas em que ele tem poucos e-mails.

O `--json` fornece os mesmos números para scripts.


## Aprender com denúncias

Quando os usuários movem e-mails para dentro ou para fora de uma pasta Junk, ensine o modelo uma mensagem por vez:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

O primeiro `learn` cria o arquivo a partir do modelo incluído. Por HTTP, `POST /learn/spam` e `/learn/ham` na [API HTTP](http-api.md) fazem o mesmo, e o `spamc -L spam` funciona com o [servidor spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) usando `--allow-tell`. O [IMAPSieve do Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) pode chamar qualquer um dos dois quando uma mensagem é movida.

No Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Uma mensagem denunciada como classificada errado deve ser desaprendida da classe errada antes de ser aprendida na certa, se já tiver sido aprendida antes.


## O modelo incluído

O `model/classifier.json` é gerado pelo `npm run model:train` a partir destes conjuntos de dados públicos no Hugging Face, todos sob licenças abertas:

| Conjunto de dados                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Licença                    | Conteúdo                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | Mensagens e e-mails em 43 idiomas                                         |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Corpus público de pesquisa | O corpus Enron-Spam                                                       |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | Mensagens do Telegram em russo                                            |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Mensagens sintéticas                                                      |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Listas de discussão, newsletters, spam, phishing e e-mails de fraude      |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Mensagens em 14 idiomas da Índia                                          |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | E-mails indonésios por categoria                                          |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | O correio de uma empresa em espanhol                                      |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | Correio comum: contas, reservas, newsletters, promoções e avisos de conta |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | O que as pessoas pedem a um assistente, em 20 idiomas                     |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                  | O correio de uma empresa fictícia em francês                              |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Com este projeto           | Correio do dia a dia e fraudes em 23 idiomas, escritos para este projeto  |

O ham inclui o correio comum de empresas e lojas (faturas, avisos de pedidos e de conta, newsletters, promoções), de modo que esse correio, por si só, não é lido como spam.

As mensagens de devolução (bounces) dos conjuntos de dados ficam de fora: estão apenas entre o spam, o que ensinaria ao classificador que toda devolução é spam.

As três últimas linhas são texto comum nos idiomas dos quais os outros conjuntos de dados têm sobretudo spam (francês, português, holandês, as línguas nórdicas, polonês, turco, árabe, japonês, coreano, chinês e outros), onde cada palavra comum seria lida como spam. De 10.000 textos comuns em 20 idiomas com os quais o modelo não foi treinado, 1,4% recebem uma probabilidade de 80% ou mais (4,8% sem essas linhas) e 0,1% uma de 99% ou mais. Esse texto não é correio real, e as fraudes escritas para cada idioma são poucas: o classificador fica mais seguro do correio comum nesses idiomas e apanha pouco mais do spam deles.

Ele aprendeu com 81.254 mensagens de spam e 133.317 de ham. O script separa uma em cada dez mensagens, treina com o restante e mede apenas o classificador, sem as outras verificações:

| Teste com dados separados | Mensagens | Precisão | Revocação | Falsos positivos | Incertas |
| ------------------------- | --------: | -------: | --------: | ---------------: | -------: |
| Inglês                    |     8.481 |   100,0% |     96,3% |             0,0% |     2,6% |
| Russo                     |     1.680 |   100,0% |     97,4% |             0,0% |     2,2% |
| Italiano                  |     1.392 |    99,0% |     81,0% |             0,9% |    12,6% |
| Alemão                    |     1.314 |    97,9% |     71,4% |             1,9% |    22,3% |
| Espanhol                  |     2.088 |    98,7% |     53,3% |             0,4% |    16,2% |
| Enron-Spam                |     2.870 |   100,0% |     95,2% |             0,0% |     2,6% |
| all-scam-spam             |     4.222 |    99,9% |     92,2% |             0,0% |     9,1% |
| Todos                     |    21.329 |    99,6% |     76,6% |             0,2% |    14,2% |

Aqui, spam significa uma probabilidade do classificador de 99% ou mais, o ponto em que o classificador sozinho atinge o limite de spam. Em uma análise, o spam sobre o qual ele tem menos certeza ainda recebe pontos, e as outras verificações somam os delas.

Os resultados em alemão, espanhol e italiano vêm de conjuntos de dados sintéticos, que contêm mensagens quase idênticas rotuladas tanto como spam quanto como ham: parte desse erro está nos rótulos, e não no modelo. E-mails nos seus próprios idiomas são a melhor correção. Os números, com todos os idiomas e conjuntos de dados, estão em `metadata.metrics` do modelo.

### Mais idiomas

O `npm run model:train -- --with multilingual-sms` adiciona a [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): a SMS Spam Collection traduzida por máquina para 21 idiomas. Ela fica fora do modelo incluído porque a sua ficha indica uma licença GPL; confira se isso é adequado à forma como você compartilha o modelo. Com ela no treinamento, os resultados com dados separados para idiomas que o modelo incluído mal conhece foram:

| Idioma  | Mensagens | Precisão | Revocação | Falsos positivos |
| ------- | --------: | -------: | --------: | ---------------: |
| Chinês  |       432 |   100,0% |     86,1% |             0,0% |
| Árabe   |       432 |   100,0% |     83,1% |             0,0% |
| Coreano |       412 |   100,0% |     78,3% |             0,0% |
| Japonês |       486 |    96,1% |     87,5% |             0,5% |
| Hindi   |       494 |   100,0% |     76,2% |             0,0% |
| Francês |       511 |    98,7% |     88,6% |             0,6% |
| Turco   |       222 |   100,0% |     70,4% |             0,0% |

### Treinar de novo

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## O arquivo do modelo

Um modelo é um arquivo JSON: o número de mensagens de spam e de ham aprendidas e, para cada característica com hash, quantas mensagens de spam e de ham a continham, ordenadas e codificadas em base64. Ele não guarda palavras nem texto de mensagens. O `--max-features` mantém só as características mais frequentes e o `--min-count` descarta as raras, trocando precisão por tamanho; o modelo incluído mantém 400.000 características em cerca de 6 MB.

Os modelos do Spam Scanner 6 e anteriores não podem ser carregados: eles usavam hash em características diferentes. Treine um novo a partir dos mesmos e-mails.
