<!-- source: 7cc30ff4ad91 -->

# Treinamento

O modelo incluído funciona sem configuração. Um modelo treinado com os seus próprios e-mails funciona melhor, porque aprende como é o seu ham: as suas newsletters, a escrita dos seus colegas, os idiomas que você recebe.


## Treinar um modelo

Aponte o `train` para pastas de spam e de ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

As fontes podem ser:

* arquivos **mbox**, também compactados com gzip (`.mbox.gz`),
* um **Maildir** (as pastas `cur` e `new` são lidas, e a `tmp` é ignorada),
* uma **pasta** de arquivos `.eml`, lida de forma recursiva,
* um **conjunto de dados**: um arquivo CSV ou JSON Lines com uma coluna de texto e uma coluna de rótulo (`--dataset`). Colunas chamadas `text`, `message`, `body`, `email` ou `content`, e `label`, `category`, `class`, `spam` ou `is_spam`, são encontradas automaticamente; caso contrário, use `--text-column` e `--label-column`. Rótulos como `spam`, `1`, `phishing` e `ham`, `0`, `not_spam`, `legitimate` são entendidos.

Mensagens duplicadas são contadas uma vez. Para partir do modelo incluído em vez de começar do zero, adicione `--merge`.

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
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
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

| Conjunto de dados                                                                                                                                                                                                                                                                                                          | Licença                    | Conteúdo                          |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                 | Mensagens e e-mails em 43 idiomas |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Corpus público de pesquisa | O corpus Enron-Spam               |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                    | Mensagens do Telegram em russo    |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                        | Mensagens sintéticas              |

Ele aprendeu com 62.480 mensagens de spam e 76.489 de ham. O script separa uma em cada dez mensagens, treina com o restante e mede apenas o classificador, sem as outras verificações:

| Teste com dados separados | Mensagens | Precisão | Revocação | Falsos positivos | Incertas |
| ------------------------- | --------: | -------: | --------: | ---------------: | -------: |
| Inglês                    |     6.564 |   100,0% |     97,0% |             0,0% |     2,4% |
| Russo                     |     1.682 |   100,0% |     97,4% |             0,0% |     2,2% |
| Italiano                  |     1.389 |    98,1% |     85,3% |             1,8% |    10,9% |
| Alemão                    |     1.309 |    97,7% |     76,1% |             2,2% |    20,7% |
| Espanhol                  |     1.281 |    97,5% |     82,5% |             2,6% |    16,8% |
| Enron-Spam                |     2.888 |   100,0% |     93,1% |             0,0% |     4,5% |
| all-scam-spam             |     4.236 |   100,0% |     88,8% |             0,0% |    11,2% |
| Todos                     |    13.840 |    99,2% |     85,1% |             0,5% |    12,4% |

Aqui, spam significa uma probabilidade do classificador de 99% ou mais, o ponto em que o classificador sozinho atinge o limite de spam. Em uma análise, o spam sobre o qual ele tem menos certeza ainda recebe pontos, e as outras verificações somam os delas.

Os resultados em alemão, espanhol e italiano vêm de conjuntos de dados sintéticos, que contêm mensagens quase idênticas rotuladas tanto como spam quanto como ham: parte desse erro está nos rótulos, e não no modelo. E-mails nos seus próprios idiomas são a melhor correção. Os números, com todos os idiomas e conjuntos de dados, estão em `metadata.metrics` do modelo.

### Mais idiomas

O `npm run model:train -- --with multilingual-sms` adiciona a [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): a SMS Spam Collection traduzida por máquina para 21 idiomas. Ela fica fora do modelo incluído porque a sua ficha indica uma licença GPL; confira se isso é adequado à forma como você compartilha o modelo. Com ela no treinamento, os resultados com dados separados para idiomas que o modelo incluído mal conhece foram:

| Idioma  | Mensagens | Precisão | Revocação | Falsos positivos |
| ------- | --------: | -------: | --------: | ---------------: |
| Chinês  |       430 |   100,0% |     82,3% |             0,0% |
| Árabe   |       430 |   100,0% |     84,6% |             0,0% |
| Coreano |       412 |   100,0% |     80,4% |             0,0% |
| Japonês |       486 |    96,0% |     85,7% |             0,5% |
| Hindi   |       412 |   100,0% |     63,9% |             0,0% |
| Francês |       480 |    98,6% |     94,2% |             0,6% |
| Turco   |       220 |   100,0% |     73,1% |             0,0% |

### Treinar de novo

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## O arquivo do modelo

Um modelo é um arquivo JSON: o número de mensagens de spam e de ham aprendidas e, para cada característica com hash, quantas mensagens de spam e de ham a continham, ordenadas e codificadas em base64. Ele não guarda palavras nem texto de mensagens. O `--max-features` mantém só as características mais frequentes e o `--min-count` descarta as raras, trocando precisão por tamanho; o modelo incluído mantém 400.000 características em cerca de 6 MB.

Os modelos do Spam Scanner 6 e anteriores não podem ser carregados: eles usavam hash em características diferentes. Treine um novo a partir dos mesmos e-mails.
