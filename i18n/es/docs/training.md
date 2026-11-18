<!-- source: 6f344039ec5d -->

# Entrenamiento

El modelo incluido funciona desde el primer momento. Un modelo entrenado con tu propio correo funciona mejor, porque aprende cómo es tu ham: tus boletines, la forma de escribir de tus colegas, los idiomas que recibes.


## Entrenar un modelo

Indica a `train` las carpetas de spam y de ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Las fuentes pueden ser:

* archivos **mbox**, también comprimidos con gzip (`.mbox.gz`; los demás archivos `.gz` se omiten),
* un **Maildir** (se leen sus carpetas `cur` y `new`, y se omite `tmp`),
* una **carpeta** de archivos `.eml`, leída de forma recursiva,
* un **conjunto de datos**: un archivo CSV o JSON Lines con una columna de texto y una columna de etiqueta (`--dataset`). Las columnas, o campos JSON, llamadas `text`, `message`, `body`, `email text`, `email`, `content`, `sms` o `v2`, y `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` o `labels`, en mayúsculas o minúsculas, se detectan solas (en JSON Lines, `label_text` antes que `label`); si no, usa `--text-column` y `--label-column`. Una línea JSON que no es un objeto se omite. Se entienden etiquetas como `spam`, `1`, `phishing` y `ham`, `0`, `not_spam`, `legitimate`.

Los mensajes duplicados se cuentan una sola vez. Un mensaje que está tanto en las fuentes de spam como en las de ham se conserva como spam, ya que las fuentes de spam se leen primero. Para partir del modelo incluido en lugar de empezar de cero, añade `--merge`.

Usa el modelo:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Cuánto correo es suficiente: unos cientos de mensajes de cada tipo dan un modelo útil, y unos miles, uno bueno. Mantén ambos tipos más o menos equilibrados, y deja en el ham el correo que no quieres filtrar (restablecimientos de contraseña, facturas de tus propios proveedores).


## Medirlo

Deja algo de correo fuera del entrenamiento y mide con él:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

El modelo incluido con mensajes SMS en 21 idiomas que nunca vio, la mayoría en idiomas que apenas conoce:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

La precisión indica qué parte de lo que llama spam es spam; la exhaustividad, qué parte del spam detecta. Aquí los mensajes dudosos cuentan como spam no detectado, aunque en un análisis las demás comprobaciones y el modelo de lenguaje todavía pueden detectarlos. La cifra que hay que vigilar son los falsos positivos: ham marcado como spam. En la ejecución anterior, el modelo tiene dudas sobre la mayoría de estos mensajes en lugar de equivocarse con ellos, que es el comportamiento buscado para los idiomas de los que tiene poco correo.

`--json` da las mismas cifras para los scripts.


## Aprender de las denuncias

Cuando los usuarios mueven correo a una carpeta Junk o lo sacan de ella, enseña al modelo mensaje a mensaje:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

El primer `learn` crea el archivo a partir del modelo incluido. Por HTTP, `POST /learn/spam` y `/learn/ham` de la [API HTTP](http-api.md) hacen lo mismo, y `spamc -L spam` funciona con el [servidor spamd](mail-servers.md#a-drop-in-for-spamassassins-spamd) con `--allow-tell`. [IMAPSieve de Dovecot](mail-servers.md#dovecot-junk-folder-and-learning) puede llamar a cualquiera de los dos cuando se mueve un mensaje.

Desde Node.js:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Un mensaje denunciado como mal clasificado debe desaprenderse de la clase equivocada antes de aprenderlo en la correcta, si se aprendió antes.


## El modelo incluido

`npm run model:train` genera `model/classifier.json` a partir de estos conjuntos de datos públicos de Hugging Face, todos con licencias abiertas:

| Conjunto de datos                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Licencia                        | Contenido                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------- | ------------------------------------------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                      | Mensajes y correos electrónicos en 43 idiomas                                   |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Corpus público de investigación | El corpus Enron-Spam                                                            |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                         | Mensajes de Telegram en ruso                                                    |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                             | Mensajes sintéticos                                                             |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                       | Listas de correo, boletines, spam, phishing y correos de fraude                 |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                             | Mensajes en 14 idiomas de la India                                              |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                      | Correos indonesios por categoría                                                |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                      | El correo de una empresa en español                                             |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0      | Correo corriente: facturas, reservas, boletines, promociones y avisos de cuenta |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                       | Lo que la gente pide a un asistente, en 20 idiomas                              |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                       | El correo de una empresa inventada en francés                                   |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Con este proyecto               | Correo cotidiano y fraudes en 23 idiomas, escritos para este proyecto           |

El ham incluye correo corriente de empresas y tiendas (facturas, avisos de pedidos y de cuenta, boletines, promociones), de modo que ese correo por sí solo no se lee como spam.

Los mensajes de rebote de los conjuntos de datos se dejan fuera: solo están entre el spam, lo que enseñaría al clasificador que todo rebote es spam.

Las tres últimas filas son texto corriente en los idiomas de los que los demás conjuntos de datos tienen sobre todo spam (francés, portugués, neerlandés, las lenguas nórdicas, polaco, turco, árabe, japonés, coreano, chino y otros), donde de otro modo cada palabra corriente se leería como spam. De 10 000 textos corrientes en 20 idiomas con los que el modelo no se entrenó, el 1.4 % obtiene una probabilidad del 80 % o más (el 4.8 % sin estas filas) y el 0.1 % una del 99 % o más. Este texto no es correo real, y los fraudes escritos para cada idioma son pocos: el clasificador queda más seguro del correo corriente en estos idiomas y atrapa poco más de su spam.

Aprendió de 81 254 mensajes de spam y 133 317 de ham. El script reserva uno de cada diez mensajes, entrena con el resto y mide solo el clasificador, sin las demás comprobaciones:

| Prueba con mensajes reservados | Mensajes | Precisión | Exhaustividad | Falsos positivos | Dudosos |
| ------------------------------ | -------: | --------: | ------------: | ---------------: | ------: |
| Inglés                         |     8481 |   100.0 % |        96.3 % |            0.0 % |   2.6 % |
| Ruso                           |     1680 |   100.0 % |        97.4 % |            0.0 % |   2.2 % |
| Italiano                       |     1392 |    99.0 % |        81.0 % |            0.9 % |  12.6 % |
| Alemán                         |     1314 |    97.9 % |        71.4 % |            1.9 % |  22.3 % |
| Español                        |     2088 |    98.7 % |        53.3 % |            0.4 % |  16.2 % |
| Enron-Spam                     |     2870 |   100.0 % |        95.2 % |            0.0 % |   2.6 % |
| all-scam-spam                  |     4222 |    99.9 % |        92.2 % |            0.0 % |   9.1 % |
| Todos                          |   21 329 |    99.6 % |        76.6 % |            0.2 % |  14.2 % |

Aquí, spam significa una probabilidad del clasificador del 99 % o más, el punto en el que el clasificador por sí solo alcanza el umbral de spam. En un análisis, el spam del que está menos seguro también recibe puntos, y las demás comprobaciones suman los suyos.

Los resultados en alemán, español e italiano provienen de conjuntos de datos sintéticos, que contienen mensajes casi idénticos etiquetados a la vez como spam y como ham: parte de ese error está en las etiquetas, no en el modelo. El correo en tus propios idiomas es la mejor solución. Las cifras, con cada idioma y conjunto de datos, están en `metadata.metrics` del modelo.

### Más idiomas

`npm run model:train -- --with multilingual-sms` añade la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): la SMS Spam Collection traducida automáticamente a 21 idiomas. Queda fuera del modelo incluido porque su ficha indica una licencia GPL; comprueba que se ajusta a la forma en que compartes el modelo. Entrenado con ella, los resultados con mensajes reservados para los idiomas que el modelo incluido apenas conoce fueron:

| Idioma  | Mensajes | Precisión | Exhaustividad | Falsos positivos |
| ------- | -------: | --------: | ------------: | ---------------: |
| Chino   |      432 |   100.0 % |        86.1 % |            0.0 % |
| Árabe   |      432 |   100.0 % |        83.1 % |            0.0 % |
| Coreano |      412 |   100.0 % |        78.3 % |            0.0 % |
| Japonés |      486 |    96.1 % |        87.5 % |            0.5 % |
| Hindi   |      494 |   100.0 % |        76.2 % |            0.0 % |
| Francés |      511 |    98.7 % |        88.6 % |            0.6 % |
| Turco   |      222 |   100.0 % |        70.4 % |            0.0 % |

### Volver a entrenarlo

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## El archivo de modelo

Un modelo es un archivo JSON: el número de mensajes de spam y de ham aprendidos y, para cada característica convertida con hash, cuántos mensajes de spam y de ham la contenían, ordenados y codificados en base64. No contiene palabras ni texto de los mensajes. `--max-features` conserva solo las características más frecuentes y `--min-count` descarta las poco frecuentes, a cambio de precisión por tamaño; el modelo incluido conserva 400 000 características en unos 6 MB.

Los modelos de Spam Scanner 6 y anteriores no se pueden cargar: usaban características distintas para el hash. Entrena uno nuevo con el mismo correo.
