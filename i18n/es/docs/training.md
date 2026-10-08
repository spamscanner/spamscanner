<!-- source: 7cc30ff4ad91 -->

# Entrenamiento

El modelo incluido funciona desde el primer momento. Un modelo entrenado con tu propio correo funciona mejor, porque aprende cómo es tu ham: tus boletines, la forma de escribir de tus colegas, los idiomas que recibes.


## Entrenar un modelo

Indica a `train` las carpetas de spam y de ham:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Las fuentes pueden ser:

* archivos **mbox**, también comprimidos con gzip (`.mbox.gz`),
* un **Maildir** (se leen sus carpetas `cur` y `new`, y se omite `tmp`),
* una **carpeta** de archivos `.eml`, leída de forma recursiva,
* un **conjunto de datos**: un archivo CSV o JSON Lines con una columna de texto y una columna de etiqueta (`--dataset`). Las columnas llamadas `text`, `message`, `body`, `email` o `content`, y `label`, `category`, `class`, `spam` o `is_spam`, se detectan solas; si no, usa `--text-column` y `--label-column`. Se entienden etiquetas como `spam`, `1`, `phishing` y `ham`, `0`, `not_spam`, `legitimate`.

Los mensajes duplicados se cuentan una sola vez. Para partir del modelo incluido en lugar de empezar de cero, añade `--merge`.

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
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
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

| Conjunto de datos                                                                                                                                                                                                                                                                                                          | Licencia                        | Contenido                                     |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | --------------------------------------------- |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0                      | Mensajes y correos electrónicos en 43 idiomas |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Corpus público de investigación | El corpus Enron-Spam                          |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                         | Mensajes de Telegram en ruso                  |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                             | Mensajes sintéticos                           |

Aprendió de 62 480 mensajes de spam y 76 489 de ham. El script reserva uno de cada diez mensajes, entrena con el resto y mide solo el clasificador, sin las demás comprobaciones:

| Prueba con mensajes reservados | Mensajes | Precisión | Exhaustividad | Falsos positivos | Dudosos |
| ------------------------------ | -------: | --------: | ------------: | ---------------: | ------: |
| Inglés                         |     6564 |   100.0 % |        97.0 % |            0.0 % |   2.4 % |
| Ruso                           |     1682 |   100.0 % |        97.4 % |            0.0 % |   2.2 % |
| Italiano                       |     1389 |    98.1 % |        85.3 % |            1.8 % |  10.9 % |
| Alemán                         |     1309 |    97.7 % |        76.1 % |            2.2 % |  20.7 % |
| Español                        |     1281 |    97.5 % |        82.5 % |            2.6 % |  16.8 % |
| Enron-Spam                     |     2888 |   100.0 % |        93.1 % |            0.0 % |   4.5 % |
| all-scam-spam                  |     4236 |   100.0 % |        88.8 % |            0.0 % |  11.2 % |
| Todos                          |   13 840 |    99.2 % |        85.1 % |            0.5 % |  12.4 % |

Aquí, spam significa una probabilidad del clasificador del 99 % o más, el punto en el que el clasificador por sí solo alcanza el umbral de spam. En un análisis, el spam del que está menos seguro también recibe puntos, y las demás comprobaciones suman los suyos.

Los resultados en alemán, español e italiano provienen de conjuntos de datos sintéticos, que contienen mensajes casi idénticos etiquetados a la vez como spam y como ham: parte de ese error está en las etiquetas, no en el modelo. El correo en tus propios idiomas es la mejor solución. Las cifras, con cada idioma y conjunto de datos, están en `metadata.metrics` del modelo.

### Más idiomas

`npm run model:train -- --with multilingual-sms` añade la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset): la SMS Spam Collection traducida automáticamente a 21 idiomas. Queda fuera del modelo incluido porque su ficha indica una licencia GPL; comprueba que se ajusta a la forma en que compartes el modelo. Entrenado con ella, los resultados con mensajes reservados para los idiomas que el modelo incluido apenas conoce fueron:

| Idioma  | Mensajes | Precisión | Exhaustividad | Falsos positivos |
| ------- | -------: | --------: | ------------: | ---------------: |
| Chino   |      430 |   100.0 % |        82.3 % |            0.0 % |
| Árabe   |      430 |   100.0 % |        84.6 % |            0.0 % |
| Coreano |      412 |   100.0 % |        80.4 % |            0.0 % |
| Japonés |      486 |    96.0 % |        85.7 % |            0.5 % |
| Hindi   |      412 |   100.0 % |        63.9 % |            0.0 % |
| Francés |      480 |    98.6 % |        94.2 % |            0.6 % |
| Turco   |      220 |   100.0 % |        73.1 % |            0.0 % |

### Volver a entrenarlo

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## El archivo de modelo

Un modelo es un archivo JSON: el número de mensajes de spam y de ham aprendidos y, para cada característica convertida con hash, cuántos mensajes de spam y de ham la contenían, ordenados y codificados en base64. No contiene palabras ni texto de los mensajes. `--max-features` conserva solo las características más frecuentes y `--min-count` descarta las poco frecuentes, a cambio de precisión por tamaño; el modelo incluido conserva 400 000 características en unos 6 MB.

Los modelos de Spam Scanner 6 y anteriores no se pueden cargar: usaban características distintas para el hash. Entrena uno nuevo con el mismo correo.
