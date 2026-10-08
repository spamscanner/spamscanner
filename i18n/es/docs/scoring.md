<!-- source: 6f6b765c5fc1 -->

# Pruebas y puntuaciones

Un mensaje es spam con 5 puntos y se rechaza con 15. Cada prueba de abajo suma o resta puntos; el resultado enumera las que se activaron.

Cambia los umbrales con `threshold` y `rejectThreshold`. Cambia los puntos con `scores`, ya sea por clave de configuración (`scores: {deceptiveLink: 4}`) o por nombre de prueba, lo que fija los puntos de esa prueba (`scores: {FROM_NAME_BRAND: 4}`).


## Clasificador

| Prueba                   | Puntos          | Significado                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------ | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` a `BAYES_999` | de -2.5 a +6.25 | La probabilidad de spam del clasificador, en una escala logarítmica de probabilidades a favor (log-odds): 2.4 puntos al 90 %, 5 al 99 % y 6.25 al 99.9 %, así que el clasificador marca spam por sí solo solo cuando está seguro al menos en un 99 %. El nombre indica la franja: `BAYES_999` es 99.9 % o más, `BAYES_99` de 99 % a 99.9 %, `BAYES_50` de 40 % a 60 %. Las claves de configuración `bayesHam` y `bayesSpam` definen los dos extremos. |


## Phishing y enlaces

| Prueba                      | Puntos | Clave de configuración | Significado                                                                           |
| --------------------------- | -----: | ---------------------- | ------------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |      5 | `homograph`            | El dominio de un enlace imita una marca con caracteres parecidos o cambiados          |
| `MIXED_SCRIPT_DOMAIN`       |      3 | `mixedScriptDomain`    | Una etiqueta de dominio mezcla alfabetos                                              |
| `BRAND_IN_DOMAIN`           |    1.5 | `brandInDomain`        | Un nombre de marca dentro del dominio de otra persona                                 |
| `TYPO_DOMAIN`               |      1 | `typoDomain`           | A una letra de distancia del dominio de una marca                                     |
| `DECEPTIVE_LINK`            |      3 | `deceptiveLink`        | Un enlace muestra una dirección y lleva a otra                                        |
| `MALICIOUS_DOMAIN`          |      6 | `maliciousDomain`      | El resolutor de malware de Cloudflare bloquea un dominio enlazado                     |
| `ADULT_DOMAIN`              |      2 | `adultDomain`          | El resolutor familiar de Cloudflare bloquea un dominio enlazado                       |
| `URIBL_<LIST>`              |      5 | `uriblListed`          | Un dominio enlazado está en una lista de bloqueo de dominios, por ejemplo `URIBL_DBL` |


## Adjuntos

| Prueba                  | Puntos | Clave de configuración                   | Significado                                                              |
| ----------------------- | -----: | ---------------------------------------- | ------------------------------------------------------------------------ |
| `EXECUTABLE_ATTACHMENT` |     10 | `executable`                             | Un programa o script                                                     |
| `DISGUISED_EXECUTABLE`  |     12 | `disguisedExecutable`                    | Un programa con nombre de documento o de imagen                          |
| `DOUBLE_EXTENSION`      |      6 | `doubleExtension`                        | Un nombre como `invoice.pdf.exe`                                         |
| `RTL_OVERRIDE_FILENAME` |      6 | `rtlOverride`                            | Un carácter de anulación de derecha a izquierda oculta la extensión real |
| `EXECUTABLE_IN_ARCHIVE` |      8 | `executableInArchive`                    | Un programa dentro de un archivo ZIP                                     |
| `ENCRYPTED_ARCHIVE`     |      2 | `encryptedArchive`                       | Un archivo comprimido que los analizadores no pueden abrir               |
| `MACRO_ATTACHMENT`      |      4 | `macro`                                  | Un archivo de Office con macros                                          |
| `PDF_ACTIVE_CONTENT`    |      3 | `pdfActive`                              | Un PDF con JavaScript, acciones de ejecución o archivos incrustados      |
| `RTF_EMBEDDED_OBJECT`   |      4 | `rtfObject`                              | Un archivo RTF con objetos incrustados                                   |
| `HTML_ATTACHMENT`       |  1 o 3 | `htmlAttachment`, `activeHtmlAttachment` | Un archivo HTML; 3 cuando tiene scripts o formularios                    |
| `VIRUS`                 |    100 | `virus`                                  | ClamAV encontró un virus                                                 |


## Reglas

| Prueba                    | Puntos | Significado                                                                                                             |
| ------------------------- | -----: | ----------------------------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |   1000 | La cadena de prueba GTUBE                                                                                               |
| `SEXTORTION_SUBJECT`      |      6 | Un asunto que usan las estafas de sextorsión y de robo de cuentas                                                       |
| `PAYPAL_INVOICE`          |      6 | Una factura o solicitud de dinero de PayPal, un canal que se aprovecha para estafas                                     |
| `MICROSOFT_SPAM_VERDICT`  |      5 | Microsoft marcó el mensaje como spam antes de retransmitirlo (solo se confía en ello desde los servidores de Microsoft) |
| `MICROSOFT_HIGH_SCL`      |      3 | Microsoft le dio un nivel de confianza de spam alto (igual que el anterior)                                             |
| `PROMPT_INJECTION`        |      3 | Texto dirigido a un filtro de IA                                                                                        |
| `SELF_SPOOF`              |      3 | Dice venir del propio dominio del destinatario y no se autentica                                                        |
| `FROM_NAME_OTHER_ADDRESS` |    2.5 | El nombre visible contiene una dirección de correo electrónico distinta                                                 |
| `FROM_NAME_BRAND`         |      2 | El nombre visible dice ser una marca a la que no pertenece la dirección                                                 |
| `DATE_IN_FUTURE`          |      1 | Con una fecha de más de un día en el futuro                                                                             |
| `MISSING_DATE`            |    0.5 | Sin encabezado Date                                                                                                     |
| `MISSING_MESSAGE_ID`      |    0.5 | Sin encabezado Message-ID                                                                                               |

Las reglas que valen al menos el umbral de spam también aparecen en `results.arbitrary`, como en las versiones anteriores.


## Ofuscación e idioma

| Prueba                 | Puntos | Clave de configuración | Significado                                                         |
| ---------------------- | -----: | ---------------------- | ------------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |      2 | `invisibleCharacters`  | Tres o más caracteres invisibles dentro del texto                   |
| `MIXED_SCRIPT_WORDS`   |    2.5 | `mixedScriptWords`     | Dos o más palabras mezclan letras de alfabetos distintos            |
| `STYLED_LETTERS`       |    1.5 | `styledLetters`        | Letras matemáticas o encerradas que se hacen pasar por texto simple |
| `LANGUAGE_NOT_ALLOWED` |      3 | `languageNotAllowed`   | No está en `allowedLanguages`                                       |


## Autenticación

Necesita la dirección IP del cliente y `authentication: true`.

| Prueba         | Puntos | Clave de configuración (en `authentication.weights`) |
| -------------- | -----: | ---------------------------------------------------- |
| `SPF_PASS`     |   -0.5 | `spfPass`                                            |
| `SPF_FAIL`     |      2 | `spfFail`                                            |
| `SPF_SOFTFAIL` |      1 | `spfSoftfail`                                        |
| `DKIM_PASS`    |   -0.5 | `dkimPass`                                           |
| `DKIM_FAIL`    |      1 | `dkimFail`                                           |
| `DMARC_PASS`   |   -1.5 | `dmarcPass`                                          |
| `DMARC_FAIL`   |    3.5 | `dmarcFail`                                          |
| `ARC_PASS`     |   -0.5 | `arcPass`                                            |
| `ARC_FAIL`     |      1 | `arcFail`                                            |


## Reputación y listas de bloqueo

| Prueba         | Puntos | Clave de configuración | Significado                                                                             |
| -------------- | -----: | ---------------------- | --------------------------------------------------------------------------------------- |
| `DENYLISTED`   |    100 | `denylisted`           | La dirección IP, el dominio o la dirección del remitente está en la lista de bloqueados |
| `ALLOWLISTED`  |    -20 | `allowlisted`          | Está en la lista de permitidos                                                          |
| `TRUTH_SOURCE` |     -5 | `truthSource`          | Un servicio de reputación marca al remitente como de confianza                          |
| `RBL_<LIST>`   |      4 | `rblListed`            | La dirección IP del cliente está en una lista de bloqueo, por ejemplo `RBL_ZEN`         |


## Modelo de lenguaje y modelos opcionales

| Prueba                                                | Puntos   | Clave de configuración | Significado                                            |
| ----------------------------------------------------- | -------- | ---------------------- | ------------------------------------------------------ |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | hasta +6 | `llmSpam`              | El veredicto del modelo, multiplicado por su confianza |
| `LLM_HAM`                                             | hasta -3 | `llmHam`               | Igual que el anterior                                  |
| `TOXIC_CONTENT`                                       | 3        | `toxicity`             | Un modelo de toxicidad que aportas tú marcó el texto   |
| `NSFW_IMAGE`                                          | 3        | `nsfw`                 | Un modelo de imágenes que aportas tú marcó una imagen  |
