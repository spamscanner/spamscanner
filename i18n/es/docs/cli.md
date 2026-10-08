<!-- source: a59bc5927d86 -->

# Línea de comandos

```text
spamscanner <command> [options]
```

| Comando                                    | Qué hace                                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Analiza un mensaje de un archivo o de la entrada estándar                                   |
| `filter -f <sender> -- <recipients...>`    | Filtro de contenido de Postfix: analiza la entrada estándar, añade encabezados y lo reenvía |
| `milter`                                   | Milter para Postfix y Sendmail, puerto 7831                                                 |
| `http`                                     | API HTTP, puerto 7832                                                                       |
| `server`                                   | Servidor TCP simple, puerto 7830                                                            |
| `spamd`                                    | Servidor spamd compatible con SpamAssassin, puerto 783                                      |
| `train`                                    | Entrena un modelo con archivos mbox, Maildirs, carpetas o conjuntos de datos                |
| `eval`                                     | Mide un modelo con correo etiquetado                                                        |
| `learn spam\|ham [file\|-] --model <file>` | Enseña un mensaje a un modelo                                                               |
| `llm-test`                                 | Comprueba la configuración del modelo de lenguaje con tres mensajes de ejemplo              |
| `models`                                   | Muestra los modelos abiertos recomendados                                                   |
| `version`, `help`                          |                                                                                             |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Opción                     | Significado                                                             |
| -------------------------- | ----------------------------------------------------------------------- |
| `--json`                   | Imprime el resultado completo en JSON                                   |
| `--headers`                | Imprime el mensaje con los encabezados `X-Spam-*` añadidos              |
| `--subject-tag <tag>`      | Añade además un prefijo al asunto del spam                              |
| `--verbose`                | Muestra todas las pruebas y los indicios más fuertes del clasificador   |
| `--threshold <n>`          | Puntuación a partir de la cual el correo es spam (predeterminado 5)     |
| `--reject-threshold <n>`   | Puntuación a partir de la cual el correo se rechaza (predeterminado 15) |
| `--model <file>`           | Un archivo de modelo en lugar del incluido                              |
| `--no-classifier`          | No usa el clasificador                                                  |
| `--config <file>`          | Un archivo JSON con [opciones de la biblioteca](api.md#options)         |
| `--allow-language <codes>` | Idiomas aceptados, por ejemplo `en,de,fr`                               |

Códigos de salida: 0 ham, 1 spam, 2 error.

### Sesión SMTP

| Opción              | Significado                                          |
| ------------------- | ---------------------------------------------------- |
| `--ip <address>`    | Dirección IP del cliente que envió el mensaje        |
| `--hostname <name>` | El nombre DNS inverso verificado del cliente         |
| `--helo <name>`     | El nombre que dio en HELO o EHLO                     |
| `--from <address>`  | Remitente del sobre (MAIL FROM)                      |
| `--to <address>`    | Destinatario del sobre; repítelo para indicar varios |

### Comprobaciones

| Opción                | Significado                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------- |
| `--auth`              | Comprueba SPF, DKIM, DMARC y ARC (necesita `--ip`)                                          |
| `--dnsbl <zone>`      | Lista de bloqueo de IP, por ejemplo `zen.spamhaus.org`; se puede repetir                    |
| `--uribl <zone>`      | Lista de bloqueo de dominios para enlaces, por ejemplo `dbl.spamhaus.org`; se puede repetir |
| `--dns-server <ip>`   | Servidor de nombres para las comprobaciones DNS; se puede repetir                           |
| `--no-cloudflare`     | No consulta a los resolutores de filtrado de Cloudflare por los enlaces                     |
| `--clamav [socket]`   | Analiza los adjuntos con clamd, en su socket predeterminado o en el indicado                |
| `--allowlist <value>` | Acepta siempre esta dirección IP, dominio o dirección; se puede repetir                     |
| `--denylist <value>`  | Rechaza siempre esta dirección IP, dominio o dirección; se puede repetir                    |

### Modelo de lenguaje

| Opción                                                     | Significado                                                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` y otros ([lista](llm.md#providers))                     |
| `--llm-model <name>`                                       | Modelo, por ejemplo `qwen3.5:4b` o `claude-haiku-4-5`                                             |
| `--llm-url <url>`                                          | URL base, por ejemplo `http://10.0.0.5:11434`                                                     |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Cambia una parte de la URL del proveedor                                                          |
| `--llm-api-key <key>`                                      | Clave de API; consulta también las variables de entorno más abajo                                 |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` o `none`                                      |
| `--llm-auth-header <name>`                                 | Encabezado para la clave, con `--llm-auth header`                                                 |
| `--llm-username`, `--llm-password`                         | Para `--llm-auth basic`                                                                           |
| `--llm-header "Name: value"`                               | Encabezado adicional de la petición; se puede repetir                                             |
| `--llm-mode <mode>`                                        | `auto` (solo casos dudosos, el valor predeterminado) o `always`                                   |
| `--llm-timeout <ms>`                                       | Predeterminado 30000                                                                              |
| `--llm-policy <text>`                                      | Reglas adicionales para el modelo, por ejemplo «Nunca enviamos facturas»                          |
| `--llm-redact`, `--no-llm-redact`                          | Elimina antes los datos personales; activado de forma predeterminada para los proveedores remotos |


## filter

Un [filtro de contenido de Postfix](postfix.md#content-filter). Lee un mensaje de la entrada estándar, añade los encabezados `X-Spam-*` y lo pasa a sendmail con el mismo sobre.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Opción                | Significado                                                              |
| --------------------- | ------------------------------------------------------------------------ |
| `--sendmail <path>`   | Predeterminado `/usr/sbin/sendmail`                                      |
| `--subject-tag <tag>` | Añade un prefijo al asunto del spam                                      |
| `--reject`            | Devuelve el correo que llega al umbral de rechazo en lugar de reenviarlo |
| `--discard`           | Descarta el correo que llega al umbral de rechazo en lugar de reenviarlo |

Los códigos de salida siguen las convenciones de sendmail, que Postfix interpreta: 0 entregado (o descartado), 64 no se indicaron destinatarios, 69 rechazado como spam (Postfix lo devuelve), 75 cualquier fallo, así que Postfix conserva el mensaje y vuelve a intentarlo más tarde.


## milter, http, server y spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

El puerto 783 es el que usan de forma predeterminada los clientes de SpamAssassin. Los puertos por debajo de 1024 necesitan root o la capacidad `CAP_NET_BIND_SERVICE`; usa otro puerto, como `--port 7833`, e indícaselo al cliente.

| Opción                | Significado                                                                   |
| --------------------- | ----------------------------------------------------------------------------- |
| `--port <n>`          | Puerto TCP                                                                    |
| `--host <ip>`         | Dirección en la que escuchar (predeterminado 127.0.0.1)                       |
| `--socket <path>`     | Escucha en un socket Unix en su lugar                                         |
| `--reject`            | Milter: rechaza el correo que llega al umbral de rechazo                      |
| `--reject-code <n>`   | Milter: 451, reintentar más tarde (el predeterminado), o 550                  |
| `--quarantine`        | Milter: retiene el spam en la cuarentena del servidor de correo               |
| `--name <hostname>`   | Milter: el nombre de este servidor en Authentication-Results                  |
| `--token <secret>`    | HTTP: exige `Authorization: Bearer <secret>`; necesario para `/learn`         |
| `--allow-tell`        | spamd: acepta peticiones TELL (`spamc -L spam`) para aprender                 |
| `--out <file>`        | HTTP y spamd: guarda lo aprendido en este archivo de modelo                   |
| `--subject-tag <tag>` | Milter y spamd: añade un prefijo al asunto del spam                           |
| `--verbose`           | Milter: registra cada análisis. Servidor TCP: responde con una línea de texto |

Las opciones de análisis anteriores también se aplican a los servidores. [El milter](postfix.md#milter), [la API HTTP, el servidor TCP y spamd](http-api.md).


## train, eval y learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Opción                                          | Significado                                                                          |
| ----------------------------------------------- | ------------------------------------------------------------------------------------ |
| `--spam <path>`                                 | Spam: un archivo mbox, un Maildir o una carpeta de archivos `.eml`; se puede repetir |
| `--ham <path>`                                  | Ham, de la misma forma; se puede repetir                                             |
| `--dataset <file>`                              | Un archivo CSV o JSON Lines con columnas de texto y de etiqueta; se puede repetir    |
| `--text-column <name>`, `--label-column <name>` | Nombres de las columnas, cuando no se detectan                                       |
| `--out <file>`                                  | Dónde escribir el modelo (predeterminado `spamscanner-model.json`)                   |
| `--merge`                                       | Parte del modelo incluido (o de `--model`) en lugar de uno vacío                     |

`learn` actualiza el archivo de modelo en el mismo lugar y, la primera vez, lo crea a partir del modelo incluido. [Entrenamiento](training.md)


## llm-test y models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` envía al modelo un mensaje normal y dos estafas, en inglés y en italiano, imprime sus veredictos y termina con 0 solo si acierta los tres.


## Archivo de configuración

`--config file.json` (o la variable de entorno `SPAMSCANNER_CONFIG`) carga [opciones de la biblioteca](api.md#options). Las opciones de la línea de comandos tienen prioridad sobre el archivo.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Variables de entorno

| Variable                                                                                                                                                                                                                                             | Significado                                                  |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | Archivo de configuración                                     |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | Archivo de modelo usado en lugar del incluido                |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | Token para la API HTTP                                       |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | Clave de API para cualquier proveedor de modelos de lenguaje |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | La clave propia de cada proveedor                            |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | Registro de depuración                                       |
