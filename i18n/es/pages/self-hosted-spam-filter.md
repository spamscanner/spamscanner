<!-- source: 988243aec4f3 -->

<!--
label: Filtro de spam autoalojado
title: Filtro de spam autoalojado para tu propio servidor de correo
description: Un filtro de spam en tu propio servidor. Spam Scanner deja el correo en la máquina, incluye su modelo en el paquete, no envía telemetría y se conecta a Postfix o Exim.
keywords: filtro de spam autoalojado, filtro de spam local, filtro de spam privado, antispam on-premise, filtro de spam para servidor de correo, filtro de spam sin nube
-->

# Filtro de spam autoalojado

Spam Scanner funciona en tu propio servidor y deja el correo allí. El modelo del clasificador viene dentro del paquete, no hay telemetría ni comprobación de actualizaciones y, por defecto, lo único que envía es una consulta DNS por el nombre de host de cada enlace.


## Qué sale del servidor

Por defecto, solo los nombres de host de los enlaces de un mensaje. Se consultan en los resolvedores con filtrado de Cloudflare (1.1.1.2 y 1.1.1.3) como consultas DNS normales, y no se envía ninguna parte del mensaje ni de sus direcciones. `--no-cloudflare` también lo desactiva.

Cualquier otra comprobación que use la red está desactivada hasta que la actives:

| Comprobación          | Se activa con        | Qué envía                                                                     |
| --------------------- | -------------------- | ----------------------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | Consultas DNS de los registros del remitente                                  |
| Listas de bloqueo DNS | `--dnsbl`, `--uribl` | La dirección IP del cliente y los dominios de los enlaces, como consultas DNS |
| ClamAV                | `--clamav`           | Los adjuntos, a tu propio clamd                                               |
| Un modelo de lenguaje | `--llm`              | Un resumen del mensaje, al servidor que indiques                              |

Los análisis no se registran ni se guardan. [Seguridad y privacidad](../../docs/security.md)


## Instalar en un servidor

```sh
npm install --global spamscanner
```

O el binario independiente, con Node.js y el modelo incluidos:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

El script de instalación comprueba el binario con el archivo `SHA256SUMS` de la versión antes de instalarlo, y cada binario tiene una atestación de procedencia de compilación firmada que comprueba `gh attestation verify`. Hay binarios para Linux (x64 y arm64), macOS y Windows. Los binarios de Linux necesitan glibc, así que en Alpine instala con npm. [Primeros pasos](../../docs/getting-started.md)

No hay comprobación de actualizaciones. Para actualizar, vuelve a ejecutar el comando de instalación: los dos comandos instalan la última versión.


## Ejecutarlo como servicio

Los servidores milter, HTTP, TCP y spamd escuchan en 127.0.0.1 salvo que `--host` indique otra cosa. Ejecútalos con un usuario sin privilegios, por ejemplo con systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

La [unidad completa y su configuración](../../docs/postfix.md#1-run-the-milter) están en la guía de Postfix. Ninguno de los servidores habla TLS, así que para llegar a uno desde otra máquina usa una red privada, un túnel SSH o un proxy inverso con TLS.


## Conectar tu servidor de correo

| Servidor de correo                       | Comando                                      | Puerto  |
| ---------------------------------------- | -------------------------------------------- | ------- |
| Postfix o Sendmail                       | `spamscanner milter`                         | 7831    |
| Postfix, sin rechazar nunca correo       | `spamscanner filter`, un filtro de contenido | ninguno |
| Exim, Haraka o spamc                     | `spamscanner spamd`                          | 783     |
| Cualquier cosa que hable HTTP            | `spamscanner http`                           | 7832    |
| Un cliente TCP simple                    | `spamscanner server`                         | 7830    |
| Un servidor de correo escrito en Node.js | `import SpamScanner from 'spamscanner'`      | ninguno |

Los servidores pueden añadir al mensaje las cabeceras `X-Spam-Flag`, `X-Spam-Score` y `X-Spam-Status`, y la biblioteca devuelve la puntuación y cada prueba que se activó. Guías: [filtro de spam para Postfix](/postfix-spam-filter/), [otros servidores de correo](../../docs/mail-servers.md) y [la API HTTP](../../docs/http-api.md).


## Mantener los modelos de lenguaje en local

Un modelo de lenguaje es opcional y solo lee los casos dudosos: el spam claro y el ham claro nunca le llegan. Con Ollama se ejecuta en el mismo servidor, así que ningún mensaje sale de él:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` funciona en una CPU. Si usas un proveedor alojado, los datos personales se eliminan del mensaje antes de enviarlo. [Modelos de lenguaje](../../docs/llm.md)


## Entrenarlo con tu propio correo

El modelo incluido está entrenado con conjuntos de datos públicos. Un modelo entrenado con el correo que recibe tu servidor funciona mejor, y se queda en ese servidor:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Un archivo de modelo guarda recuentos de características con hash, no palabras ni texto de mensajes. [Entrenamiento](../../docs/training.md)


## Requisitos

Node.js 18 o posterior en Linux, macOS o Windows, o nada con un binario independiente. ClamAV y Ollama son opcionales y funcionan como servicios propios.
