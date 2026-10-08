<!-- source: f1043eb5fc58 -->

# Postfix y Sendmail

Spam Scanner se conecta a Postfix de dos maneras:

* **Como milter** (recomendado). Postfix le consulta sobre cada mensaje durante la sesión SMTP, antes de aceptarlo. El spam se puede rechazar con una respuesta 4xx o 5xx, así que se encarga de él el servidor remitente, no el tuyo. Sendmail usa el mismo protocolo.
* **Como filtro de contenido.** Postfix acepta el mensaje y lo pasa por una tubería a `spamscanner filter`, que añade los encabezados y lo devuelve con sendmail. Nunca se rechaza nada durante la sesión SMTP.

Ambos añaden estos encabezados a cada mensaje:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Los encabezados `X-Spam-*` que ya traiga el mensaje se eliminan primero, así que un remitente no puede marcar su propio correo como limpio.


## Milter

### 1. Ejecutar el milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Con `--reject`, los mensajes que llegan al umbral de rechazo (15 puntos) se rechazan con `451 4.7.1 Message rejected as spam`. Un 451 es temporal: el remitente vuelve a intentarlo más tarde y un error todavía se puede corregir cambiando una opción. Usa `--reject-code 550` para un rechazo permanente cuando los resultados parezcan correctos. Con `--quarantine`, el spam va en cambio a la cola de retención de Postfix.

Como servicio de systemd, en `/etc/systemd/system/spamscanner-milter.service`:

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. Configurar Postfix para usarlo

En `/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters` cubre el correo que llega por SMTP. Deja `non_smtpd_milters` vacío salvo que también se deba analizar el correo enviado con el comando `sendmail`.

### 3. Probarlo

[swaks](https://www.jetmore.org/john/code/swaks/) envía mensajes de prueba. GTUBE es una cadena de prueba que todo filtro de spam trata como spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Sin `--reject`, el mensaje se entrega con `X-Spam-Flag: YES` y el asunto marcado. Con `--reject`, swaks muestra la respuesta 451 o 550.


## Filtro de contenido

Usa esta opción cuando el correo no se deba rechazar nunca durante la sesión SMTP, o en un servidor que no pueda usar milters.

En `/etc/postfix/master.cf`, añade un servicio de filtro y úsalo en el servicio de escucha SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix ejecuta el filtro con un entorno casi vacío, así que `argv` nombra Node.js y el script por sus rutas completas (`command -v node` y `npm root --global` las muestran). Después:

```sh
sudo postfix reload
```

El filtro devuelve el mensaje con `sendmail -G -i`. El correo enviado así no vuelve a pasar por el servicio de escucha `smtp`, así que no se filtra dos veces.

Los códigos de salida indican a Postfix qué ocurrió: 0 entregado, 69 rechazado (con `--reject`: Postfix lo devuelve al remitente), 75 fallo temporal (Postfix conserva el mensaje y vuelve a intentarlo). Cualquier fallo de análisis o de entrega es 75, así que una configuración rota nunca pierde ni devuelve correo.


## Sendmail

En `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` hace que Sendmail responda con un fallo temporal mientras el milter no está disponible; quítalo para aceptar en cambio el correo sin filtrar. Vuelve a generar `sendmail.cf` y reinicia Sendmail.


## Clasificar el spam en una carpeta Junk

Marcarlo por sí solo entrega el spam en la bandeja de entrada. Con Dovecot, una regla de Sieve lo mueve:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Otros servidores de correo](mail-servers.md) trata Dovecot, Exim, Haraka y procmail, y [entrenamiento](training.md#learning-from-reports) muestra cómo aprender del correo que los usuarios mueven a Junk o sacan de ahí.


## Probado

Las pruebas de extremo a extremo del repositorio ejecutan un Postfix real: el ham se entrega con encabezados, un `X-Spam-Flag` falsificado se elimina, el spam se marca, GTUBE se rechaza con un 550 durante la sesión SMTP y el filtro de contenido marca el correo en un segundo puerto. `scripts/e2e-postfix.sh` configura ese Postfix y `test/e2e/postfix.test.js` envía el correo.
