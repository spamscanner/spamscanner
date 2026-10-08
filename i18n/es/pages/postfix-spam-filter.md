<!-- source: f33722183f00 -->

<!--
label: Filtro de spam para Postfix
title: Filtro de spam para Postfix con milter o filtro de contenido
description: Filtra el spam en Postfix con el milter o el filtro de contenido de Spam Scanner: instalación, unidad systemd, rechazo con 4xx o 5xx y carpeta Junk.
keywords: filtro de spam para Postfix, milter de Postfix, smtpd_milters, filtro de contenido de Postfix, antispam para Postfix, rechazar spam en Postfix
-->

# Filtro de spam para Postfix

Spam Scanner filtra un servidor Postfix en unos cinco minutos. Funciona como milter, así que Postfix le consulta sobre cada mensaje durante la sesión SMTP y puede rechazar el spam antes de aceptarlo.


## Instalar y ejecutar

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` comprueba SPF, DKIM, DMARC y ARC; `--subject-tag` marca el spam en el asunto. Cada mensaje recibe los encabezados `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` y `X-Spam-Action`, y cualquier encabezado `X-Spam-*` que haya puesto el remitente se elimina primero.


## Conectar Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` deja pasar el correo sin filtrar si el milter no está disponible; `tempfail` pide en cambio a los remitentes que vuelvan a intentarlo.


## Rechazar el spam durante la sesión SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

Los mensajes que llegan al umbral de rechazo (15 puntos) se rechazan con `451 4.7.1 Message rejected as spam`. Un 451 es temporal: el remitente conserva el mensaje y vuelve a intentarlo, así que una decisión equivocada cuesta un retraso, no un mensaje perdido. Cuando los resultados parezcan correctos, `--reject-code 550` hace que el rechazo sea permanente.


## Sin milter

Un filtro de contenido se ejecuta después de que Postfix acepte un mensaje: Postfix lo pasa por una tubería a `spamscanner filter`, que añade los encabezados y lo devuelve. Nunca se rechaza nada durante la sesión, y un fallo siempre aplaza la entrega en lugar de devolver el mensaje. [Configuración del filtro de contenido](../../docs/postfix.md#content-filter)


## Spam a Junk

Con Dovecot, una regla de Sieve archiva el correo marcado:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Probado con un Postfix real

Las pruebas de extremo a extremo del proyecto ejecutan Postfix con el milter y el filtro de contenido: el ham se entrega con encabezados y sin el `X-Spam-Flag` falsificado, el spam se marca y GTUBE se rechaza con un 550 durante la sesión SMTP.

Siguiente: [la guía completa de Postfix y Sendmail](../../docs/postfix.md), con una unidad de systemd y el `INPUT_MAIL_FILTER` de Sendmail.
