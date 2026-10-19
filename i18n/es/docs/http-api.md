<!-- source: 665fbc0d5adc -->

# API HTTP, servidor TCP y spamd


## API HTTP

```sh
spamscanner http --port 7832    # token in SPAMSCANNER_TOKEN
```

La API HTTP lee su token de la variable de entorno `SPAMSCANNER_TOKEN`. `--token` también funciona, pero los demás usuarios de la máquina pueden ver las opciones de la línea de comandos en `ps`.

Escucha en 127.0.0.1 salvo que `--host` indique otra cosa. Con un token, todas las peticiones excepto `/health` necesitan `Authorization: Bearer <token>`. Ponlo detrás de un proxy inverso con TLS antes de exponerlo fuera de la máquina.

| Método y ruta      | Cuerpo                  | Respuesta                                                                 |
| ------------------ | ----------------------- | ------------------------------------------------------------------------- |
| `GET /health`      |                         | `{"ok": true, "version": "..."}`                                          |
| `POST /scan`       | El mensaje sin procesar | El [resultado del análisis](api.md#the-result) en JSON                    |
| `POST /check`      | El mensaje sin procesar | El mensaje con los encabezados `X-Spam-*` añadidos, como `message/rfc822` |
| `POST /learn/spam` | El mensaje sin procesar | `{"ok": true, "learned": "spam"}`; necesita un token                      |
| `POST /learn/ham`  | El mensaje sin procesar | `{"ok": true, "learned": "ham"}`; necesita un token                       |

Los parámetros de consulta describen la sesión SMTP:

| Parámetro    | Significado                                                             |
| ------------ | ----------------------------------------------------------------------- |
| `ip`         | La dirección IP del cliente                                             |
| `hostname`   | Su nombre DNS inverso verificado                                        |
| `helo`       | Su nombre en HELO o EHLO                                                |
| `from`       | El remitente del sobre                                                  |
| `to`         | Un destinatario; repítelo o separa varios con comas                     |
| `verbose=1`  | `/scan`: devuelve también la lista de palabras y el asunto              |
| `subjectTag` | `/check`: añade un prefijo al asunto del spam, por ejemplo `%5BSPAM%5D` |

Sin `ip`, se omiten las comprobaciones de SPF, DKIM, DMARC, ARC y listas de bloqueo de IP (`--auth`, `--dnsbl`).

`/check` también devuelve `X-Spam-Flag`, `X-Spam-Score` y `X-Spam-Action` como encabezados de la respuesta, así que un cliente puede decidir sin procesar el mensaje.

Los mensajes de más de 25 MiB (`--max-size`) reciben `413`, antes de leer el cuerpo cuando `Content-Length` indica el tamaño. Un análisis que falla recibe `500` con `{"error": "..."}`. El servidor atiende como máximo 200 peticiones a la vez (`--max-connections`), incluidas las enviadas en pipeline; las demás reciben `503` con `Retry-After: 1`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Con `--out model.json`, lo que enseña `/learn` se guarda en ese archivo después de cada petición. Sin esa opción, el aprendizaje dura hasta que se reinicia el servidor.

Desde Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Desde Python:

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## Servidor TCP

```sh
spamscanner server --port 7830
```

Envía el mensaje sin procesar, cierra el lado de envío de la conexión y lee una línea de JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Con `--verbose`, la respuesta es en cambio una línea de texto: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` o `HAM -2.5/5.0 BAYES_00`.

El servidor TCP no conoce la dirección IP del cliente, así que `--auth` y `--dnsbl` no tienen efecto. Solo responde cuando el cliente cierra su lado de envío (`nc -N` o `nc -q 1`, o `shutdown(SHUT_WR)` en un socket); un cliente que lo mantiene abierto no recibe respuesta, y la conexión se cierra tras 60 segundos sin datos. Responde con un error a los mensajes de más de 25 MiB (`--max-size`).


## spamd

```sh
spamscanner spamd --port 783
```

Un servidor compatible con SpamAssassin para spamc, Exim, Haraka y otros clientes de SpamAssassin. [Configurar Exim y Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Comando         | Respuesta                                                                          |
| --------------- | ---------------------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                                          |
| `SYMBOLS`       | El veredicto y los nombres de las pruebas que se activaron                         |
| `REPORT`        | El veredicto y una tabla de pruebas, puntos y motivos                              |
| `REPORT_IFSPAM` | Como `REPORT`, con un informe vacío para el ham                                    |
| `PROCESS`       | El veredicto y el mensaje con los encabezados `X-Spam-*`                           |
| `HEADERS`       | El veredicto y el bloque de encabezados del mensaje con los encabezados `X-Spam-*` |
| `PING`          | `PONG`                                                                             |
| `SKIP`          | Nada                                                                               |
| `TELL`          | Aprende spam o ham, con `--allow-tell`; guarda en `--out`                          |

Las peticiones comprimidas (`Compress: zlib`) se rechazan.

Los clientes de spamd tampoco envían la dirección IP del cliente, así que `--auth` y `--dnsbl` no tienen efecto. Un mensaje de más de 25 MiB (`--max-size`) recibe `65` (`EX_DATAERR`), un mensaje más corto que su `Content-length` recibe `76` (`EX_PROTOCOL`), y las conexiones que no envían nada durante 60 segundos se cierran.
