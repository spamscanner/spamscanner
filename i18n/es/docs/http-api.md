<!-- source: faf44f093f8b -->

# API HTTP, servidor TCP y spamd


## API HTTP

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Escucha en 127.0.0.1 salvo que `--host` indique otra cosa. Con un token, todas las peticiones excepto `/health` necesitan `Authorization: Bearer <token>`. Ponlo detrás de un proxy inverso con TLS antes de exponerlo fuera de la máquina.

| Método y ruta      | Cuerpo                  | Respuesta                                                                 |
| ------------------ | ----------------------- | ------------------------------------------------------------------------- |
| `GET /health`      |                         | `{"ok": true, "version": "7.0.0"}`                                        |
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

`/check` también devuelve `X-Spam-Flag`, `X-Spam-Score` y `X-Spam-Action` como encabezados de la respuesta, así que un cliente puede decidir sin procesar el mensaje.

Los mensajes de más de 25 MB reciben `413`. Un análisis que falla recibe `500` con `{"error": "..."}`.

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
