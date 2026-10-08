<!-- source: 60f00f92b5aa -->

# Seguridad y privacidad

Spam Scanner lee correo, que es privado, de remitentes, que pueden ser hostiles. Esta página enumera qué envía a cualquier sitio y cómo trata lo que lee.


## Qué sale de la máquina

De forma predeterminada, una sola cosa: los **nombres de host de los enlaces** de un mensaje se consultan en los resolutores de filtrado de Cloudflare, 1.1.1.2 y 1.0.0.2 (malware y phishing) y 1.1.1.3 y 1.0.0.3 (también contenido para adultos). Son consultas DNS normales de nombres como `example.com`; no se envía ninguna parte del mensaje ni de sus direcciones. Desactívalas con `phishing: {cloudflare: false}` o `--no-cloudflare`, o solo la comprobación de contenido para adultos con `phishing: {adult: false}`.

Todo lo demás está desactivado hasta que se configura:

| Comprobación        | Envía                                                                                     | A                                                                                               |
| ------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `authentication`    | Consultas DNS de los registros SPF, DKIM, DMARC y ARC del remitente                       | Tu resolutor, o `dnsServers`                                                                    |
| `dnsbl`             | La dirección IP del cliente, invertida, y los dominios de los enlaces, como consultas DNS | Los servidores de nombres de las listas de bloqueo, a través de tu resolutor o de `dns.servers` |
| `llm`               | Un resumen del mensaje, sin los datos personales en el caso de los proveedores remotos    | El servidor de modelo de lenguaje que indiques ([privacidad](llm.md#privacy))                   |
| `reputation.apiUrl` | La dirección IP, el dominio y la dirección del remitente                                  | El servicio que indiques                                                                        |
| `clamav`            | Los adjuntos                                                                              | Tu clamd, a través de su socket                                                                 |

No hay telemetría, ni comprobación de actualizaciones, ni descargas durante la ejecución. El modelo viene dentro del paquete.


## Qué guarda

Nada, salvo que se le pida. Los análisis no se registran ni se almacenan. `learn()` cambia el clasificador en memoria; solo se escribe en disco con `saveModel()`, `spamscanner learn` o la opción `--out` de los servidores. Un archivo de modelo contiene recuentos de características convertidos con hash, no palabras ni texto de los mensajes.

Las respuestas del modelo de lenguaje se guardan en caché en memoria, con un hash de lo que se envió como clave, así que sobre las copias repetidas del mismo mensaje se consulta una sola vez. Las respuestas DNS se guardan en caché en memoria durante diez minutos.


## Entrada hostil

* Los adjuntos se identifican por sus bytes; nunca se ejecutan ni los abre otro programa. Los archivos ZIP se leen desde su directorio central, con un límite en el número de entradas; los archivos anidados no se descomprimen.
* El texto del cuerpo se lee hasta `maxLength` (100 000 caracteres) y los servidores aceptan mensajes de hasta 25 MB.
* Cada comprobación de red tiene un tiempo límite (`timeout`, 10 segundos de forma predeterminada). Una comprobación que falla o agota su tiempo se omite y el análisis termina sin ella.
* El milter, el filtro de contenido y `--headers` eliminan los encabezados `X-Spam-*` que ya traiga un mensaje, así que los remitentes no pueden marcar su propio correo como limpio.
* En los encabezados de veredicto de spam de Microsoft solo se confía cuando el mensaje llegó directamente de los servidores de Microsoft, y los encabezados Received nunca se usan para decidir de dónde vino un mensaje.
* El texto dirigido a filtros de IA se puntúa como spam, y al modelo de lenguaje se le indica que el mensaje son datos, no instrucciones. [Inyección de instrucciones](llm.md#prompt-injection)


## Servidores

Los servidores milter, HTTP, TCP y spamd escuchan en 127.0.0.1 salvo que `--host` indique otra cosa. La API HTTP compara su token en tiempo constante y rechaza `/learn` si no hay uno. Ninguno habla TLS: para acceder a ellos a través de una red, usa una red privada, un túnel SSH o un proxy inverso con TLS.

Ejecútalos con un usuario sin privilegios. La [unidad de systemd de la guía de Postfix](postfix.md#1-run-the-milter) añade el refuerzo de seguridad habitual.


## Informar de una vulnerabilidad

Informa de los problemas de seguridad de forma privada a través del [sistema de informe de vulnerabilidades de GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), no en issues públicas.
