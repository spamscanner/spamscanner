<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner lo desarrolló [Forward Email](https://forwardemail.net), el servicio de correo electrónico de código abierto y centrado en la privacidad, para sus propios servidores de correo. Forward Email no guarda registros del contenido de los mensajes, así que ningún servicio de filtrado externo servía: el filtro tenía que ejecutarse en sus propios servidores y tenía que explicar cada decisión sin que una persona leyera el correo.

Esta página muestra cómo lo usa un servidor de correo como el de Forward Email y qué cambió para el código escrito para Spam Scanner 5 o 6.


## En un servidor de correo entrante

Forward Email recibe el correo con [smtp-server](https://nodemailer.com/extras/smtp-server/). El patrón, para cualquier servidor basado en él:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()` acepta directamente el flujo SMTP. Si ya tienes a mano los resultados de [mailauth](https://github.com/postalsys/mailauth), omite `authentication` y pasa solo la dirección IP.

Una respuesta 421 o 451 hace que el servidor remitente ponga el mensaje en cola y vuelva a intentarlo más tarde. Las reglas de rechazo nuevas pueden empezar con un código temporal y pasar a 550 cuando se hayan revisado sus resultados, sin perder correo entretanto.


## Actualizar desde la versión 5 o 6

La versión 7 es una reescritura. El constructor, `scan()` y los campos del resultado que lee el código de las versiones 5 y 6 siguen funcionando; cambiaron el clasificador, el modelo y las comprobaciones opcionales de TensorFlow.

### Lo que sigue igual

* `new SpamScanner(options)` y `await scanner.scan(source)`.
* `require('spamscanner')` devuelve la clase, y `import SpamScanner from 'spamscanner'` funciona.
* `result.isSpam`, `result.message` y `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` y `.idnHomographAttack`.
* Cada elemento de `results.phishing`, `.executables`, `.arbitrary` y `.viruses` se convierte en el mismo tipo de cadena de mensaje que antes (`String(item)`, plantillas literales, `message.includes('adult-related content')`). Ahora son objetos con `type`, `message` y detalles.
* `getTokensAndMailFromSource()`, `getClassification()` y `getTokens()`.
* Estas opciones se corresponden con sus nombres nuevos: `clamscan` con `clamav`, `enableMacroDetection: false` con `macros: false`, `enableArbitraryDetection: false` con `arbitrary: false`, `enableAuthentication` junto con `authOptions` con `authentication` y `session`, `enableReputation` junto con `reputationOptions.apiUrl` con `reputation`, `strictIDNDetection` con `phishing.homograph.strictMode`, y `allowlist` y `denylist`. `logger` y `memoize` se aceptan y se ignoran.

### Lo que cambió

| Antes                                                                                               | Ahora                                                                                                                                                                       |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` leía el archivo                                                          | Una cadena es texto del mensaje. Usa `scanFile(path)` o pasa un Buffer                                                                                                      |
| Un modelo bayesiano ingenuo de palabras (`classifier.json`), que ya no se puede cargar              | Un clasificador y un formato de modelo nuevos; vuelve a entrenar con `spamscanner train` ([entrenamiento](training.md))                                                     |
| Las comprobaciones de toxicidad y NSFW cargaban modelos de TensorFlow desde la red en el primer uso | Aporta tu propio modelo: `toxicity: {model}` y `nsfw: {model}` aceptan cualquier objeto con un método `classify()`, por ejemplo de `@tensorflow-models/toxicity` y `nsfwjs` |
| `results.arbitrary` enumeraba cada patrón que coincidía                                             | Enumera las reglas lo bastante fuertes para marcar spam por sí solas; todas las reglas están en `result.tests`                                                              |
| Una respuesta de sí o no                                                                            | `result.score`, `result.action` (`accept`, `tag` o `reject`) y `result.tests`, cada una con puntos y un motivo                                                              |
| `isSpam` lo decidía el clasificador o cualquier comprobación individual                             | `isSpam` es una puntuación de 5 o más; los umbrales y los puntos se pueden cambiar                                                                                          |
| Comprobaciones de reputación contra un servicio de Forward Email                                    | Un servicio de reputación genérico, desactivado salvo que se defina `reputation.apiUrl`                                                                                     |

### Lo nuevo

* [Modelos de lenguaje](llm.md) para los casos dudosos, locales o alojados.
* SPF, DKIM, DMARC y ARC; listas de bloqueo DNS; los resolutores de filtrado de Cloudflare.
* Comprobaciones de adjuntos por su contenido: ejecutables disfrazados, archivos comprimidos, macros, PDF activos.
* Un [milter, una API HTTP, un servidor TCP y un servidor spamd](mail-servers.md), y una [línea de comandos](cli.md).
* Entrenamiento, evaluación y aprendizaje a partir de denuncias, desde la línea de comandos o la API.
