<!-- source: 8263c06f1dab -->

# Primeros pasos

Spam Scanner necesita Node.js 18 o posterior, o nada en absoluto con el binario independiente.


## Instalación

Como herramienta de línea de comandos:

```sh
npm install --global spamscanner
spamscanner version
```

Como biblioteca en un proyecto de Node.js:

```sh
npm install spamscanner
```

Como binario independiente para Linux o macOS, con Node.js y el modelo incluidos:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Cada [versión](https://github.com/spamscanner/spamscanner/releases) incluye binarios para Linux (x64 y arm64), macOS (Intel y Apple silicon) y Windows.


## Analizar un mensaje

Guarda un mensaje como archivo (la mayoría de los programas de correo llaman a esto «Guardar como» o «Mostrar original») y analízalo:

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

El código de salida es 0 para ham, 1 para spam y 2 para un error, así que los scripts pueden usarlo directamente. `--json` imprime el resultado completo y `--headers` imprime el mensaje con los encabezados `X-Spam-*` añadidos.

Los mensajes también pueden llegar por la entrada estándar:

```sh
cat message.eml | spamscanner scan -
```


## Usarlo desde Node.js

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJS también funciona:

```js
const SpamScanner = require('spamscanner');
```

`scan()` recibe el mensaje sin procesar como Buffer, cadena, Uint8Array o flujo legible. Una cadena siempre es texto del mensaje: Spam Scanner nunca lee un archivo porque una cadena parezca una ruta. Usa `scanner.scanFile(path)` para los archivos.


## Informarle de la sesión SMTP

La dirección IP del cliente, su nombre de host verificado, el nombre HELO y el sobre hacen que el resultado sea más preciso: la autenticación necesita la dirección IP, y la regla de autosuplantación necesita los destinatarios.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

Lo mismo desde la línea de comandos:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Activar más comprobaciones

Ninguna de estas está activada de forma predeterminada, porque cada una necesita un servicio o una decisión:

| Comprobación                              | Opción de la biblioteca                          | Línea de comandos           |
| ----------------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC                     | `authentication: true`                           | `--auth`                    |
| Lista de bloqueo de IP                    | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Lista de bloqueo de dominios para enlaces | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                                    | `clamav: true` o `clamav: {socket}`              | `--clamav [socket]`         |
| Un modelo de lenguaje                     | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Listas de permitidos y bloqueados         | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

De forma predeterminada se consulta a los resolutores de filtrado de Cloudflare (1.1.1.2 para malware, 1.1.1.3 para contenido para adultos) por los hosts de los enlaces. Desactívalo con `phishing: {cloudflare: false}` o `--no-cloudflare`. [Qué sale de la máquina](security.md)

Spamhaus y algunas otras listas de bloqueo no responden a las consultas enviadas a través de resolutores públicos como 8.8.8.8 o 1.1.1.1. Úsalas con un resolutor local con caché y revisa sus condiciones de uso para tu volumen.


## Próximos pasos

* Ponlo delante de un servidor de correo: [Postfix y Sendmail](postfix.md), [otros servidores](mail-servers.md).
* Enséñale tu propio correo: [entrenamiento](training.md).
* Añade un modelo de lenguaje para los casos dudosos: [modelos de lenguaje](llm.md).
