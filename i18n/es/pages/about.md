<!-- source: 599bd320e55a -->

<!--
label: Acerca de
title: Acerca de Spam Scanner, su licencia y la privacidad
description: Quién hace Spam Scanner, cómo informar de un error o una vulnerabilidad, su licencia y qué recoge este sitio web: ni cookies ni analítica.
keywords: acerca de Spam Scanner, Forward Email, licencia de Spam Scanner, BUSL-1.1, contacto Spam Scanner, privacidad Spam Scanner
-->

# Acerca de Spam Scanner

Spam Scanner es un filtro de spam para correo hecho por [Forward Email](https://forwardemail.net), el servicio de correo centrado en la privacidad, que lo creó para sus propios servidores de correo. El código fuente, las incidencias y las versiones están en [GitHub](https://github.com/spamscanner/spamscanner), y el paquete en [npm](https://www.npmjs.com/package/spamscanner).


## Quién lo hace

El equipo de Forward Email escribe y mantiene Spam Scanner. Forward Email no guarda registros del contenido de los mensajes, así que no podía enviar el correo a un servicio de filtrado externo: el filtro tenía que funcionar en sus propios servidores y explicar cada decisión sin que una persona leyera el correo. [Cómo lo usa Forward Email](../../docs/forward-email.md)

Forward Email también es de código abierto, en [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Su fundador fue uno de los primeros empleados de DuckDuckGo.


## Contacto

* **Preguntas, errores y peticiones de funciones:** abre una incidencia en [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Vulnerabilidades de seguridad:** infórmalas en privado mediante [el aviso de vulnerabilidades de GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), no en incidencias públicas. La misma dirección está en [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Otras licencias:** contacta con [Forward Email](https://forwardemail.net).


## Términos de la licencia

La [licencia](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) de Spam Scanner es la Business Source License 1.1, con la Apache License 2.0 como Change License. La Change Date que indica la licencia ya pasó, y desde esa fecha la licencia te concede derechos según la Apache License 2.0.


## Privacidad

Este sitio web no usa cookies ni carga analítica, rastreadores, anuncios, fuentes ni scripts de otros sitios. Todos los archivos vienen de spamscanner.net.

* El tema, el idioma que eliges y el servidor de Mastodon al que compartes se guardan en el almacenamiento local de tu navegador y no se envían a ningún sitio.
* El vídeo solo se carga cuando lo reproduces.
* Los enlaces para compartir son enlaces normales, así que nada de esas redes se carga hasta que sigues uno.
* El sitio está alojado en GitHub Pages, y GitHub registra la dirección IP de cada visitante por motivos de seguridad. Consulta [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) y la [declaración de privacidad de GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Qué envía el software

Spam Scanner no envía telemetría ni busca actualizaciones. Por defecto consulta los nombres de host de los enlaces de un mensaje en los resolvedores DNS con filtrado de Cloudflare, y nada más sale de la máquina. Sus otras comprobaciones de red están desactivadas hasta que las actives. [Seguridad y privacidad](../../docs/security.md)


## Versiones

GitHub Actions compila los binarios independientes a partir del repositorio público. Cada versión lista sus hashes en un archivo `SHA256SUMS`, que comprueba el script de instalación, y cada binario lleva una atestación de procedencia de compilación firmada. Las versiones y sus notas están en [GitHub](https://github.com/spamscanner/spamscanner/releases).
