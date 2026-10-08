<!-- source: 0378a5e0f12b -->

<!--
label: Detección de phishing
title: Detección de phishing: dominios parecidos, enlaces engañosos
description: Cómo detecta Spam Scanner el phishing: dominios Unicode parecidos, enlaces que llevan a otra dirección, marcas en nombres visibles, Cloudflare y DMARC.
keywords: detección de phishing, filtro de phishing para correo, ataque homográfico, homógrafo IDN, detección de dominios parecidos, enlace engañoso, suplantación de marca por correo
-->

# Detección de phishing en el correo electrónico

El phishing funciona haciéndose pasar por otra persona. Spam Scanner revisa los lugares donde se nota el disfraz.


## Dominios parecidos

Cada dominio de un enlace se reduce a un esqueleto con la tabla de caracteres confundibles de Unicode y se compara con casi 100 marcas suplantadas con frecuencia:

| Dominio                             | Se detecta como                     |
| ----------------------------------- | ----------------------------------- |
| `pаypal.com` (а cirílica)           | Caracteres confundibles             |
| `paypa1-secure.top`                 | Caracteres cambiados                |
| `xn--pple-43d.com`                  | Punycode de `аpple.com`             |
| `paypal.com.account-verify.example` | Marca en el dominio de otra persona |
| `paypall.com`                       | A una letra de distancia            |

Se pueden añadir marcas, y los dominios propios se pueden añadir a la lista de permitidos.


## Enlaces engañosos

Un enlace HTML cuyo texto es una dirección y cuyo destino es otra, como el texto `https://www.paypal.com/signin` apuntando a `http://paypa1-secure.top/login`, suma 3 puntos.


## Nombres visibles y suplantación

* Un nombre visible que contiene una marca («PayPal Security») desde una dirección de otro dominio.
* Un nombre visible que contiene una dirección de correo electrónico distinta.
* Correo que dice venir del propio dominio del destinatario y no supera SPF, DKIM ni DMARC.


## Sitios maliciosos conocidos

Los hosts de los enlaces se consultan en el resolutor 1.1.1.2 de Cloudflare, que bloquea los sitios de malware y phishing conocidos, y opcionalmente en listas de bloqueo de dominios como Spamhaus DBL.


## Adjuntos

El phishing también llega como adjuntos HTML que dibujan una página de inicio de sesión falsa sin conexión, y como ejecutables renombrados a `.pdf`. Ambos se detectan por su contenido.

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

[Cómo funcionan las comprobaciones](../../docs/how-it-works.md#phishing)
