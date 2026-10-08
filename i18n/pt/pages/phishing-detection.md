<!-- source: 0378a5e0f12b -->

<!--
label: Detecção de phishing
title: Detecção de phishing: domínios parecidos, links falsos e spoofing
description: Como o Spam Scanner detecta phishing: domínios parecidos em Unicode, links que levam a outro endereço, marcas no remetente, resolvedor da Cloudflare e DMARC.
keywords: detecção de phishing, filtro de phishing para e-mail, ataque homográfico, homógrafo IDN, detecção de domínio parecido, link enganoso, falsificação de marca em e-mail
-->

# Detecção de phishing em e-mails

O phishing funciona se parecendo com outra pessoa. O Spam Scanner verifica os lugares onde o disfarce aparece.


## Domínios parecidos

Cada domínio de um link é reduzido a um esqueleto com a tabela de caracteres confundíveis do Unicode e comparado com quase 100 marcas imitadas com frequência:

| Domínio                             | Detectado como                   |
| ----------------------------------- | -------------------------------- |
| `pаypal.com` (а cirílico)           | Caracteres confundíveis          |
| `paypa1-secure.top`                 | Caracteres trocados              |
| `xn--pple-43d.com`                  | Punycode de `аpple.com`          |
| `paypal.com.account-verify.example` | Marca no domínio de outra pessoa |
| `paypall.com`                       | A uma letra de distância         |

É possível adicionar marcas, e os domínios que são seus podem entrar em uma lista de permissão.


## Links enganosos

Um link HTML cujo texto é um endereço e cujo destino é outro, como o texto `https://www.paypal.com/signin` apontando para `http://paypa1-secure.top/login`, adiciona 3 pontos.


## Nomes de exibição e falsificação

* Um nome de exibição que contém uma marca (“PayPal Security”) vindo de um endereço de outro domínio.
* Um nome de exibição que contém um endereço de e-mail diferente.
* Um e-mail que alega vir do próprio domínio do destinatário e falha em SPF, DKIM e DMARC.


## Sites maliciosos conhecidos

Os hosts dos links são consultados no resolvedor 1.1.1.2 da Cloudflare, que bloqueia sites conhecidos de malware e phishing, e, opcionalmente, em listas de bloqueio de domínios como a Spamhaus DBL.


## Anexos

O phishing também chega como anexos HTML que desenham uma página de login falsa offline e como executáveis renomeados para `.pdf`. Os dois são encontrados pelo conteúdo.

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

[Como as verificações funcionam](../../docs/how-it-works.md#phishing)
