<!-- source: 0378a5e0f12b -->

<!--
label: Oppdage phishing
title: Phishing i e-post: forvekslingsdomener og villedende lenker
description: Slik oppdager Spam Scanner phishing: forvekslbare Unicode-domener, villedende lenker, merkenavn i visningsnavn, Cloudflares resolver mot skadevare og DMARC.
keywords: oppdage phishing, phishingfilter e-post, nettfiske, homografangrep, IDN-homograf, forvekslingsdomene, villedende lenke, etterligning av merkenavn
-->

# Oppdage phishing i e-post

Phishing virker ved å se ut som noen andre. Spam Scanner sjekker stedene der forkledningen synes.


## Forvekslingsdomener

Hvert domene i en lenke reduseres til et skjelett med Unicode-tabellen over forvekslbare tegn og sammenlignes med nesten 100 merkenavn som ofte etterlignes:

| Domene                              | Fanget som                     |
| ----------------------------------- | ------------------------------ |
| `pаypal.com` (kyrillisk а)          | Forvekslbare tegn              |
| `paypa1-secure.top`                 | Ombyttede tegn                 |
| `xn--pple-43d.com`                  | Punycode for `аpple.com`       |
| `paypal.com.account-verify.example` | Merkenavn i noen andres domene |
| `paypall.com`                       | Én bokstav unna                |

Merkenavn kan legges til, og domener du eier, kan settes på tillatelseslisten.


## Villedende lenker

En HTML-lenke der teksten er én adresse og målet en annen, for eksempel teksten `https://www.paypal.com/signin` som peker til `http://paypa1-secure.top/login`, gir 3 poeng.


## Visningsnavn og forfalskning

* Et visningsnavn som inneholder et merkenavn («PayPal Security»), fra en adresse på et annet domene.
* Et visningsnavn som inneholder en annen e-postadresse.
* E-post som utgir seg for å komme fra mottakerens eget domene og ikke består SPF, DKIM og DMARC.


## Kjente skadelige nettsteder

Vertene i lenker slås opp på Cloudflares resolver 1.1.1.2, som blokkerer kjente nettsteder for skadevare og phishing, og eventuelt på domeneblokkeringslister som Spamhaus DBL.


## Vedlegg

Phishing kommer også som HTML-vedlegg som tegner en falsk innloggingsside uten nett, og som kjørbare filer omdøpt til `.pdf`. Begge finnes ut fra innholdet.

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

[Slik virker sjekkene](../../docs/how-it-works.md#phishing)
