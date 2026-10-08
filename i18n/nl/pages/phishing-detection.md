<!-- source: 0378a5e0f12b -->

<!--
label: Phishingdetectie
title: Phishingdetectie: lookalike-domeinen, misleidende links, spoofing
description: Hoe Spam Scanner phishingmail herkent: Unicode-lookalike-domeinen, misleidende links, merknamen als afzender, de malware-resolver van Cloudflare en DMARC.
keywords: phishing detectie, phishing herkennen, phishingfilter e-mail, homograafaanval, IDN homograph, lookalike domein detectie, misleidende link, merkimitatie e-mail
-->

# Phishingdetectie voor e-mail

Phishing werkt door zich voor te doen als iemand anders. Spam Scanner controleert de plekken waar de vermomming zichtbaar wordt.


## Lookalike-domeinen

Elk domein in een link wordt met de Unicode-tabel van verwarrende tekens tot een skelet teruggebracht en vergeleken met bijna 100 merken die vaak worden nagebootst:

| Domein                              | Herkend als                          |
| ----------------------------------- | ------------------------------------ |
| `pаypal.com` (Cyrillische а)        | Verwarrende tekens                   |
| `paypa1-secure.top`                 | Verwisselde tekens                   |
| `xn--pple-43d.com`                  | Punycode voor `аpple.com`            |
| `paypal.com.account-verify.example` | Merk in het domein van iemand anders |
| `paypall.com`                       | Eén letter verschil                  |

Merken kunnen worden toegevoegd, en domeinen die van jou zijn, kunnen op de allowlist.


## Misleidende links

Een HTML-link waarvan de tekst het ene adres is en het doel een ander, zoals de tekst `https://www.paypal.com/signin` die naar `http://paypa1-secure.top/login` wijst, voegt 3 punten toe.


## Weergavenamen en spoofing

* Een weergavenaam met een merk erin („PayPal Security”) vanaf een adres op een ander domein.
* Een weergavenaam met een ander e-mailadres erin.
* Mail die zegt van het eigen domein van de ontvanger te komen en niet slaagt voor SPF, DKIM en DMARC.


## Bekende kwaadaardige sites

Linkhosts worden opgezocht op de resolver 1.1.1.2 van Cloudflare, die bekende malware- en phishingsites blokkeert, en optioneel op domeinblocklists zoals Spamhaus DBL.


## Bijlagen

Phishing komt ook binnen als HTML-bijlagen die offline een nep-inlogpagina tonen, en als uitvoerbare bestanden die zijn hernoemd naar `.pdf`. Beide worden aan hun inhoud herkend.

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

[Hoe de controles werken](../../docs/how-it-works.md#phishing)
