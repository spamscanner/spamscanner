<!-- source: 0378a5e0f12b -->

<!--
label: Phishing-Erkennung
title: Phishing-Erkennung für E-Mails: Doppelgänger-Domains und Spoofing
description: Wie Spam Scanner Phishing erkennt: Unicode-Doppelgänger-Domains, irreführende Links, Marken in Anzeigenamen, der Malware-Resolver von Cloudflare und DMARC.
keywords: Phishing-Erkennung, Phishing erkennen, E-Mail Phishing-Filter, Homograph-Angriff, IDN-Homograph, Doppelgänger-Domain erkennen, irreführender Link, Markenmissbrauch E-Mail
-->

# Phishing-Erkennung für E-Mails

Phishing funktioniert, indem es aussieht wie jemand anderes. Spam Scanner prüft die Stellen, an denen die Tarnung sichtbar wird.


## Doppelgänger-Domains

Jede Domain in einem Link wird mit der Unicode-Tabelle verwechselbarer Zeichen auf ein Skelett reduziert und mit fast 100 häufig nachgeahmten Marken verglichen:

| Domain                              | Erkannt als                       |
| ----------------------------------- | --------------------------------- |
| `pаypal.com` (kyrillisches а)       | Verwechselbare Zeichen            |
| `paypa1-secure.top`                 | Vertauschte Zeichen               |
| `xn--pple-43d.com`                  | Punycode für `аpple.com`          |
| `paypal.com.account-verify.example` | Marke in der Domain eines anderen |
| `paypall.com`                       | Einen Buchstaben entfernt         |

Marken lassen sich hinzufügen, und eigene Domains lassen sich auf die Erlaubtliste setzen.


## Irreführende Links

Ein HTML-Link, dessen Text eine Adresse ist und dessen Ziel eine andere, etwa der Text `https://www.paypal.com/signin` mit Ziel `http://paypa1-secure.top/login`, addiert 3 Punkte.


## Anzeigenamen und Spoofing

* Ein Anzeigename mit einer Marke („PayPal Security“) von einer Adresse unter einer anderen Domain.
* Ein Anzeigename, der eine andere E-Mail-Adresse enthält.
* E-Mails, die vorgeben, von der eigenen Domain des Empfängers zu kommen, und SPF, DKIM und DMARC nicht bestehen.


## Bekannte schädliche Websites

Link-Hosts werden beim Resolver 1.1.1.2 von Cloudflare abgefragt, der bekannte Malware- und Phishing-Seiten blockiert, und optional bei Domain-Blocklisten wie Spamhaus DBL.


## Anhänge

Phishing kommt auch als HTML-Anhang, der offline eine gefälschte Anmeldeseite anzeigt, und als ausführbare Datei, die in `.pdf` umbenannt ist. Beides wird am Inhalt erkannt.

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

[Wie die Prüfungen funktionieren](../../docs/how-it-works.md#phishing)
