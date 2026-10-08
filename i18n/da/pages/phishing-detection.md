<!-- source: 0378a5e0f12b -->

<!--
label: Phishing-detektion
title: Phishing-detektion: falske domæner, vildledende links og spoofing
description: Sådan fanger Spam Scanner phishing: Unicode-forvekslinger, links til en anden adresse end den viste, varemærker i navne, Cloudflares malware-resolver og DMARC.
keywords: phishing-detektion, phishingfilter e-mail, homografangreb, IDN-homograf, forvekslelige domæner, vildledende link, varemærkeefterligning e-mail
-->

# Phishing-detektion i e-mail

Phishing virker ved at ligne en anden. Spam Scanner tjekker de steder, hvor forklædningen viser sig.


## Forvekslelige domæner

Hvert domæne i et link reduceres til et skelet med Unicodes tabel over forvekslelige tegn og sammenlignes med næsten 100 varemærker, der ofte efterlignes:

| Domæne                              | Fanget som                   |
| ----------------------------------- | ---------------------------- |
| `pаypal.com` (kyrillisk а)          | Forvekslelige tegn           |
| `paypa1-secure.top`                 | Ombyttede tegn               |
| `xn--pple-43d.com`                  | Punycode for `аpple.com`     |
| `paypal.com.account-verify.example` | Varemærke i en andens domæne |
| `paypall.com`                       | Ét bogstav fra               |

Varemærker kan tilføjes, og domæner, du ejer, kan sættes på tilladelseslisten.


## Vildledende links

Et HTML-link, hvis tekst er én adresse og hvis mål er en anden, for eksempel teksten `https://www.paypal.com/signin`, der peger på `http://paypa1-secure.top/login`, lægger 3 point til.


## Visningsnavne og spoofing

* Et visningsnavn, der indeholder et varemærke (»PayPal Security«), fra en adresse på et andet domæne.
* Et visningsnavn, der indeholder en anden e-mailadresse.
* Post, der påstår at komme fra modtagerens eget domæne, og som ikke består SPF, DKIM og DMARC.


## Kendte skadelige websteder

Værter i links slås op på Cloudflares resolver 1.1.1.2, som blokerer kendte malware- og phishingwebsteder, og valgfrit på domæneblokeringslister som Spamhaus DBL.


## Vedhæftede filer

Phishing kommer også som HTML-vedhæftninger, der tegner en falsk login-side offline, og som programfiler, der er omdøbt til `.pdf`. Begge findes ud fra deres indhold.

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

[Sådan virker tjekkene](../../docs/how-it-works.md#phishing)
