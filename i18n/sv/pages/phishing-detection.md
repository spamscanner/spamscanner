<!-- source: 0378a5e0f12b -->

<!--
label: Upptäcka nätfiske
title: Upptäck nätfiske i e-post: förväxlingsbara domäner, falska länkar
description: Spam Scanner hittar nätfiske: förväxlingsbara Unicode-domäner, länkar som leder fel, varumärken i visningsnamn, Cloudflares skyddsresolver och DMARC.
keywords: upptäcka nätfiske, nätfiskefilter e-post, phishing, homografattack, IDN-homograf, förväxlingsbara domäner, vilseledande länk, varumärkesförfalskning e-post
-->

# Upptäck nätfiske i e-post

Nätfiske fungerar genom att se ut som någon annan. Spam Scanner kontrollerar de ställen där förklädnaden syns.


## Förväxlingsbara domäner

Varje domän i en länk reduceras till ett skelett med Unicodes tabell över förväxlingsbara tecken och jämförs med nästan 100 varumärken som ofta utges för:

| Domän                               | Fångas som                     |
| ----------------------------------- | ------------------------------ |
| `pаypal.com` (kyrilliskt а)         | Förväxlingsbara tecken         |
| `paypa1-secure.top`                 | Utbytta tecken                 |
| `xn--pple-43d.com`                  | Punycode för `аpple.com`       |
| `paypal.com.account-verify.example` | Varumärke i någon annans domän |
| `paypall.com`                       | En bokstav ifrån               |

Varumärken kan läggas till, och domäner du äger kan tillåtas.


## Vilseledande länkar

En HTML-länk vars text är en adress och vars mål är en annan, till exempel texten `https://www.paypal.com/signin` som pekar på `http://paypa1-secure.top/login`, ger 3 poäng.


## Visningsnamn och förfalskning

* Ett visningsnamn som innehåller ett varumärke (”PayPal Security”) från en adress på en annan domän.
* Ett visningsnamn som innehåller en annan e-postadress.
* E-post som påstår sig komma från mottagarens egen domän och som inte klarar SPF, DKIM och DMARC.


## Kända skadliga webbplatser

Länkarnas värdar slås upp hos Cloudflares resolver 1.1.1.2, som blockerar kända webbplatser med skadlig kod och nätfiske, och valfritt i domänblocklistor som Spamhaus DBL.


## Bilagor

Nätfiske kommer också som HTML-bilagor som ritar upp en falsk inloggningssida offline, och som körbara filer som bytt namn till `.pdf`. Båda hittas genom sitt innehåll.

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

[Så fungerar kontrollerna](../../docs/how-it-works.md#phishing)
