<!-- source: 0378a5e0f12b -->

<!--
label: Detekce phishingu
title: Detekce phishingu: podobné domény, klamavé odkazy a podvrhování
description: Jak Spam Scanner odhaluje phishing: podobné domény v Unicode, odkazy vedoucí jinam, než ukazují, jména značek, resolver Cloudflare proti malwaru a DMARC.
keywords: detekce phishingu, phishingový filtr e-mailu, ochrana proti phishingu, homografický útok, IDN homograf, podobné domény, klamavý odkaz, zneužití značky v e-mailu
-->

# Detekce phishingu v e-mailu

Phishing funguje tak, že vypadá jako někdo jiný. Spam Scanner kontroluje místa, kde se přestrojení prozradí.


## Podobně vypadající domény

Každá doména v odkazu se pomocí tabulky zaměnitelných znaků Unicode zredukuje na kostru a porovná se s téměř 100 často napodobovanými značkami:

| Doména                              | Zachycena jako           |
| ----------------------------------- | ------------------------ |
| `pаypal.com` (cyrilické а)          | Zaměnitelné znaky        |
| `paypa1-secure.top`                 | Prohozené znaky          |
| `xn--pple-43d.com`                  | Punycode pro `аpple.com` |
| `paypal.com.account-verify.example` | Značka v cizí doméně     |
| `paypall.com`                       | Liší se jedním písmenem  |

Značky lze přidávat a domény, které vlastníte, lze zařadit na seznam povolených.


## Klamavé odkazy

Odkaz v HTML, jehož text je jedna adresa a cíl jiná, například text `https://www.paypal.com/signin` vedoucí na `http://paypa1-secure.top/login`, přidá 3 body.


## Zobrazovaná jména a podvrhování

* Zobrazované jméno obsahující značku („PayPal Security“) z adresy v jiné doméně.
* Zobrazované jméno obsahující jinou e-mailovou adresu.
* Pošta, která tvrdí, že přichází z vlastní domény příjemce, a neprojde SPF, DKIM a DMARC.


## Známé škodlivé weby

Hostitelé z odkazů se vyhledávají na resolveru Cloudflare 1.1.1.2, který blokuje známé weby s malwarem a phishingem, a volitelně na blocklistech domén jako Spamhaus DBL.


## Přílohy

Phishing přichází také jako přílohy HTML, které offline vykreslí falešnou přihlašovací stránku, a jako spustitelné soubory přejmenované na `.pdf`. Obojí se rozpozná podle obsahu.

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

[Jak kontroly fungují](../../docs/how-it-works.md#phishing)
