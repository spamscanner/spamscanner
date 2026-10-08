<!-- source: 0378a5e0f12b -->

<!--
label: Adathalászat felismerése
title: Adathalász e-mailek felismerése: hasonmás domainek, csaló linkek
description: Hogyan ismeri fel a Spam Scanner az adathalász e-maileket: Unicode hasonmás domainek, megtévesztő hivatkozások, márkanevek, Cloudflare-szűrés és DMARC.
keywords: adathalászat felismerése, adathalász e-mail szűrő, phishing szűrő, homográf támadás, IDN homográf, hasonmás domain felismerése, megtévesztő link, márkahamisítás e-mail
-->

# Adathalász e-mailek felismerése

Az adathalászat úgy működik, hogy valaki másnak tűnik. A Spam Scanner azokat a pontokat ellenőrzi, ahol az álca kilátszik.


## Hasonmás domainek

A hivatkozásokban szereplő minden domaint a Unicode confusables táblázatával egy vázra egyszerűsít, és összeveti közel 100 gyakran utánzott márkával:

| Domain                              | Minek ismeri fel               |
| ----------------------------------- | ------------------------------ |
| `pаypal.com` (cirill а)             | Összetéveszthető karakterek    |
| `paypa1-secure.top`                 | Felcserélt karakterek          |
| `xn--pple-43d.com`                  | Az `аpple.com` Punycode-alakja |
| `paypal.com.account-verify.example` | Márka valaki más domainjében   |
| `paypall.com`                       | Egy betű eltérés               |

Márkák adhatók hozzá, a saját domainek pedig engedélyezőlistára tehetők.


## Megtévesztő hivatkozások

Az a HTML-hivatkozás, amelynek szövege egy cím, a célja pedig egy másik, például a `https://www.paypal.com/signin` szöveg, amely a `http://paypa1-secure.top/login` címre mutat, 3 pontot ad hozzá.


## Megjelenített nevek és hamisítás

* Márkanevet tartalmazó megjelenített név („PayPal Security”) egy másik domainhez tartozó címről.
* Egy másik e-mail-címet tartalmazó megjelenített név.
* A címzett saját domainjéről érkezőnek mondott levél, amely elbukik az SPF-, DKIM- és DMARC-ellenőrzésen.


## Ismert rosszindulatú oldalak

A hivatkozások gépneveit lekérdezi a Cloudflare 1.1.1.2-es DNS-feloldóján, amely blokkolja az ismert kártevő- és adathalász oldalakat, valamint opcionálisan olyan domain-tiltólistákon, mint a Spamhaus DBL.


## Mellékletek

Az adathalászat HTML-mellékletként is érkezik, amely offline rajzol ki egy hamis bejelentkezési oldalt, valamint `.pdf` kiterjesztésre átnevezett futtatható fájlként. Mindkettőt a tartalma alapján ismeri fel.

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

[Hogyan működnek az ellenőrzések](../../docs/how-it-works.md#phishing)
