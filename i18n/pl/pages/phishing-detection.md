<!-- source: 0378a5e0f12b -->

<!--
label: Wykrywanie phishingu
title: Wykrywanie phishingu w e-mailach: podobne domeny i mylące linki
description: Jak Spam Scanner wykrywa phishing: podobne domeny Unicode, linki pokazujące inny adres niż cel, marki w nazwach nadawców, resolver Cloudflare i DMARC.
keywords: wykrywanie phishingu, filtr phishingu e-mail, atak homograficzny, homograf IDN, wykrywanie podobnych domen, fałszywe linki, podszywanie się pod markę e-mail
-->

# Wykrywanie phishingu w poczcie e-mail

Phishing działa, bo udaje kogoś innego. Spam Scanner sprawdza miejsca, w których widać przebranie.


## Podobne domeny

Każda domena w linku jest sprowadzana do szkieletu za pomocą tabeli confusables Unicode i porównywana z prawie 100 często podrabianymi markami:

| Domena                              | Rozpoznana jako          |
| ----------------------------------- | ------------------------ |
| `pаypal.com` (cyrylickie а)         | Mylące podobne znaki     |
| `paypa1-secure.top`                 | Zamienione znaki         |
| `xn--pple-43d.com`                  | Punycode dla `аpple.com` |
| `paypal.com.account-verify.example` | Marka w cudzej domenie   |
| `paypall.com`                       | Jedna litera różnicy     |

Można dodawać marki, a własne domeny dodać do listy dozwolonych.


## Mylące linki

Link HTML, którego tekst to jeden adres, a cel to inny, na przykład tekst `https://www.paypal.com/signin` wskazujący na `http://paypa1-secure.top/login`, dodaje 3 punkty.


## Nazwy wyświetlane i podszywanie się

* Nazwa wyświetlana zawierająca markę („PayPal Security”) z adresu w innej domenie.
* Nazwa wyświetlana zawierająca inny adres e-mail.
* Poczta rzekomo pochodząca z własnej domeny odbiorcy, która nie przechodzi SPF, DKIM i DMARC.


## Znane szkodliwe witryny

Hosty z linków są sprawdzane w resolverze Cloudflare 1.1.1.2, który blokuje znane witryny ze złośliwym oprogramowaniem i phishingiem, a opcjonalnie na czarnych listach domen, takich jak Spamhaus DBL.


## Załączniki

Phishing przychodzi też jako załączniki HTML, które offline rysują fałszywą stronę logowania, oraz jako pliki wykonywalne przemianowane na `.pdf`. Jedno i drugie jest rozpoznawane po zawartości.

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

[Jak działają kontrole](../../docs/how-it-works.md#phishing)
