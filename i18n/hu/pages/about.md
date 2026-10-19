<!-- source: 599bd320e55a -->

<!--
label: Névjegy
title: A Spam Scanner, a licenc és az adatvédelem
description: Ki készíti a Spam Scannert, hogyan jelenthet hibát vagy sérülékenységet, mi a licence, és mit gyűjt ez a webhely: sem sütiket, sem analitikát.
keywords: Spam Scanner névjegy, Forward Email, Spam Scanner licenc, BUSL-1.1, Spam Scanner kapcsolat, Spam Scanner adatvédelem
-->

# A Spam Scannerről

A Spam Scanner a [Forward Email](https://forwardemail.net), az adatvédelemre összpontosító levelezőszolgáltatás e-mail-spamszűrője, amelyet a saját levelezőszervereihez készített. A forráskód, a hibajegyek és a kiadások a [GitHubon](https://github.com/spamscanner/spamscanner) vannak, a csomag pedig az [npm-en](https://www.npmjs.com/package/spamscanner).


## Ki készíti

A Forward Email csapata írja és tartja karban a Spam Scannert. A Forward Email nem naplózza a levelek tartalmát, így nem küldhette a leveleket külső szűrőszolgáltatásnak: a szűrőnek a saját szerverein kellett futnia, és minden döntését úgy kellett megindokolnia, hogy ember nem olvassa a levelet. [Hogyan használja a Forward Email](../../docs/forward-email.md)

A Forward Email is nyílt forráskódú: [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Az alapítója a DuckDuckGo egyik első munkatársa volt.


## Kapcsolat

* **Kérdések, hibák és funkciókérések:** nyisson hibajegyet a [GitHubon](https://github.com/spamscanner/spamscanner/issues).
* **Biztonsági sérülékenységek:** bizalmasan jelentse őket [a GitHub sérülékenységbejelentőjén](https://github.com/spamscanner/spamscanner/security/advisories/new) keresztül, ne nyilvános hibajegyben. Ugyanez a cím szerepel a [security.txt](https://spamscanner.net/.well-known/security.txt) fájlban.
* **Más licencek:** forduljon a [Forward Emailhez](https://forwardemail.net).


## Licencfeltételek

A Spam Scanner [licence](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) a Business Source License 1.1, amelynek Change License-e az Apache License 2.0. A licencben megnevezett Change Date már elmúlt, és attól a naptól a licenc az Apache License 2.0 szerinti jogokat adja meg.


## Adatvédelem

Ez a webhely nem állít be sütiket, és nem tölt be analitikát, nyomkövetőket, hirdetéseket, betűtípusokat vagy szkripteket más webhelyekről. Minden fájl a spamscanner.net-ről érkezik.

* A téma, a választott nyelv és a Mastodon-szerver, ahová megoszt, a böngésző helyi tárolójába kerül, és sehová nem küldi el.
* A videó csak akkor töltődik be, amikor lejátssza.
* A megosztási hivatkozások egyszerű hivatkozások, így ezekből a hálózatokból semmi sem töltődik be, amíg nem követ egyet.
* A webhelyet a GitHub Pages szolgálja ki, és a GitHub biztonsági okokból naplózza minden látogató IP-címét. Lásd: [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) és a [GitHub adatvédelmi nyilatkozata](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Mit küld a szoftver

A Spam Scanner nem küld telemetriát, és nem keres frissítéseket. Alapértelmezés szerint a levél hivatkozásainak gépneveit a Cloudflare szűrő DNS-feloldóinál keresi ki, és semmi más nem hagyja el a gépet. A többi hálózati ellenőrzése ki van kapcsolva, amíg be nem kapcsolja. [Biztonság és adatvédelem](../../docs/security.md)


## Kiadások

Az önálló binárisokat a GitHub Actions építi a nyilvános tárolóból. Minden kiadás egy `SHA256SUMS` fájlban sorolja fel a hash-eiket, ezt a telepítőszkript ellenőrzi, és minden bináris aláírt builderedet-igazolást hordoz. A kiadások és megjegyzéseik a [GitHubon](https://github.com/spamscanner/spamscanner/releases) vannak.
