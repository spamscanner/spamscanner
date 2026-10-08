<!-- source: f33722183f00 -->

<!--
label: Postfix spamszűrő
title: Postfix spamszűrő milterrel vagy tartalomszűrővel
description: Spamszűrés Postfix-szerveren a Spam Scanner milterével vagy tartalomszűrőjével: beállítás, systemd unit, elutasítás 4xx vagy 5xx kóddal és Levélszemét mappa.
keywords: Postfix spamszűrő, Postfix milter, smtpd_milters, Postfix tartalomszűrő, Postfix antispam, spam elutasítása Postfixben, levélszemétszűrő Postfix
-->

# Postfix spamszűrő

A Spam Scanner körülbelül öt perc alatt beállítható egy Postfix-szerver szűrésére. Milterként fut, így a Postfix az SMTP-munkamenet közben minden levélről megkérdezi, és a spamet még az átvétel előtt visszautasíthatja.


## Telepítés és futtatás

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

Az `--auth` ellenőrzi az SPF-et, a DKIM-et, a DMARC-ot és az ARC-ot; a `--subject-tag` a tárgyban jelöli meg a spamet. Minden levél `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` és `X-Spam-Action` fejlécet kap, a feladó által beillesztett `X-Spam-*` fejléceket pedig előbb eltávolítja.


## A Postfix csatlakoztatása

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

A `milter_default_action = accept` szűrés nélkül átengedi a leveleket, ha a milter nem fut; a `tempfail` ehelyett újrapróbálkozásra kéri a feladókat.


## A spam visszautasítása az SMTP-munkamenet közben

```sh
spamscanner milter --port 7831 --auth --reject
```

Az elutasítási küszöböt (15 pont) elérő leveleket `451 4.7.1 Message rejected as spam` válasszal utasítja vissza. A 451 ideiglenes: a feladó megtartja a levelet, és újra próbálkozik, így egy rossz döntés késést okoz, nem elveszett levelet. Ha az eredmények megfelelőnek tűnnek, a `--reject-code 550` véglegessé teszi az elutasítást.


## Milter nélkül

A tartalomszűrő azután fut, hogy a Postfix átvett egy levelet: a Postfix továbbítja a `spamscanner filter` parancsnak, amely hozzáadja a fejléceket, és visszaadja. A munkamenet közben soha semmi nem kerül visszautasításra, hiba esetén pedig a kézbesítés mindig elhalasztódik ahelyett, hogy a levél visszapattanna. [A tartalomszűrő beállítása](../../docs/postfix.md#content-filter)


## A spam a Levélszemét mappába

Dovecottal egy Sieve-szabály helyezi át a megjelölt leveleket:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Valódi Postfixszel tesztelve

A projekt végpontok közötti tesztjei a milterrel és a tartalomszűrővel futtatják a Postfixet: a ham fejlécekkel és a hamisított `X-Spam-Flag` eltávolításával kerül kézbesítésre, a spam megjelölést kap, a GTUBE-ot pedig az SMTP-munkamenet közben 550-es kóddal utasítja vissza.

Következő lépés: [a teljes Postfix- és Sendmail-útmutató](../../docs/postfix.md) systemd unittal és a Sendmail `INPUT_MAIL_FILTER` beállításával.
