<!-- source: c56969e779c4 -->

# A Spam Scanner dokumentációja

A Spam Scanner spamszűrő Node.js-hez és a parancssorhoz, a forráskódja a GitHubon érhető el. Beolvas egy nyers e-mail-üzenetet, és bármilyen nyelven eldönti, hogy spam, adathalászat, csalás, vagy kártevőt tartalmaz-e. Futhat könyvtárként, parancssori eszközként, Postfix- vagy Sendmail-milterként, Postfix-tartalomszűrőként, SpamAssassin-kompatibilis spamd szerverként, HTTP API-ként vagy TCP-szerverként.

A [Forward Email](https://forwardemail.net) fejleszti a saját levelezőszerverei számára.


## Hogyan születik a döntés egy levélről

Minden ellenőrzés pontot ad hozzá vagy von le. Az összeg dönti el az eredményt:

| Pontszám       | Művelet  | Mit tesz a levelezőszerver               |
| -------------- | -------- | ---------------------------------------- |
| 5 alatt        | `accept` | Kézbesíti a levelet                      |
| 5 és 14,9 közt | `tag`    | Spamként megjelölve kézbesíti            |
| 15 vagy több   | `reject` | Az SMTP-munkamenet közben visszautasítja |

Mindkét küszöb módosítható. Minden eredmény felsorolja a teljesült teszteket a pontjaikkal és az okukkal együtt, így egy döntés mindig megindokolható.

Az ellenőrzések:

* **Egy tanított osztályozó** bármilyen írásrendszerben olvassa a levél szavait, a hivatkozásai felépítését, a feladóját és a mellékleteit. Nyilvános adatkészleteken tanítva érkezik, és a saját levelekből is tanul. [Hogyan működik az osztályozó](how-it-works.md#the-classifier)
* **Az adathalászat-ellenőrzések** kiszűrik a hasonmás domaineket (`paypa1.com`, `pаypal.com` cirill а-val), az olyan hivatkozásokat, amelyek szövege egy címet mutat, a célja pedig egy másik, valamint az egy márka nevében fellépő megjelenített neveket. [Adathalászat](how-it-works.md#phishing)
* **A mellékletek ellenőrzése** felismeri a futtatható fájlokat, a dokumentumnak átnevezett futtatható fájlokat, a dupla kiterjesztéseket, a jobbról balra író fájlnévtrükköket, a ZIP-fájlokban lévő futtatható fájlokat, az Office-makrókat és az aktív PDF-tartalmat. A ClamAV vírusokat kereshet a mellékletekben. [Mellékletek](how-it-works.md#attachments)
* **Hitelesítés**: SPF, DKIM, DMARC és ARC, ha a kliens IP-címe ismert. [Hitelesítés](how-it-works.md#authentication)
* **DNS-tiltólisták** a kliens IP-címére és a hivatkozásokban szereplő domainekre, valamint a Cloudflare szűrő DNS-feloldói az ismert kártevő- és felnőtt oldalakra. [Tiltólisták](how-it-works.md#blocklists)
* **Szabályok** olyan mintákra, amelyeket egyetlen osztályozónak sem kell megtanulnia: a GTUBE tesztkarakterlánc, szextorziós tárgysorok, PayPal-számlás csalások, önhamisítás és MI-szűrőknek elrejtett utasítások. [Szabályok](scoring.md#rules)
* **Egy nyelvi modell**, opcionálisan, második véleményt ad a kétes esetekben: helyi modell Ollamán vagy bármely OpenAI-kompatibilis szerveren keresztül, vagy a Claude, a ChatGPT, a Gemini és mások. [Nyelvi modellek](llm.md)


## Hol érdemes kezdeni

* [Első lépések](getting-started.md): telepítés és az első levél vizsgálata.
* [Parancssor](cli.md): minden parancs és kapcsoló.
* [Postfix és Sendmail](postfix.md): levelezőszerver szűrése a milterrel vagy tartalomszűrővel.
* [Más levelezőszerverek](mail-servers.md): Exim, Haraka, Dovecot, procmail és bármi, ami HTTP API-t tud hívni.
* [Tanítás](training.md): tanítás a saját leveleken és az eredmény mérése.
* [Nyelvi modellek](llm.md): szolgáltatók, ajánlott nyílt modellek, adatvédelem és prompt injection.
* [Nyelvek](languages.md): hogyan olvassa a kínait, az arabot, a thait és minden más írásrendszert.
* [Forward Email](forward-email.md): hogyan használja a Forward Email, és frissítés az 5-ös vagy 6-os verzióról.
* [API-referencia](api.md) és [tesztek és pontszámok](scoring.md).
* [Biztonság és adatvédelem](security.md): mi hagyja el a gépet, és hogyan lehet ezt megakadályozni.
