<!-- source: 60f00f92b5aa -->

# Biztonság és adatvédelem

A Spam Scanner leveleket olvas, amelyek magánjellegűek, és olyan feladóktól származnak, akik ellenségesek lehetnek. Ez az oldal felsorolja, mit küld el bárhova, és hogyan kezeli, amit olvas.


## Mi hagyja el a gépet

Alapértelmezetten egyetlen dolog: a levélben lévő **hivatkozások gépneveit** lekérdezi a Cloudflare szűrő DNS-feloldóin, az 1.1.1.2-n és az 1.0.0.2-n (kártevők és adathalászat), valamint az 1.1.1.3-on és az 1.0.0.3-on (felnőtt tartalom is). Ezek hagyományos DNS-lekérdezések olyan nevekre, mint az `example.com`; a levél semmilyen része és a benne lévő címek sem kerülnek elküldésre. Kikapcsolhatók a `phishing: {cloudflare: false}` vagy a `--no-cloudflare` beállítással, csak a felnőtt tartalom ellenőrzése pedig a `phishing: {adult: false}` beállítással.

Minden más ki van kapcsolva, amíg be nem állítják:

| Ellenőrzés          | Mit küld                                                                    | Hova                                                                                   |
| ------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `authentication`    | DNS-lekérdezéseket a feladó SPF-, DKIM-, DMARC- és ARC-rekordjaira          | A saját DNS-feloldóhoz vagy a `dnsServers` szerverekhez                                |
| `dnsbl`             | A kliens fordított IP-címét és a hivatkozások domainjeit DNS-lekérdezésként | A tiltólisták névszervereihez, a saját DNS-feloldón vagy a `dns.servers` szerverein át |
| `llm`               | A levél összefoglalóját, távoli szolgáltatóknál a személyes adatok nélkül   | A megadott nyelvimodell-szerverhez ([adatvédelem](llm.md#privacy))                     |
| `reputation.apiUrl` | A feladó IP-címét, domainjét és címét                                       | A megadott szolgáltatáshoz                                                             |
| `clamav`            | A mellékleteket                                                             | A saját clamd-hez, annak socketén keresztül                                            |

Nincs telemetria, nincs frissítésellenőrzés, és futás közben nincs letöltés. A modell a csomag része.


## Mit tárol

Semmit, hacsak nem kérik. A vizsgálatokat nem naplózza és nem tárolja. A `learn()` a memóriában módosítja az osztályozót; lemezre csak a `saveModel()`, a `spamscanner learn` vagy a szerverek `--out` kapcsolója írja ki. Egy modellfájl hashelt jellemzőszámlálókat tartalmaz, nem szavakat vagy levélszöveget.

A nyelvi modell válaszai a memóriában gyorsítótárazódnak, az elküldött adatok hashével kulcsolva, így ugyanannak a levélnek az ismételt példányairól csak egyszer kérdez. A DNS-válaszok tíz percig maradnak a memóriában.


## Ellenséges bemenet

* A mellékleteket a bájtjaik alapján azonosítja, soha nem futtatja őket, és más programmal sem nyitja meg. A ZIP-archívumokat a központi könyvtárukból olvassa, a bejegyzések számának korlátozásával; a beágyazott archívumokat nem bontja ki.
* A levéltörzs szövegét legfeljebb `maxLength` (100 000 karakter) hosszig olvassa, a szerverek pedig legfeljebb 25 MB-os leveleket fogadnak.
* Minden hálózati ellenőrzésnek van időkorlátja (`timeout`, alapértelmezetten 10 másodperc). A sikertelen vagy időtúllépéssel végződő ellenőrzés kimarad, és a vizsgálat nélküle fejeződik be.
* A levélben már meglévő `X-Spam-*` fejléceket a milter, a tartalomszűrő és a `--headers` eltávolítja, így a feladók nem jelölhetik tisztának a saját levelüket.
* A Microsoft spamítélet-fejléceiben csak akkor bízik meg, ha a levél közvetlenül a Microsoft szervereiről érkezett, és a Received fejléceket soha nem használja annak eldöntésére, honnan érkezett egy levél.
* Az MI-szűrőknek szóló szöveg spamnek számít, a nyelvi modell pedig azt az utasítást kapja, hogy a levél adat, nem utasítás. [Prompt injection](llm.md#prompt-injection)


## Szerverek

A milter, a HTTP-, a TCP- és a spamd szerver a 127.0.0.1 címen figyel, hacsak a `--host` mást nem ad meg. A HTTP API konstans idő alatt hasonlítja össze a tokenjét, és token nélkül elutasítja a `/learn` kéréseket. Egyik sem kezel TLS-t: hálózaton keresztüli eléréshez magánhálózat, SSH-alagút vagy TLS-t használó fordított proxy szükséges.

Nem privilegizált felhasználóként érdemes futtatni őket. A [Postfix-útmutatóban lévő systemd unit](postfix.md#1-run-the-milter) a szokásos biztonsági megerősítéseket is tartalmazza.


## Sebezhetőség bejelentése

A biztonsági problémákat privát módon, a [GitHub sebezhetőségbejelentő felületén](https://github.com/spamscanner/spamscanner/security/advisories/new) kell bejelenteni, nem nyilvános hibajegyekben.
