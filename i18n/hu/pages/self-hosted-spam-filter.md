<!-- source: 988243aec4f3 -->

<!--
label: Saját üzemeltetésű spamszűrő
title: Saját üzemeltetésű spamszűrő a saját levelezőszerveréhez
description: Spamszűrő a saját szerverén. A Spam Scanner a gépen tartja a leveleket, a modellje a csomagban van, nem küld telemetriát, és Postfixszel vagy Eximmel is működik.
keywords: saját üzemeltetésű spamszűrő, helyben telepített spamszűrő, privát spamszűrő, helyi spamszűrő, spamszűrő levelezőszerverhez, spamszűrő felhő nélkül
-->

# Saját üzemeltetésű spamszűrő

A Spam Scanner a saját szerverén fut, és ott tartja a leveleket. Az osztályozó modellje a csomagban van, nincs telemetria és frissítéskeresés, alapértelmezés szerint pedig csak egy DNS-lekérdezést küld minden hivatkozás gépnevére.


## Mi hagyja el a szervert

Alapértelmezés szerint csak a levélben lévő hivatkozások gépnevei. Ezeket a Cloudflare szűrő feloldóinál (1.1.1.2 és 1.1.1.3) keresi ki szokásos DNS-lekérdezésekkel, a levélből és a címeiből semmit nem küld el. A `--no-cloudflare` ezt is kikapcsolja.

Minden más, hálózatot használó ellenőrzés ki van kapcsolva, amíg be nem kapcsolja:

| Ellenőrzés            | Bekapcsolás          | Mit küld                                                            |
| --------------------- | -------------------- | ------------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | DNS-lekérdezéseket a feladó rekordjaira                             |
| DNS-tiltólisták       | `--dnsbl`, `--uribl` | Az ügyfél IP-címét és a hivatkozások domainjeit, DNS-lekérdezésként |
| ClamAV                | `--clamav`           | A mellékleteket, a saját clamd-jének                                |
| Nyelvi modell         | `--llm`              | A levél összefoglalóját, az Ön által megadott szervernek            |

A vizsgálatokat nem naplózza és nem tárolja. [Biztonság és adatvédelem](../../docs/security.md)


## Telepítés szerverre

```sh
npm install --global spamscanner
```

Vagy az önálló bináris, beépített Node.js-szel és modellel:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

A telepítőszkript a kiadás `SHA256SUMS` fájlja alapján ellenőrzi a binárist telepítés előtt, és minden binárisnak van aláírt builderedet-igazolása, amelyet a `gh attestation verify` ellenőriz. Binárisok vannak Linuxra (x64 és arm64), macOS-re és Windowsra. A linuxos binárisokhoz glibc kell, ezért Alpine-on npm-mel telepítsen. [Első lépések](../../docs/getting-started.md)

Nincs frissítéskeresés. A frissítéshez futtassa újra a telepítő parancsot: mindkét parancs a legújabb kiadást telepíti.


## Futtatás szolgáltatásként

A milter-, HTTP-, TCP- és spamd-szerverek a 127.0.0.1 címen figyelnek, hacsak a `--host` mást nem mond. Futtassa őket jogosultság nélküli felhasználóként, például systemd alatt:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

A [teljes egység és a beállítása](../../docs/postfix.md#1-run-the-milter) a Postfix-útmutatóban található. Egyik szerver sem beszél TLS-t, ezért másik gépről privát hálózaton, SSH-alagúton vagy TLS-es fordított proxyn át érje el őket.


## A levelezőszerver csatlakoztatása

| Levelezőszerver                     | Parancs                                 | Port  |
| ----------------------------------- | --------------------------------------- | ----- |
| Postfix vagy Sendmail               | `spamscanner milter`                    | 7831  |
| Postfix, levelek elutasítása nélkül | `spamscanner filter`, tartalomszűrő     | nincs |
| Exim, Haraka vagy spamc             | `spamscanner spamd`                     | 783   |
| Bármi, ami HTTP-t beszél            | `spamscanner http`                      | 7832  |
| Egyszerű TCP-ügyfél                 | `spamscanner server`                    | 7830  |
| Node.js-ben írt levelezőszerver     | `import SpamScanner from 'spamscanner'` | nincs |

A szerverek hozzáadhatják a levélhez az `X-Spam-Flag`, `X-Spam-Score` és `X-Spam-Status` fejléceket, a könyvtár pedig visszaadja a pontszámot és minden jelzett tesztet. Útmutatók: [spamszűrő Postfixhez](/postfix-spam-filter/), [más levelezőszerverek](../../docs/mail-servers.md) és [a HTTP API](../../docs/http-api.md).


## Nyelvi modellek helyben

A nyelvi modell nem kötelező, és csak a határesetekkel foglalkozik: az egyértelmű spam és az egyértelmű ham sosem jut el hozzá. Az Ollamával ugyanazon a szerveren fut, így egyetlen levél sem hagyja el:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

A `qwen3.5:4b` CPU-n fut. Felhőben futó szolgáltató esetén a személyes adatokat küldés előtt eltávolítja a levélből. [Nyelvi modellek](../../docs/llm.md)


## Tanítás a saját leveleivel

A mellékelt modellt nyilvános adathalmazokon tanították. A szervere által fogadott leveleken tanított modell jobban teljesít, és azon a szerveren marad:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

A modellfájl hash-elt jellemzőszámlálókat tartalmaz, nem szavakat vagy levélszöveget. [Tanítás](../../docs/training.md)


## Követelmények

Node.js 18 vagy újabb Linuxon, macOS-en vagy Windowson, önálló binárissal pedig semmi. A ClamAV és az Ollama nem kötelező, és külön szolgáltatásként fut.
