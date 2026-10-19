<!-- source: 599bd320e55a -->

<!--
label: O projektu
title: O Spam Scanneru, jeho licenci a soukromí
description: Kdo vyvíjí Spam Scanner, jak nahlásit chybu nebo zranitelnost, jakou má licenci a co tento web shromažďuje: žádné cookies ani analytiku.
keywords: o Spam Scanneru, Forward Email, licence Spam Scanner, BUSL-1.1, kontakt Spam Scanner, soukromí Spam Scanner
-->

# O Spam Scanneru

Spam Scanner je e-mailový spamový filtr od [Forward Email](https://forwardemail.net), poštovní služby zaměřené na soukromí, která ho vytvořila pro své vlastní poštovní servery. Zdrojový kód, hlášení a vydání jsou na [GitHubu](https://github.com/spamscanner/spamscanner) a balíček je v [npm](https://www.npmjs.com/package/spamscanner).


## Kdo ho vyvíjí

Tým Forward Email Spam Scanner píše a udržuje. Forward Email neuchovává záznamy o obsahu zpráv, a nemohl tedy posílat poštu externí filtrovací službě: filtr musel běžet na vlastních serverech a vysvětlit každé rozhodnutí, aniž by poštu četl člověk. [Jak ho Forward Email používá](../../docs/forward-email.md)

I Forward Email je open source, na adrese [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Jeho zakladatel byl jedním z prvních zaměstnanců DuckDuckGo.


## Kontakt

* **Dotazy, chyby a požadavky na funkce:** založte hlášení na [GitHubu](https://github.com/spamscanner/spamscanner/issues).
* **Bezpečnostní zranitelnosti:** hlaste je soukromě přes [hlášení zranitelností na GitHubu](https://github.com/spamscanner/spamscanner/security/advisories/new), ne ve veřejných hlášeních. Stejná adresa je v souboru [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Jiné licence:** obraťte se na [Forward Email](https://forwardemail.net).


## Licenční podmínky

[Licence](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) Spam Scanneru je Business Source License 1.1 a jako Change License uvádí Apache License 2.0. Change Date uvedené v licenci už uplynulo a od tohoto data vám licence uděluje práva podle Apache License 2.0.


## Soukromí

Tento web nenastavuje cookies a nenačítá analytiku, sledovací nástroje, reklamy, písma ani skripty z jiných webů. Každý soubor pochází z spamscanner.net.

* Motiv, zvolený jazyk a server Mastodonu, na který sdílíte, se ukládají do místního úložiště prohlížeče a nikam se neodesílají.
* Video se načte, až když ho přehrajete.
* Odkazy ke sdílení jsou obyčejné odkazy, takže se z těchto sítí nic nenačte, dokud na některý neklepnete.
* Web běží na GitHub Pages a GitHub z bezpečnostních důvodů zaznamenává IP adresu každého návštěvníka. Viz [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) a [prohlášení GitHubu o ochraně soukromí](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Co software odesílá

Spam Scanner neposílá telemetrii a nekontroluje aktualizace. Ve výchozím stavu vyhledá názvy hostitelů z odkazů ve zprávě ve filtrujících DNS resolverech Cloudflare a nic jiného stroj neopustí. Jeho další síťové kontroly jsou vypnuté, dokud je nezapnete. [Zabezpečení a soukromí](../../docs/security.md)


## Vydání

Samostatné binární soubory sestavuje GitHub Actions z veřejného repozitáře. Každé vydání uvádí jejich haše v souboru `SHA256SUMS`, který ověřuje instalační skript, a každý binární soubor nese podepsané osvědčení o původu sestavení. Vydání a jejich poznámky jsou na [GitHubu](https://github.com/spamscanner/spamscanner/releases).
