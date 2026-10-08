<!-- source: 361732724f0e -->

<!--
label: Časté dotazy
title: Často kladené otázky
description: Odpovědi o Spam Scanneru: jak je přesný, které jazyky podporuje, co posílá po síti, jazykové modely, SpamAssassin a Forward Email.
keywords: Spam Scanner časté dotazy, otázky ke spamovému filtru, přesnost spamového filtru, spamový filtr soukromí
-->

# Často kladené otázky


## Co je Spam Scanner?

Spamový filtr pro Node.js, příkazovou řádku a poštovní servery. Přečte surovou e-mailovou zprávu a rozhodne, zda jde o spam, phishing nebo podvod, nebo zda nese malware, a uvede skóre a seznam testů, které rozhodly. Běží jako knihovna, milter pro Postfix a Sendmail, server spamd kompatibilní se SpamAssassinem, obsahový filtr pro Postfix, HTTP API nebo TCP server.


## Je zdarma?

Jeho [licence](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), Business Source License 1.1, povoluje jakékoli použití kromě nabízení detekce spamu jako služby jiným a uvádí datum, kdy se změní na Apache License 2.0.


## Jak je přesný?

Na odložených anglických zprávách z trénovacích dat neoznačil samotný přibalený klasifikátor žádný ham jako spam a zachytil 97 % spamu; úplná čísla pro jednotlivé jazyky jsou v [návodu k trénování](../../docs/training.md#the-bundled-model). Odkazy, přílohy, ověření, blocklisty a jazykový model k tomu přidávají. Skutečným testem je vaše vlastní pošta: `spamscanner eval` změří jakýkoli model na jakékoli označené poště.


## Které jazyky podporuje?

Všechny. Slova dělí podle pravidel Unicode, včetně čínštiny, japonštiny a thajštiny, které nemají mezery. Tam, kde přibalený model viděl v nějakém jazyce málo pošty, zůstane nejistý, místo aby zprávu označil, a rozhodne jazykový model nebo vaše vlastní trénování. [Jazyky](../../docs/languages.md)


## Posílá poštu někam?

Ne. Ve výchozím stavu vyhledává názvy hostitelů z odkazů na filtrovacích DNS resolverech Cloudflare a nic jiného počítač neopouští. Ověření, blocklisty, jazykové modely a služby reputace jsou vypnuté, dokud je nenastavíte, a než pošta odejde k hostovanému jazykovému modelu, odstraní se z ní osobní údaje. [Zabezpečení a soukromí](../../docs/security.md)


## Je potřeba jazykový model?

Ne. Je to druhý názor pro hraniční případy. Bez něj o těchto zprávách rozhoduje jen jejich skóre.


## Který jazykový model použít?

`qwen3.5:4b` přes Ollama na CPU, nebo `qwen3.5:9b` s GPU. Oba mají licenci Apache a čtou 201 jazyků. Spam Scanner čte pravděpodobnost každého verdiktu z jednoho kroku modelu, což na dvoujádrovém CPU trvalo asi 11 sekund na zprávu místo 31 u napsané odpovědi, se stejnou přesností. Jako hostovaná služba odpovídají rozhodovací modely Cloudflare Clef a TypeSafe Jev za méně než sekundu; fungují i modely od Anthropicu, OpenAI, Googlu a dalších. [Měření](../../docs/llm.md#measured) a [doporučené modely](../../docs/llm.md#recommended-open-models)


## Může nahradit SpamAssassin?

Ve většině nasazení ano: mluví protokolem spamd, takže spamc, Exim a Haraka fungují beze změn, a zapisuje stejné hlavičky `X-Spam-*`. Nespouští soubory pravidel SpamAssassinu. [Alternativa ke SpamAssassinu](/spamassassin-alternative/)


## Bude odmítat legitimní poštu?

Odmítání pošty je ve výchozím stavu vypnuté: milter jen označuje. S `--reject` se odmítají jen zprávy se skóre 15 nebo více, a to dočasnou chybou 451, takže odesílatelé to zkusí znovu a chybu lze opravit změnou nastavení. Obsahový filtr během relace SMTP nikdy neodmítá.


## Jak ho natrénovat na vlastní poště?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, potom `--model model.json`. Fungují soubory mbox, adresáře Maildir, složky souborů `.eml` i datové sady CSV nebo JSON Lines. [Trénování](../../docs/training.md)


## Funguje bez Node.js?

Ano: samostatné binárky pro Linux, macOS a Windows obsahují Node.js i model. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Kdo ho vyvíjí?

[Forward Email](https://forwardemail.net) pro vlastní poštovní servery.
