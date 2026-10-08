<!-- source: 8860e232d858 -->

# Dokumentace Spam Scanneru

Spam Scanner je spamový filtr pro Node.js a příkazovou řádku se zdrojovým kódem na GitHubu. Přečte surovou e-mailovou zprávu a rozhodne, zda jde o spam, phishing nebo podvod, nebo zda nese malware, a to v jakémkoli jazyce. Běží jako knihovna, nástroj pro příkazovou řádku, milter pro Postfix nebo Sendmail, obsahový filtr pro Postfix, server spamd kompatibilní se SpamAssassinem, HTTP API nebo TCP server.

Vytváří ho [Forward Email](https://forwardemail.net) pro vlastní poštovní servery.


## Jak se zpráva posuzuje

Každá kontrola body přidává nebo ubírá. O výsledku rozhoduje součet:

| Skóre     | Akce     | Co udělá poštovní server      |
| --------- | -------- | ----------------------------- |
| Pod 5     | `accept` | Zprávu doručí                 |
| 5 až 14,9 | `tag`    | Doručí ji označenou jako spam |
| 15 a více | `reject` | Odmítne ji během relace SMTP  |

Oba prahy lze změnit. Každý výsledek uvádí testy, které se spustily, s jejich body a důvodem, takže rozhodnutí lze vždy vysvětlit.

Kontroly:

* **Natrénovaný klasifikátor** čte slova zprávy v jakémkoli písmu, podobu jejích odkazů, odesílatele a přílohy. Dodává se natrénovaný na veřejných datových sadách a učí se z vaší vlastní pošty. [Jak klasifikátor funguje](how-it-works.md#the-classifier)
* **Kontroly phishingu** zachytí podobně vypadající domény (`paypa1.com`, `pаypal.com` s cyrilickým а), odkazy, jejichž text ukazuje jednu adresu a cíl vede jinam, a zobrazovaná jména, která se hlásí ke značce. [Phishing](how-it-works.md#phishing)
* **Kontroly příloh** najdou spustitelné soubory, spustitelné soubory přejmenované na dokumenty, dvojité přípony, triky se směrem textu zprava doleva v názvech souborů, spustitelné soubory v souborech ZIP, makra Office a aktivní obsah PDF. ClamAV může přílohy kontrolovat na viry. [Přílohy](how-it-works.md#attachments)
* **Ověření**: SPF, DKIM, DMARC a ARC, pokud je známa IP adresa klienta. [Ověření](how-it-works.md#authentication)
* **DNS blocklisty** pro IP adresu klienta a domény v odkazech a filtrovací resolvery Cloudflare pro známý malware a weby pro dospělé. [Blocklisty](how-it-works.md#blocklists)
* **Pravidla** pro vzory, které se žádný klasifikátor nemusí učit: testovací řetězec GTUBE, předměty sextortion, podvody s fakturami PayPal, podvrhování vlastní domény a pokyny skryté pro filtry s AI. [Pravidla](scoring.md#rules)
* **Jazykový model**, volitelný, dává druhý názor v hraničních případech: lokální model přes Ollama nebo jakýkoli server kompatibilní s OpenAI, rozhodovací model, například Clef od Cloudflaru, nebo Claude, ChatGPT, Gemini a další. Ve výchozím stavu vrátí v jednom kroku pravděpodobnost každého verdiktu, místo aby psal odpověď. [Jazykové modely](llm.md)


## Kde začít

* [Začínáme](getting-started.md): instalace a kontrola první zprávy.
* [Příkazová řádka](cli.md): všechny příkazy a volby.
* [Postfix a Sendmail](postfix.md): filtrování poštovního serveru milterem nebo obsahovým filtrem.
* [Další poštovní servery](mail-servers.md): Exim, Haraka, Dovecot, procmail a cokoli, co umí volat HTTP API.
* [Trénování](training.md): naučte ho vaši vlastní poštu a změřte výsledek.
* [Jazykové modely](llm.md): rozhodování a generování, naměřená přesnost a rychlost, rozhodovací modely, poskytovatelé, doporučené otevřené modely, soukromí a prompt injection.
* [Jazyky](languages.md): jak čte čínštinu, arabštinu, thajštinu a každé další písmo.
* [Forward Email](forward-email.md): jak ho používá Forward Email a přechod z verze 5 nebo 6.
* [Reference API](api.md) a [testy a skóre](scoring.md).
* [Zabezpečení a soukromí](security.md): co opouští počítač a jak to zastavit.
