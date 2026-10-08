<!-- source: 60f00f92b5aa -->

# Zabezpečení a soukromí

Spam Scanner čte poštu, která je soukromá, od odesílatelů, kteří mohou být nepřátelští. Tato stránka uvádí, co kam posílá a jak zachází s tím, co čte.


## Co opouští počítač

Ve výchozím stavu jediná věc: **názvy hostitelů z odkazů** ve zprávě se vyhledávají na filtrovacích resolverech Cloudflare, 1.1.1.2 a 1.0.0.2 (malware a phishing) a 1.1.1.3 a 1.0.0.3 (navíc obsah pro dospělé). Jde o běžné dotazy DNS na jména jako `example.com`; neposílá se žádná část zprávy ani jejích adres. Vypnete je pomocí `phishing: {cloudflare: false}` nebo `--no-cloudflare`, samotnou kontrolu obsahu pro dospělé pomocí `phishing: {adult: false}`.

Vše ostatní je vypnuté, dokud to nenastavíte:

| Kontrola            | Posílá                                                                 | Komu                                                                 |
| ------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `authentication`    | Dotazy DNS na záznamy SPF, DKIM, DMARC a ARC odesílatele               | Vašemu resolveru nebo `dnsServers`                                   |
| `dnsbl`             | IP adresu klienta v obráceném pořadí a domény z odkazů jako dotazy DNS | Jmenným serverům blocklistů přes váš resolver nebo `dns.servers`     |
| `llm`               | Souhrn zprávy, u vzdálených poskytovatelů bez osobních údajů           | Serveru jazykového modelu, který určíte ([soukromí](llm.md#privacy)) |
| `reputation.apiUrl` | IP adresu, doménu a adresu odesílatele                                 | Službě, kterou určíte                                                |
| `clamav`            | Přílohy                                                                | Vašemu clamd přes jeho socket                                        |

Žádná telemetrie, žádná kontrola aktualizací a žádné stahování za běhu. Model se dodává uvnitř balíčku.


## Co uchovává

Nic, pokud o to nepožádáte. Kontroly se nezaznamenávají ani neukládají. `learn()` mění klasifikátor v paměti; na disk se zapíše jen pomocí `saveModel()`, `spamscanner learn` nebo volby serverů `--out`. Soubor modelu obsahuje zahešované počty příznaků, ne slova ani text zpráv.

Odpovědi jazykového modelu se ukládají do mezipaměti v paměti pod hešem toho, co bylo odesláno, takže na opakované kopie stejné zprávy se model ptá jen jednou. Odpovědi DNS se v paměti uchovávají deset minut.


## Nepřátelský vstup

* Přílohy se rozpoznávají podle bajtů, nikdy se nespouštějí ani neotevírají jiným programem. Archivy ZIP se čtou z centrálního adresáře s omezením počtu položek; vnořené archivy se nerozbalují.
* Text těla se čte do `maxLength` (100 000 znaků) a servery přijímají zprávy do 25 MB.
* Každá síťová kontrola má časový limit (`timeout`, ve výchozím stavu 10 sekund). Kontrola, která selže nebo vyprší, se přeskočí a kontrola zprávy skončí bez ní.
* Hlavičky `X-Spam-*`, které už zpráva obsahuje, odstraňuje milter, obsahový filtr i `--headers`, takže odesílatelé nemohou svou vlastní poštu označit jako čistou.
* Hlavičkám s verdiktem spamu od Microsoftu se věří, jen když zpráva přišla přímo ze serverů Microsoftu, a hlavičky Received se nikdy nepoužívají k určení, odkud zpráva přišla.
* Text, který se obrací na filtry s AI, se boduje jako spam a jazykový model dostane informaci, že zpráva jsou data, ne pokyny. [Prompt injection](llm.md#prompt-injection)


## Servery

Servery milter, HTTP, TCP a spamd naslouchají na 127.0.0.1, pokud `--host` neurčí jinak. HTTP API porovnává svůj token v konstantním čase a bez něj odmítá `/learn`. Žádný z nich nemluví TLS: chcete-li se k nim dostat přes síť, použijte privátní síť, tunel SSH nebo reverzní proxy s TLS.

Spouštějte je pod neprivilegovaným uživatelem. [Jednotka systemd v návodu pro Postfix](postfix.md#1-run-the-milter) přidává obvyklé zabezpečení.


## Hlášení zranitelnosti

Bezpečnostní problémy hlaste soukromě přes [hlášení zranitelností na GitHubu](https://github.com/spamscanner/spamscanner/security/advisories/new), ne ve veřejných issues.
