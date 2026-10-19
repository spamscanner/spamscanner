<!-- source: 1d7373f991c2 -->

# Zabezpečení a soukromí

Spam Scanner čte poštu, která je soukromá, od odesílatelů, kteří mohou být nepřátelští. Tato stránka uvádí, co kam posílá a jak zachází s tím, co čte.


## Co opouští počítač

Ve výchozím stavu jediná věc: **názvy hostitelů z odkazů** ve zprávě se vyhledávají na filtrovacích resolverech Cloudflare, 1.1.1.2 a 1.0.0.2 (malware a phishing) a 1.1.1.3 a 1.0.0.3 (navíc obsah pro dospělé). Jde o běžné dotazy DNS na jména jako `example.com`; neposílá se žádná část zprávy ani jejích adres. Vypnete je pomocí `phishing: {cloudflare: false}` nebo `--no-cloudflare`, samotnou kontrolu obsahu pro dospělé pomocí `phishing: {adult: false}`.

Vše ostatní je vypnuté, dokud to nenastavíte:

| Kontrola            | Posílá                                                                                                     | Komu                                                                 |
| ------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `authentication`    | Dotazy DNS na záznamy SPF, DKIM, DMARC a ARC odesílatele                                                   | Vašemu resolveru nebo `dnsServers`                                   |
| `dnsbl`             | IP adresu klienta v obráceném pořadí a domény z odkazů jako dotazy DNS                                     | Jmenným serverům blocklistů přes váš resolver nebo `dns.servers`     |
| `llm`               | Souhrn zprávy, u vzdálených poskytovatelů bez osobních údajů                                               | Serveru jazykového modelu, který určíte ([soukromí](llm.md#privacy)) |
| `reputation.apiUrl` | IP adresu a ověřený název hostitele klienta a adresy From, odesílatele obálky a Reply-To s jejich doménami | Službě, kterou určíte                                                |
| `clamav`            | Přílohy                                                                                                    | Vašemu clamd přes jeho socket                                        |

Žádná telemetrie, žádná kontrola aktualizací a žádné stahování za běhu. Model se dodává uvnitř balíčku.


## Co uchovává

Nic, pokud o to nepožádáte. Kontroly se nezaznamenávají ani neukládají. `learn()` mění klasifikátor v paměti; na disk se zapíše jen pomocí `saveModel()`, `spamscanner learn` nebo volby serverů `--out`. Soubor modelu obsahuje zahešované počty příznaků, ne slova ani text zpráv.

Odpovědi jazykového modelu se ukládají do mezipaměti v paměti pod hešem toho, co bylo odesláno, takže na opakované kopie stejné zprávy se model ptá jen jednou. Odpovědi DNS se v paměti uchovávají deset minut a odpovědi služby reputace pět (`reputation.cacheTtl`; neúspěšný požadavek jednu minutu).


## Nepřátelský vstup

* Přílohy se rozpoznávají podle bajtů, nikdy se nespouštějí ani neotevírají jiným programem. Archivy ZIP se čtou z centrálního adresáře s limity počtu položek (2000) a bajtů jejich názvů (1 MiB; název nad 1 KiB si ponechá svých prvních a posledních 512 bajtů a nálezy z něj ukazují nejvýše 100 znaků), přičemž každá položka se čte jednou, ať na ni ukazuje kolik záznamů adresáře chce; nic se nerozbaluje, takže programy uvnitř vnořených nebo komprimovaných archivů nejsou vidět. Přiložené zprávy (`message/rfc822` nebo přílohy, jejichž název souboru končí na `.eml`) se otevírají až do hloubky tří úrovní, nejvýše pro 100 jejich příloh a celkem 25 MB přiložených zpráv; vlastní přílohy zprávy se vždy kontrolují všechny. Zpráva, která překračuje limity parseru MIME (více než 1000 částí nebo hlavička části nad 1 MB), se čte, kam až parser dovolí (její první části, s příliš velkou hlavičkou zkrácenou tak, aby se její odesílatel stále počítal), a dostane `MIME_TOO_COMPLEX`, který žádný kredit nevyváží; ClamAV ji čte celou. Dostane ho i přiložená zpráva, na které parser selže, a kontrola kvůli ní nikdy neselže. Adresní pole se čtou do 16 KB každé (2000 adres, 16 vnořených skupin) a celkem 64 KB na zprávu, zkrácená jen na konci celé adresy, protože parser adres potřebuje čas, který roste s druhou mocninou počtu adres; mailauth čte takto omezená také From a Return-Path (ostatní pole tak, jak jsou, aby podpis nad nimi platil) a hlavičku, jejíž čtení by trvalo déle než lineární čas (tisíce zalomených řádků nebo podpisy jmenující tisíce polí), dostane zkrácenou. Zkrácené pole From způsobí selhání DMARC a nic nepovolí. HTML čte vlastní parser Spam Scanneru, v lineárním čase, ať je vnořené jakkoli hluboko.
* Text těla se čte do `maxLength` (100 000 znaků) a servery přijímají zprávy do 25 MB. Odkazy se čtou až do `phishing.maxLength` (1 000 000 znaků).
* Každá síťová kontrola má časový limit (`timeout`, ve výchozím stavu 10 sekund). Kontrola, která selže nebo vyprší, se přeskočí a kontrola zprávy skončí bez ní. Ověřování a model obrázků (prvních 10 obrázků) se každý jako celek vejdou do tohoto limitu: ověřování po něm nepošle žádný dotaz DNS, ani víc než 300 na jednu zprávu (prostor pro SPF na hranicích RFC 7208, s DKIM, ARC, DMARC a BIMI), a kontroluje jen prvních 8 podpisů DKIM zprávy (mailauth sám čte nejvýše 50 sad ARC). Hlavička `Authentication-Results`, kterou milter přidává, obsahuje nejvýše 8 KiB výsledků. ClamAV (čtyři přílohy najednou) má vlastní limit pro všechny přílohy zprávy (`clamav.timeout`, 60 sekund) a přílohy, které nedokázal zkontrolovat, jsou uvedeny v `results.virusScanErrors`. Jazykový model má vlastní limit (`llm.timeout`).
* Seznam povolených důvěřuje jen tomu, co odesílatel nemůže podvrhnout: adrese a ověřenému názvu hostitele klienta a doménám odesílatelů, které potvrdí ověřování. [Seznam povolených a zakázaných](api.md#allowlist-and-denylist)
* Hlavičky `X-Spam-*`, které už zpráva obsahuje, odstraňuje milter, obsahový filtr i `--headers`, takže odesílatelé nemohou svou vlastní poštu označit jako čistou.
* Hlavičkám s verdiktem spamu od Microsoftu se věří, jen když zpráva přišla přímo ze serverů Microsoftu, a hlavičky Received se nikdy nepoužívají k určení, odkud zpráva přišla.
* Text, který se obrací na filtry s AI, se boduje jako spam a jazykový model dostane informaci, že zpráva jsou data, ne pokyny. [Prompt injection](llm.md#prompt-injection)


## Servery

Servery milter, HTTP, TCP a spamd naslouchají na 127.0.0.1, pokud `--host` neurčí jinak. HTTP API porovnává svůj token v konstantním čase a bez něj odmítá `/learn`. Žádný z nich nemluví TLS: chcete-li se k nim dostat přes síť, použijte privátní síť, tunel SSH nebo reverzní proxy s TLS.

Spouštějte je pod neprivilegovaným uživatelem. [Jednotka systemd v návodu pro Postfix](postfix.md#1-run-the-milter) přidává obvyklé zabezpečení.


## Hlášení zranitelnosti

Bezpečnostní problémy hlaste soukromě přes [hlášení zranitelností na GitHubu](https://github.com/spamscanner/spamscanner/security/advisories/new), ne ve veřejných issues.
