import {domainToUnicode} from 'node:url';
import {parse as parseDomain} from 'tldts';
import {scriptOf} from './language.js';

// Banks, posts, tax offices, shops, payment and delivery services imitated
// around the world (only names that are not words or close to words, so
// ordinary domains are not taken for typos of them: each run against a
// million of the most visited domains, which must hold none it takes for
// an imitation but those that are).
const INTERNATIONAL_BRANDS = [
	'abnamro', 'agenziaentrate', 'aliorbank', 'alipay', 'alphabank', 'alrajhibank', 'auspost', 'axisbank', 'banamex', 'bancatransilvania', 'bancoazteca', 'bancodebogota', 'bancodechile', 'bancodobrasil', 'bancoestado', 'bancofalabella', 'bancogalicia', 'bancolombia', 'bancomacro', 'bancomer', 'bancoposta', 'bancoppel', 'bancosabadell', 'bancsabadell', 'bangkokbank', 'bankaustria', 'bankhapoalim', 'bankleumi', 'bankmandiri', 'bankmillennium', 'bankofbaroda', 'bankofchina', 'bankofcyprus', 'bankofireland', 'bankwest', 'banorte', 'banquemisr', 'banquepopulaire', 'banreservas', 'banrisul', 'bbva', 'belarusbank', 'belastingdienst', 'belfius', 'bendigobank', 'biglobe', 'bitflyer', 'bithumb', 'bitstamp', 'bitvavo', 'bluehost', 'bnpparibas', 'boursobank', 'boursorama', 'bouyguestelecom', 'bradesco', 'britishgas', 'bukalapak', 'bunq', 'caixabank', 'canadapost', 'capitalone', 'ceskaposta', 'ceskasporitelna', 'chronopost', 'citibanamex', 'coincheck', 'colissimo', 'commerzbank', 'commonwealthbank', 'consorsbank', 'correoargentino', 'coupang', 'creditagricole', 'creditmutuel', 'creditsuisse', 'danskebank', 'daviplata', 'davivienda', 'denizbank', 'deutschebank', 'deutschepost', 'dgfip', 'dvla', 'easypaisa', 'emiratesnbd', 'emiratespost', 'eposcard', 'equitybank', 'erstebank', 'erstegroup', 'etisalat', 'fancourier', 'finecobank', 'flipkart', 'flutterwave', 'garantibbva', 'gazprombank', 'geeksquad', 'gosuslugi', 'grabpay', 'halkbank', 'halykbank', 'hanabank', 'handelsbanken', 'hdfcbank', 'hellenicbank', 'hellobank', 'hepsiburada', 'hostgator', 'hypovereinsbank', 'ibercaja', 'iberdrola', 'icbc', 'inbursa', 'indiapost', 'intesasanpaolo', 'isracard', 'israelpost', 'itau', 'japanpost', 'jazzcash', 'kakaobank', 'kakaopay', 'kakaotalk', 'kasikornbank', 'kiwibank', 'klarna', 'klikbca', 'kotakbank', 'krungsri', 'krungthai', 'kucoin', 'kutxabank', 'kyivstar', 'labanquepostale', 'landbank', 'lazada', 'lloydsbank', 'luxtrust', 'maltapost', 'mediolanum', 'mercadolibre', 'mercadolivre', 'mercadopago', 'mercari', 'metrobank', 'millenniumbcp', 'mizuhobank', 'moneygram', 'monobank', 'multibanco', 'multicaixa', 'naturgy', 'natwest', 'navyfederal', 'nexi', 'ninjavan', 'nonghyup', 'novaposhta', 'novobanco', 'nubank', 'octopusenergy', 'oschadbank', 'ovhcloud', 'pagseguro', 'parcelforce', 'paymaya', 'payoneer', 'paystack', 'permanenttsb', 'phonepe', 'piraeusbank', 'pocztapolska', 'posindonesia', 'postbank', 'posteitaliane', 'postfinance', 'postnord', 'rabobank', 'rakuten', 'resonabank', 'riyadbank', 'safaricom', 'saisoncard', 'sberbank', 'scotiabank', 'serpost', 'servicecanada', 'servientrega', 'shinhanbank', 'shinhancard', 'sicoob', 'sicredi', 'singpass', 'skatteetaten', 'skatteverket', 'squarespace', 'standardchartered', 'starlingbank', 'swedbank', 'swisscom', 'targobank', 'tatrabanka', 'techcombank', 'telepass', 'telstra', 'thailandpost', 'tinkoff', 'tokopedia', 'tossbank', 'totalenergies', 'trendyol', 'triodos', 'truemoney', 'trustwallet', 'turkcell', 'turktelekom', 'tvlicensing', 'ukrposhta', 'unicredit', 'vietcombank', 'vietinbank', 'vietnampost', 'viewcard', 'virginmedia', 'virginmoney', 'vodafone', 'wallapop', 'wechat', 'wechatpay', 'westernunion', 'wildberries', 'willhaben', 'wooribank', 'yandex', 'zenithbank', 'ziraatbank',
];

/**
 * Brands most often imitated in phishing: banks, payment services, mail and
 * cloud providers, shops, couriers and tax offices. A domain whose name is a
 * brand's ("paypal" in paypal.com, paypal.de, ...) is the brand's own and is
 * never flagged.
 */
export const BRANDS = [
	'adobe', 'airbnb', 'alibaba', 'aliexpress', 'amazon', 'americanexpress', 'amex', 'apple', 'appleid', 'att', 'binance', 'bankofamerica', 'barclays', 'bestbuy', 'blockchain', 'booking', 'bybit', 'cashapp', 'chase', 'citibank', 'cloudflare', 'coinbase', 'comcast', 'costco', 'dhl', 'discord', 'docusign', 'dropbox', 'ebay', 'facebook', 'fedex', 'forwardemail', 'github', 'gitlab', 'gmail', 'godaddy', 'google', 'hmrc', 'hotmail', 'hsbc', 'icloud', 'instagram', 'intuit', 'irs', 'kraken', 'ledger', 'linkedin', 'mastercard', 'mcafee', 'metamask', 'microsoft', 'microsoftonline', 'namecheap', 'netflix', 'norton', 'office', 'office365', 'okta', 'onedrive', 'outlook', 'paypal', 'proton', 'protonmail', 'quickbooks', 'revolut', 'roblox', 'royalmail', 'salesforce', 'samsung', 'santander', 'sharepoint', 'shopify', 'skype', 'slack', 'sparkasse', 'spotify', 'steam', 'steampowered', 'stripe', 'telegram', 'tiktok', 'tmobile', 'trezor', 'tutanota', 'twitter', 'uber', 'ups', 'usps', 'venmo', 'verizon', 'visa', 'walmart', 'wellsfargo', 'whatsapp', 'wise', 'xfinity', 'yahoo', 'zelle', 'zoom', ...INTERNATIONAL_BRANDS,
];

// Words phishing domains add to a brand ("paypallogin", "secure-chase",
// "paypal-konto", "amazonconnexion"): asking to sign in, verify, unlock or
// pay, not words a shop or service puts in an ordinary name. In the languages
// phishing is written in, as a domain name spells them, without accents; but
// not those that start ordinary words of a business ("conta" of "contato"
// and "contabilidade", "acceso" of "accesorios", "seguro" of "seguros").
export const PHISHING_WORDS = [
	'account accounts alert alerts auth authentication billing confirm login logon password recovery refund secure security signin signon suspended unlock update validate verification verify',
	// German
	'aktualisieren aktualisierung anmelden anmeldung bestaetigen bestatigen entsperren kennwort konto kundenkonto passwort sicherheit verifizieren verifizierung',
	// French
	'authentification compte confirmer connexion motdepasse remboursement securite verifier',
	// Spanish, Portuguese
	'actualizar atualizacao atualizar confirmacao confirmar contrasena cuenta reembolso seguranca seguridad verificacao verificacion verificar',
	// Italian
	'accedi aggiorna conferma rimborso sicurezza verifica',
	// Dutch
	'beveiliging bevestigen inloggen verificatie wachtwoord',
	// Polish, Czech, Hungarian, Romanian
	'autentificare bejelentkezes bezpieczenstwo biztonsag logowanie overeni potwierdz prihlaseni securitate weryfikacja zaloguj',
	// Swedish, Danish, Norwegian, Finnish
	'bekraeft bekreft inloggning kirjaudu losenord passord sakerhet salasana sikkerhed sikkerhet',
	// Turkish, Indonesian, Vietnamese
	'dangnhap dogrulama guncelle guvenlik keamanan konfirmasi taikhoan verifikasi xacminh',
].flatMap(words => words.split(' '));
const PHISHING_WORD = new Set(PHISHING_WORDS);

// Brands that are also words: joined to a phishing word ("securebooking",
// "officesecurity") they name something else as often as the brand.
const WORD_BRANDS = new Set(['apple', 'blockchain', 'booking', 'chase', 'discord', 'kraken', 'ledger', 'norton', 'office', 'postbank', 'proton', 'santander', 'slack', 'steam', 'stripe', 'telegram']);

// Words phishing domains put beside a brand that is a word, offering help,
// a gift or the brand's own wallet, bank or files ("apple-support",
// "discord-nitro", "chase-bank"): with one of these, the word is the brand
// ("apple-tree" and "chase-hotel" are not).
const BRAND_SERVICE_WORDS = new Set(['bank', 'banking', 'customer', 'files', 'gift', 'giftcard', 'gifts', 'help', 'helpdesk', 'id', 'nitro', 'online', 'pay', 'payment', 'payments', 'service', 'services', 'support', 'trade', 'trading', 'wallet', 'wallets']);
// Brands that are the most common of these words, in the names of ordinary
// businesses beside words of services too ("office-help", "booking-online",
// "ledger-services", "steam-service", "kraken-services"): only the names of
// the brand's own products and help count beside them ("ledger-live",
// "ledger-wallet", "steam-community", "steam-gift", "stripe-payments",
// "ledger-support"), and in another label only a word asking to sign in
// makes them the brand ("login.steam.example.com", not
// "auth.steam.example.edu"). For "office" and "booking", nothing does.
const HELP_WORDS = ['help', 'helpdesk', 'support'];
const COMMON_WORD_BRANDS = new Map([
	['blockchain', ['wallet', 'wallets', ...HELP_WORDS]],
	['booking', []],
	['kraken', ['trade', 'trading', 'wallet', 'wallets', ...HELP_WORDS]],
	['ledger', ['live', 'wallet', 'wallets', ...HELP_WORDS]],
	['office', []],
	['proton', ['pay', 'wallet', ...HELP_WORDS]],
	['steam', ['community', 'gift', 'giftcard', 'gifts', 'trade', 'trading', 'wallet', ...HELP_WORDS]],
	['stripe', ['payment', 'payments', ...HELP_WORDS]],
]);
const SIGN_IN_LABELS = new Set(['account', 'accounts', 'login', 'logon', 'signin', 'signon']);

// Brands one letter away from common words ("finance", "mobile", "email",
// "cloud", "adore", "morton", "belle", "cedex", "tresor", "twister"), or
// from names of places ("venlo", "samsun") or their own other domains
// ("tiktokv"):
// only two swapped neighbouring letters count as a typo of these ("gmial"),
// and, but for the brands that are words, a letter left out inside the name
// ("twiter", "samsng": not the first or the last, as "cloud", "mobile" and
// "samsun" are) or one doubled ("twittter", "samssung"). So are the brands
// that many other companies' names are a letter from, in other countries
// ("ncbank" and "nurbank" for nubank, "allpay" and "alipan" for alipay,
// "rechat" for wechat, "sterbank" for sberbank).
const TYPO_WORDS = new Set([...WORD_BRANDS, 'adobe', 'alipay', 'binance', 'citibank', 'fedex', 'gmail', 'icloud', 'nubank', 'samsung', 'sberbank', 'tiktok', 'tmobile', 'trezor', 'twitter', 'venmo', 'wechat', 'zelle']);
// (and not words that are such a typo: "titter")
const TYPO_EXCEPTIONS = new Set(['titter']);

/**
 * Whether a name is a brand with one letter left out inside it, or with one
 * of its letters doubled.
 * @param {string} name
 * @param {string} brand
 * @returns {boolean}
 */
export function isDroppedOrDoubled(name, brand) {
	if (name.length === brand.length - 1) {
		let i = 0;
		while (name[i] === brand[i]) {
			i++;
		}

		return i > 0 && i < brand.length - 1 && name.slice(i) === brand.slice(i + 1);
	}

	if (name.length === brand.length + 1) {
		let i = 0;
		while (i < brand.length && name[i] === brand[i]) {
			i++;
		}

		return i > 0 && name[i] === name[i - 1] && name.slice(i + 1) === brand.slice(i);
	}

	return false;
}

// Whether a name one edit from a brand is taken for a typo of it (see
// TYPO_WORDS)
const isTypo = (name, brand) => !TYPO_WORDS.has(brand) || isSwap(name, brand) || (!WORD_BRANDS.has(brand) && !TYPO_EXCEPTIONS.has(name) && isDroppedOrDoubled(name, brand));

// Words one letter or two swapped letters away from a brand ("applied",
// "appleid"; "raketen", "rakuten"), in the dictionaries of English, German,
// French, Spanish, Italian, Dutch, Portuguese and the Scandinavian languages,
// and the names of other companies and sites that are ("paypay" of Japan and
// "paypak" of Pakistan for paypal, "amaron", "cosco", "citicbank", "lithub").
const SWAPPED_WORDS = new Set([
	'akuten', 'alzada', 'amaron', 'amazona', 'amazone', 'appel', 'applied', 'auslost', 'ausport', 'axosbank', 'azada', 'barclay', 'bebit', 'bibit', 'capitaline', 'citicbank', 'civibank', 'comcash', 'cosco', 'coupant', 'feedx', 'gechat', 'giftlab', 'hostmail', 'intui', 'intuis', 'inuit', 'klara', 'klarta', 'lanada', 'lanzada', 'lapada', 'latada', 'lavada', 'lithub', 'mazada', 'mercar', 'mercati', 'mercuri', 'nbank', 'paypak', 'paypay', 'pazada', 'phoneme', 'postbak', 'quirkbooks', 'raketen', 'rauten', 'razada', 'rejolut', 'revolt', 'salesforge', 'setam', 'stema', 'stirpe', 'swissmom', 'swype', 'treezor', 'vazada', 'venom', 'verion', 'wallart', 'webchat', 'weechat', 'yande',
]);

// Official domains of the brands above whose names also hold a brand
// ("deutsche-bank.de"), never flagged: each registered to the brand, by
// its registry, and none that holds its customers' pages under their own
// names ("salesforce-sites.com", "sharepoint-df.com").
const OFFICIAL_DOMAINS = [
	'adobe-addons.com', 'adobe-ap.com', 'adobe-campaign.com', 'adobe-campaign.net', 'adobe-identity.com', 'adobelogin.com', 'ads-twitter.com', 'alibaba-inc.com', 'aliexpress-media.com', 'aliexpress-tech-open.com', 'alipay-eco.com', 'amazon-ads-attestation.com', 'amazon-adsystem.com', 'amazon-corp.com', 'amazon-dss.com', 'amazon-value-service.com', 'apple-cloudkit.com', 'apple-dns.net', 'assoc-amazon.com', 'associates-amazon.com', 'bluehost-cdn.com', 'bnpparibas-am.com', 'bnpparibas-pf.com', 'bouyguestelecom-entreprises.fr', 'bradescoseguranca.com.br', 'business-tiktok.com', 'canadapost-postescanada.ca', 'cc-costco.com', 'cdn-apple.com', 'cloudflare-dns.com', 'cloudflare-ech.com', 'cloudflare-email.net', 'cloudflare-eth.com', 'cloudflare-gateway.com', 'cloudflare-internal.com', 'cloudflare-ipfs.com', 'cloudflare-quic.com', 'cloudflare-terms-of-service-abuse.com', 'coinbase-corp.com', 'costco-static.com', 'credit-agricole.com', 'credit-agricole.fr', 'creditmutuel-epargnesalariale.fr', 'deutsche-bank.de', 'deutschebank-dbdirect.com', 'dropbox-dns.com', 'ebay-kleinanzeigen.de', 'erstebank-open.com', 'facebook-hardware.com', 'facebook-studio.com', 'gitlab-static.net', 'google-analytics.com', 'google-melange.com', 'icloud-content.com', 'icloud-mpp.com', 'icloud-sandbox.com', 'images-amazon.com', 'instagram-brand.com', 'instagram-engineering.com', 'instagram-press.com', 'labanquepostale-assurances-iard.fr', 'labanquepostale-cartesprepayees.fr', 'labanquepostale-financement.fr', 'labanquepostale-gestionprivee.fr', 'linkedin-ei.com', 'mcafeesecure.com', 'media-amazon.com', 'mercari-ops.com', 'mercari-shops-static.com', 'microsoft-falcon.net', 'microsoft-int.com', 'microsoft-ppe.com', 'microsoftonline-p.com', 'microsoftonline-p.net', 'notif-colissimo-laposte.info', 'okta-emea.com', 'payments-amazon.com', 'payoneer-affiliates.com', 'paypal-ads.com', 'paypal-communication.com', 'paypal-community.com', 'paypal-corp.com', 'paypal-mktg.com', 'paypal-objects.com', 'paypal-prepaid.com', 'paypal-status.com', 'postfinance-checkout.ch', 'quip-amazon.com', 'rakuten-bank.co.jp', 'rakuten-bank.net', 'rakuten-card.co.jp', 'rakuten-it.com', 'rakuten-sec.co.jp', 'rakuten-sec.net', 'rakuten-static.com', 's-microsoft.com', 'saisoncard-international.com', 'saisoncard-promotion.com', 'saisoncard-sindan.jp', 'salesforce-ccaas.com', 'salesforce-dns.com', 'salesforce-hub.com', 'samsung-dict.com', 'samsung-news.com', 'samsung-svoice.com', 'sberbank-ast.ru', 'siege-amazon.com', 'slack-edge.com', 'slack-msgs.com', 'squarespace-cdn.com', 'squarespace-mail.com', 'ssl-images-amazon.com', 't-mobile.com', 'thehub-amazon.com', 'tiktok-row.net', 'tiktok-row.org', 'tiktokcdn.com', 'tiktokv.com', 'tmobile-digital.com', 'verizon-gni.net', 'verizon-services.com', 'vodafone-ip.de', 'xxi-banorte.com', 'yahoo-corp.jp', 'yahoo-net.jp', 'yandex-bank.net', 'yandex-team.ru',
];
// (and each Sparkasse's own, "sparkasse-koelnbonn.de" and
// "berliner-sparkasse.de", unless a part of it is a phishing word; and a
// company of the Rakuten group's, "rakuten-edy.co.jp": a co.jp domain is
// registered to a company in Japan, one each)
const SPARKASSE = /^(?:sparkasse-[a-z\d-]+|[a-z\d-]+-sparkasse)\.(?:de|at)$|^rakuten-[a-z\d]+\.co\.jp$/;
// Domains of the networks that deliver a brand's own site under a name that
// starts with its address ("apple.com.edgekey.net" at Akamai,
// "instagram.fabc1-1.fna.fbcdn.net" at Meta, "sharepoint.com.dual-spo-0005.spo-msedge.net"
// at Microsoft), and of the proxies companies read the web through, which
// put the address they fetch before their own ("paypal.com.mcas.ms" is
// paypal.com through Microsoft Defender): each registered to its operator, and
// none where anyone may choose the name ("paypal.com.s3.amazonaws.com")
const CARRIERS = ['aaplimg.com', 'adobedc.net', 'akadns.net', 'akahost.net', 'akamaitech.net', 'akamaized.net', 'alibabadns.com', 'alikunlun.com', 'alikunlun.net', 'cdngslb.com', 'cloud.microsoft', 'ebaycdn.net', 'edgekey.net', 'edgesuite.net', 'fbcdn.net', 'goskope.com', 'kunlunsl.com', 'mcas-gov.ms', 'mcas-gov.us', 'mcas.ms', 'myshn.net', 'omtrdc.net', 'pv-cdn.net', 'trafficmanager.net'];
const CARRIER_NAME = /(?:^|-)msedge\.net$/;
// The brands that write their name with a hyphen in their own domains, in
// any country ("credit-agricole.pl", "deutsche-bank.es", "sber-bank.by",
// "bouygues-telecom.fr")
const OWN_SPELLINGS = new Set(['bouygues-telecom', 'credit-agricole', 'credit-suisse', 'deutsche-bank', 'poczta-polska', 'sber-bank', 'wal-mart']);

// Suffixes put after a brand inside another domain ("paypal.com-verify.example"):
// the generic ones, which no ordinary name starts with, and country codes and
// others, which many do ("office.it-haus.de", "microsoft.co-op.org"), so
// these count fully only with a phishing word after them. The country codes
// are those of the countries the brands are of ("allegro.pl-oferta.example",
// "marktplaats.nl-betaling.example"), but for the ones that start as many
// names as "my" does.
const COUNTRY = 'ae|ar|at|au|be|br|ca|ch|cl|cn|cz|de|dk|es|eu|fi|fr|gr|hk|hu|id|ie|il|in|it|jp|kr|mx|nl|no|nz|pe|ph|pl|pt|ro|ru|sa|se|sg|sk|th|tr|tw|ua|uk|us|vn|za';
const SUFFIX_DASH = /^(?:com|net|org|gov|edu)-/;
const OTHER_SUFFIX_DASH = new RegExp(`^(?:co|info|biz|io|app|${COUNTRY})-`);
// (and fully, a second-level suffix spelled out: "paypal.co-uk.example")
const SECOND_SUFFIX_DASH = /^(?:co|com)-(?:uk|jp|au|nz|za|in|kr|br|id|il|th|ke)\b/;
// (the label after a brand in a subdomain that makes it the brand's address:
// "apple.com.verify.example", not "www.steam.ncsu.edu")
const SUFFIX_LABEL = new RegExp(`^(?:com|net|org|gov|edu|co|info|biz|io|app|${COUNTRY})$`);

// Letters from other scripts, and accented Latin letters, folded to the plain
// Latin letter they look like.
const CONFUSABLE = {
	а: 'a', ӓ: 'a', в: 'b', с: 'c', ԁ: 'd', е: 'e', ё: 'e', һ: 'h', і: 'i', ї: 'i', ј: 'j', к: 'k', ӏ: 'l', м: 'm', о: 'o', ө: 'o', р: 'p', ԛ: 'q', г: 'r', ѕ: 's', т: 't', у: 'y', ү: 'y', х: 'x', ԝ: 'w', ь: 'b', п: 'n', н: 'h',
	α: 'a', β: 'b', ϲ: 'c', ε: 'e', η: 'n', ι: 'i', ί: 'i', ϳ: 'j', κ: 'k', μ: 'u', ν: 'v', ο: 'o', ό: 'o', ρ: 'p', τ: 't', υ: 'u', χ: 'x', ω: 'w', γ: 'y',
	ɑ: 'a', ɡ: 'g', ɩ: 'i', ı: 'i', ȷ: 'j', ʟ: 'l', ɴ: 'n', ᴏ: 'o', ʀ: 'r', ѵ: 'v', ʏ: 'y', ᴢ: 'z',
	ⅰ: 'i', ⅼ: 'l', ⅽ: 'c', ⅾ: 'd', ⅿ: 'm', ℓ: 'l', '٠': 'o', '۰': 'o',
	à: 'a', á: 'a', â: 'a', ã: 'a', ä: 'a', å: 'a', ā: 'a', ă: 'a', ą: 'a', ç: 'c', ć: 'c', č: 'c', ď: 'd', è: 'e', é: 'e', ê: 'e', ë: 'e', ē: 'e', ę: 'e', ě: 'e', ì: 'i', í: 'i', î: 'i', ï: 'i', ī: 'i', ł: 'l', ñ: 'n', ń: 'n', ò: 'o', ó: 'o', ô: 'o', õ: 'o', ö: 'o', ø: 'o', ō: 'o', ő: 'o', ŕ: 'r', ř: 'r', ś: 's', š: 's', ş: 's', ť: 't', ţ: 't', ù: 'u', ú: 'u', û: 'u', ü: 'u', ū: 'u', ů: 'u', ű: 'u', ý: 'y', ÿ: 'y', ź: 'z', ż: 'z', ž: 'z',
};

// ASCII tricks: digits for letters and letter pairs that read as one letter.
const ASCII_TRICKS = [
	[/rn/g, 'm'],
	[/vv/g, 'w'],
	[/cl/g, 'd'],
	[/0/g, 'o'],
	[/1/g, 'l'],
	[/3/g, 'e'],
	[/4/g, 'a'],
	[/5/g, 's'],
	[/7/g, 't'],
	[/8/g, 'b'],
];

/**
 * Map every lookalike character of a domain label to the Latin letter it
 * imitates (Cyrillic "рауpаl" becomes "paypal").
 * @param {string} label
 * @returns {string}
 */
export function skeleton(label) {
	let out = '';
	for (const char of String(label).normalize('NFKC').toLowerCase()) {
		out += CONFUSABLE[char] || char;
	}

	return out;
}

// (each trick in a label doubles its variants: a label with more than
// seven kinds of trick, which no brand's imitation needs, gets the variants
// of its first seven, rather than thousands)
const MAX_VARIANTS = 256;

// (the tricks of letters alone that no ordinary word or name has: "cl" for
// "d", "vv" for "w", and below, "l" for "i"; not "rn" for "m", as in the
// name "stearn")
const LETTER_TRICKS = ASCII_TRICKS.filter(([pattern]) => pattern.source === 'cl' || pattern.source === 'vv');

function trickVariants(label, tricks = ASCII_TRICKS) {
	const variants = new Set([label]);
	for (const [pattern, letter] of tricks) {
		if (!label.includes(pattern.source)) {
			continue;
		}

		for (const value of variants) {
			if (variants.size >= MAX_VARIANTS / 2) {
				break;
			}

			variants.add(value.replace(pattern, letter));
		}
	}

	// "1" and "l" also stand for "i" (paypa1, 1nstagram).  (At most twice as
	// many.)
	for (const value of variants) {
		variants.add(value.replaceAll('l', 'i'));
	}

	variants.delete(label);
	return variants;
}

/**
 * Edit distance (Levenshtein, with two neighbouring letters swapped counting
 * as one edit: "paypla" is one from "paypal"), giving up once it exceeds
 * `max`.
 * @param {string} a
 * @param {string} b
 * @param {number} [max]
 * @returns {number}
 */
export function editDistance(a, b, max = 2) {
	if (Math.abs(a.length - b.length) > max) {
		return max + 1;
	}

	let before = null;
	let previous = Array.from({length: b.length + 1}, (_, i) => i);
	for (let i = 1; i <= a.length; i++) {
		const current = [i];
		let best = i;
		for (let j = 1; j <= b.length; j++) {
			const cost = a[i - 1] === b[j - 1] ? 0 : 1;
			current[j] = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost);
			if (before && i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
				current[j] = Math.min(current[j], before[j - 2] + 1);
			}

			best = Math.min(best, current[j]);
		}

		// (a swap reaches back two rows, but costs at least as much as the
		// row between, so the row's best still bounds what follows)
		if (best > max) {
			return max + 1;
		}

		before = previous;
		previous = current;
	}

	return previous[b.length];
}

/**
 * The brand a name joins to a phishing word ("paypallogin", "verifyamazon"),
 * or null. Brands of five letters or more only, and not brands that are words
 * themselves.
 * @param {string} name
 * @param {Set<string>} brands
 * @returns {string|null}
 */
export function brandWithPhishingWord(name, brands) {
	// (each way to cut the name in two: a word of four letters or more, a
	//  brand of five)
	for (let cut = 4; cut <= name.length - 4; cut++) {
		const start = name.slice(0, cut);
		const end = name.slice(cut);
		const brand = PHISHING_WORD.has(end) ? start : (PHISHING_WORD.has(start) ? end : '');
		if (brand.length >= 5 && brands.has(brand) && !WORD_BRANDS.has(brand)) {
			return brand;
		}
	}

	return null;
}

/**
 * Whether two names differ only by two neighbouring letters swapped (not
 * when they are the same).
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function isSwap(a, b) {
	if (a.length !== b.length || a === b) {
		return false;
	}

	let first = 0;
	while (a[first] === b[first]) {
		first++;
	}

	return a[first] === b[first + 1] && a[first + 1] === b[first] && a.slice(first + 2) === b.slice(first + 2);
}

// (letters of no one script, as the long vowel mark of Japanese "コーヒー",
//  are left out)
function labelScripts(label) {
	const scripts = new Set();
	for (const char of label) {
		if (/\p{L}/u.test(char) && !/[\p{Script=Common}\p{Script=Inherited}]/u.test(char)) {
			scripts.add(scriptOf(char));
		}
	}

	return scripts;
}

// Scripts that legitimately appear together in one label.
const COMPATIBLE = [
	new Set(['Han', 'Hiragana', 'Katakana', 'Latin']),
	new Set(['Han', 'Hangul', 'Latin']),
];

function isSuspiciousMix(scripts) {
	return scripts.size > 1 && !COMPATIBLE.some(allowed => [...scripts].every(script => allowed.has(script)));
}

/**
 * Detects domains made to look like well-known brands: lookalike letters from
 * other scripts (Cyrillic "а" for Latin "a"), mixed scripts in one label,
 * digit and letter swaps ("paypa1", "rnicrosoft"), one-letter typos
 * ("amazom"), and a brand name inside someone else's domain
 * ("paypal-secure-login.example", "paypal.com.account-check.example").
 *
 * Legitimate international domains (münchen.de, 日本.jp, сайт.рф) are not
 * flagged: only a domain that imitates a brand or mixes scripts is.
 */
export default class HomographDetector {
	/**
	 * @param {object} [options]
	 * @param {string[]} [options.brands] - names to protect, replacing BRANDS
	 * @param {string[]} [options.extraBrands] - names to protect as well as BRANDS
	 * @param {string[]} [options.allowlist] - registrable domains never flagged
	 * @param {boolean} [options.strictMode] - flag any brand name in a subdomain
	 */
	constructor(options) {
		options ??= {};
		this.options = options;
		this.brands = new Set([...(options.brands || BRANDS), ...(options.extraBrands || [])].map(brand => brand.toLowerCase()));
		this.allowlist = new Set([...OFFICIAL_DOMAINS, ...CARRIERS, ...(options.allowlist || [])].map(domain => domain.toLowerCase()));
		this.cache = new Map();
	}

	/**
	 * Analyse a host name, in Unicode or punycode.
	 * @param {string} domain
	 * @returns {{domain: string, unicode: string, isIDN: boolean, riskScore: number, riskFactors: string[], brand: string|null, recommendations: string[], confidence: number}}
	 */
	detectHomographAttack(domain) {
		const written = typeof domain === 'string' ? domain.trim().replace(/\.$/, '') : '';
		const input = written.toLowerCase();
		// (as written when it has a capital "I", which may stand for "l")
		const key = written.includes('I') ? written : input;
		if (this.cache.has(key)) {
			return this.cache.get(key);
		}

		const result = this.analyse(input, written);
		this.cache.set(key, result);
		if (this.cache.size > 5000) {
			this.cache.delete(this.cache.keys().next().value);
		}

		return result;
	}

	analyse(input, written = input) {
		const unicode = (input && domainToUnicode(input)) || input;
		const result = {
			domain: input,
			unicode,
			isIDN: unicode !== input || /[^ -~]/.test(unicode),
			riskScore: 0,
			riskFactors: [],
			brand: null,
			recommendations: [],
			confidence: 0,
		};
		const parsed = parseDomain(unicode);
		const name = parsed.domainWithoutSuffix;
		if (!name || parsed.isIp || this.allowlist.has(parsed.domain) || CARRIER_NAME.test(parsed.domain)) {
			return result;
		}

		const flag = (score, factor, brand) => {
			result.riskFactors.push(factor);
			if (score > result.riskScore) {
				result.riskScore = score;
				result.brand = brand;
			}
		};

		if (this.brands.has(name) || OWN_SPELLINGS.has(name)) {
			// The brand's own domain, under any suffix.
			return result;
		}

		// A capital "I" for "l" in a name of small letters ("googIe",
		// "paypaI-secure"), as the name or a part of it: not in one all in
		// capitals ("AIRBNB"), or in the suffix ("google.IE")
		const start = input.length - parsed.domain.length;
		const writtenName = written.slice(start, start + name.length);
		if (writtenName.includes('I') && /[a-z]/.test(writtenName) && /^[\w.-]+$/.test(written)) {
			const read = writtenName.replaceAll('I', 'l').toLowerCase();
			const lower = [name, ...name.split('-')];
			const capital = [read, ...read.split('-')].find((part, index) => part.length >= 4 && part !== lower[index] && this.brands.has(part));
			if (capital) {
				flag(0.85, `"${written}" imitates ${capital} with a capital I for l`, capital);
			}
		}

		// (a short brand, or one that is a word, reached by letters alone, as
		//  real names are: "lrs" for irs, "arnex" for amex, "stearn" for
		//  steam; a digit for a letter is plainly a trick, and so are "cl"
		//  for "d", "vv" for "w" and "l" for "i" in a brand of five letters
		//  or more, which no word has: "discorcl", "offlce", "strlpe")
		const trickScore = (brand, label) => (/\d/.test(label) || (brand.length >= 5 && (!WORD_BRANDS.has(brand) || trickVariants(label, LETTER_TRICKS).has(brand))) ? 0.85 : 0.6);
		const scripts = labelScripts(name);
		const folded = skeleton(name);
		if (isSuspiciousMix(scripts)) {
			flag(0.6, `"${unicode}" mixes ${[...scripts].join(' and ')} letters`, null);
		}

		const pieces = /^[a-z\d-]+$/.test(folded) && folded.includes('-') ? folded.split('-') : [];
		const phishy = pieces.some(piece => PHISHING_WORD.has(piece));
		const viaConfusable = folded === name ? null : [folded, folded.replaceAll('-', '')].find(value => this.brands.has(value));
		if (viaConfusable) {
			flag(0.95, `"${unicode}" imitates ${viaConfusable} with lookalike letters`, viaConfusable);
		} else if (/^[a-z\d-]+$/.test(folded)) {
			// (a name of digits alone is a number, not letters written as digits:
			//  "477.jp" is no "att")
			const variants = /[a-z]/.test(folded) ? trickVariants(folded) : new Set();
			const trick = [...variants].find(variant => this.brands.has(variant));
			if (trick) {
				flag(trickScore(trick, folded), `"${unicode}" imitates ${trick} by swapping characters`, trick);
			} else if (folded.length >= 5 && !SWAPPED_WORDS.has(folded)) {
				// (with the brand's first letter: another one makes another name,
				//  "ubank" and "eubank" for nubank, "lithub" for github,
				//  "oberbank" for sberbank, "zetflix", as a slip of the hand
				//  seldom does)
				const near = [...this.brands].find(brand => brand.length >= 5 && brand[0] === folded[0] && editDistance(folded, brand, 1) === 1 && isTypo(folded, brand));
				if (near) {
					flag(0.5, `"${unicode}" is one letter away from ${near}`, near);
				}
			}

			const written = name.split('-');
			// (a brand that is a word or short, "home-office", "zoom-lens",
			//  "e-visa", counts beside a phishing word only, or a brand that is
			//  a word of five letters or more beside only words of its
			//  services, "apple-support", "support-apple-id")
			const official = SPARKASSE.test(parsed.domain) && !phishy;
			// (beside nothing else: not "apple-valley-bank", "steam-trains-online")
			const service = piece => pieces.every(other => other === piece || (COMMON_WORD_BRANDS.get(piece)?.includes(other) ?? BRAND_SERVICE_WORDS.has(other)));
			const counts = piece => phishy || (piece.length >= 5 && (!WORD_BRANDS.has(piece) || service(piece)));
			for (const [index, piece] of pieces.entries()) {
				if (piece.length < 4 || official) {
					continue;
				}

				// (with lookalike letters, as any brand of five letters or more:
				//  "applé-store", not "e-vísa")
				if (this.brands.has(piece) && piece !== written[index] && (piece.length >= 5 || phishy)) {
					flag(0.95, `"${unicode}" imitates ${piece} with lookalike letters`, piece);
					break;
				}

				if (this.brands.has(piece) && counts(piece)) {
					flag(0.6, `"${unicode}" puts ${piece} inside another domain name`, piece);
					break;
				}

				const disguised = [...trickVariants(piece)].find(variant => this.brands.has(variant));
				if (disguised) {
					flag(trickScore(disguised, piece), `"${unicode}" imitates ${disguised} by swapping characters`, disguised);
					break;
				}
			}

			// A brand joined to a phishing word, in the name or one of its
			// parts, also with swapped characters ("paypa1login").
			for (const value of [folded, ...pieces, ...variants]) {
				const joined = brandWithPhishingWord(value, this.brands);
				if (joined) {
					flag(0.6, `"${unicode}" joins ${joined} to a phishing word`, joined);
					break;
				}
			}
		}

		// "paypal.com.account-check.example": a brand as a subdomain label.
		const subdomain = parsed.subdomain ? parsed.subdomain.split('.') : [];
		// (a brand that is a word or short, "www.steam.ncsu.edu", only as the
		//  start of an address, "apple.com.verify.example")
		const labels = subdomain.map(label => skeleton(label));
		// (or a brand that is a word of five letters or more, but for the
		//  common nouns, beside a phishing word in the rest of the name:
		//  "login.apple.example.com", "secure.apple.verify-account.com")
		const phishyHost = phishy || labels.some(label => PHISHING_WORD.has(label));
		const signInHost = labels.some(label => SIGN_IN_LABELS.has(label));
		const asBrand = label => signInHost && COMMON_WORD_BRANDS.get(label).length > 0;
		// (a brand alone before another service's name is that service's
		//  customer, "walmart.wd5.myworkdayjobs.com", "tiktok.en.softonic.com":
		//  it counts as the start of an address, or beside a phishing word)
		const phishyLabel = labels.some(label => label.split('-').some(piece => PHISHING_WORD.has(piece)));
		const brandLabel = labels.find((label, index) => label.length >= 4 && this.brands.has(label) && (this.options.strictMode || (label.length >= 5 && (COMMON_WORD_BRANDS.has(label) ? asBrand(label) : phishyHost || phishyLabel)) || SUFFIX_LABEL.test(labels[index + 1] ?? '')));
		if (brandLabel && (this.options.strictMode || subdomain.length >= 2)) {
			flag(0.6, `"${unicode}" puts ${brandLabel} in front of another domain`, brandLabel);
		}

		// "paypal.com-verify.example": the brand's address, then a dash.
		const last = subdomain.length > 0 ? skeleton(subdomain.at(-1)) : '';
		if (last.length >= 3 && this.brands.has(last) && (SUFFIX_DASH.test(folded) || OTHER_SUFFIX_DASH.test(folded))) {
			const strong = SUFFIX_DASH.test(folded) || SECOND_SUFFIX_DASH.test(folded) || PHISHING_WORDS.some(word => folded.includes(word));
			flag(strong ? 0.85 : 0.6, `"${unicode}" starts with ${last}'s address and continues into another domain`, last);
		}

		result.confidence = result.riskScore;
		if (result.riskScore >= 0.5) {
			result.recommendations.push(result.brand ? `Do not sign in from this link; go to ${result.brand}'s site directly` : 'Treat links to this domain as untrusted');
		}

		return result;
	}
}

export {HomographDetector};
