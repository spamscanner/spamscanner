import {readableText, unmixedText} from './tokenizer.js';

// Brands whose names appear in the display name and the subject of phishing
// mail, with the domains that are theirs: a name without a dot is the brand's
// domain under any suffix ("paypal" for paypal.com, paypal.de, paypal.com.au),
// one with a dot that domain and those under it, a regular expression a whole
// domain. So is a domain under the brand's own top-level domain
// ("applecard.apple"), and, for a brand of five letters or more, one whose
// name is the brand's name joined to the words after it in the display name,
// if they are no phishing words ("Apple Music" from applemusic.com, not "USPS
// Tracking" from uspstracking.top; see isOfficial). Any other domain, also one
// that starts with or holds the brand's name ("paypal-secure.top",
// "paypalsupport.xyz", "Amazon" from amazonorders.top, "PayPal" from
// paypalmail.com: names with "mail" or "news" are anyone's, so a brand's
// sending domains are listed), is not the brand's. Brands that are also
// people's names or words count only with a word that makes them the brand
// ("Chase Bank", "Norton Security", "Apple ID", or "Apple" alone, not "Big
// Apple Bagels" or "Apple Valley Dental"), "UPS" only in capitals ("Grown Ups
// Theatre" and "Follow Ups Team" do not name it), and some names are not the
// brand at all.
//
// A brand has the names people write it with, the first the one a finding
// reports: in its own script and in Latin letters ("Сбербанк" and "Sberbank",
// "三井住友" and "SMBC", "Itaú" and, without its accents, "Itau"), together
// or apart ("Wells Fargo", "WellsFargo", "Wells-Fargo"). The brands are those
// phishing mail claims to be around the world: each country's post, tax
// office, banks and payment services, and the services people everywhere
// hold an account with. Not a brand whose name mail of others carries as a
// matter of course: a shop's or a product's ("Walmart", "PlayStation"), one
// that is the software a company runs itself ("cPanel", "WordPress"), or a
// word people write of something else and no words beside it tell apart
// ("Zoom", "Square", "Discover").
//
// Apple counts alone ("Apple", "Apple Inc.", "Apple.com") or with one of its
// products, services or what phishing mail writes beside it as the very next
// word ("Apple ID", "Apple-Support", "Apple Customer Service", "The Apple
// Billing Team", "Apple Inc. Support", "Big Apple Store"), or after one word
// phishing mail puts between ("Apple Online Store", "Apple Media Services",
// "Apple Center Support", "Apple Gift Card"), each "Apple" read on its own
// ("Apple ID Support - Apple Seed"), not with such a word further on, as a
// business named for a place, a tree, a food or a person writes it ("Apple
// Valley Dental Support", "Apple Tree Daycare Team", "Apple Chevrolet
// Service Department", "Apple Federal Credit Union Billing", "Apple, Jane
// (Billing)"), nor with words of any shop ("Apple Center Kyiv", "Apple Gift
// Baskets", "Apple Online Sales", "Apple Orders"), nor with a word of
// another business after ("Apple Care Home", "Apple Music Lessons", "Apple
// Pay Day Loans").
const APPLE_NEXT = String.raw`id|icloud|itunes|pay|music|tv|card|cash|care|accounts?|arcade|one|developer|books|podcasts|billing|security|services?|team|wallet|store|app\s+store|appstore|support|customer|notifications?|subscriptions?|receipts?|invoices?|refunds?|verification|verify|alerts?|help|helpdesk|payments?|purchases?|notice|privacy|login|sign[\s-]?in|recovery|password|com`;
const APPLE_FILLER = String.raw`official|secure|cloud|media|device|online|order|center|gift`;
const APPLE_STRONG = String.raw`support|security|services?|team|store|billing|id|confirmation|accounts?|cards?`;
const APPLE_BUSINESS = String.raw`homes?|lessons?|realty|academy|loans?|day|advance|shop|repair|school|studio|clinic|gifts|bakery|salon|restaurant`;
const APPLE_ALONE = /^[^\p{L}\p{N}]*apple(?:[^\p{L}\p{N}]{1,3}inc)?[^\p{L}\p{N}]*$/u;
const APPLE_BESIDE = new RegExp(`(?<![\\p{L}\\p{N}])apple[^\\p{L}\\p{N}]{1,3}(?:inc[^\\p{L}\\p{N}]{1,3})?(?:${APPLE_NEXT}|(?:${APPLE_FILLER})[^\\p{L}\\p{N}]{1,3}(?:${APPLE_STRONG}))(?![^\\p{L}\\p{N}]{1,3}(?:${APPLE_BUSINESS})(?:$|[^\\p{L}\\p{N}]))(?![\\p{L}\\p{N}])`, 'giu');
// (and as a business's name, not with a word in capitals after that names
//  no part of Apple, as a place does, read up to the next "Apple" or a mark
//  other than a space: "Apple Store Kyiv", "Apple Help Desk Kyiv", "Apple
//  Store Berlin Mitte", not "Apple Store Online", "Apple Support Team" or
//  "Apple Security Department")
const APPLE_PART = new Set(['account', 'accounts', 'alert', 'alerts', 'app', 'apple', 'arcade', 'assistance', 'billing', 'books', 'card', 'care', 'cash', 'center', 'centre', 'cloud', 'confirmation', 'customer', 'department', 'dept', 'desk', 'device', 'division', 'eu', 'fraud', 'gift', 'global', 'help', 'helpdesk', 'icloud', 'id', 'inc', 'info', 'information', 'international', 'invoice', 'invoices', 'itunes', 'login', 'media', 'music', 'notice', 'notification', 'notifications', 'office', 'official', 'one', 'online', 'operations', 'order', 'orders', 'password', 'pay', 'payment', 'payments', 'plus', 'prevention', 'privacy', 'protection', 'purchase', 'purchases', 'receipt', 'receipts', 'recovery', 'refund', 'refunds', 'resolution', 'review', 'safety', 'secure', 'security', 'service', 'services', 'sign', 'signin', 'staff', 'store', 'subscription', 'subscriptions', 'support', 'team', 'tech', 'technical', 'tv', 'uk', 'unit', 'update', 'us', 'usa', 'verification', 'verify', 'wallet', 'worldwide']);
const NEXT_WORD = /[^\S\n]{1,8}([\p{L}\p{N}]+)/uy;
const MAX_AFTER = 8;
function namesPlace(name, end) {
	NEXT_WORD.lastIndex = end;
	for (let count = 0; count < MAX_AFTER; count++) {
		const word = NEXT_WORD.exec(name);
		if (word === null || word[1].toLowerCase() === 'apple') {
			return false;
		}

		if (/^\p{Lu}/u.test(word[1]) && !APPLE_PART.has(word[1].toLowerCase())) {
			return true;
		}
	}

	return false;
}

const APPLE = {test: (name, written) => APPLE_ALONE.test(name) || [...written.matchAll(APPLE_BESIDE)].some(found => !namesPlace(written, found.index + found[0].length))};

// A name that is a word, a person's name or an abbreviation of other things
// too names the brand alone, with nothing else but the words of its services
// ("Orange", "Orange Business", not "Orange County Choppers"), or right
// before such a word ("ING Bank", "Stripe Support"); or as its row adds
const SEPARATOR = String.raw`[^\p{L}\p{M}\p{N}]`;
// (each pattern is made when first tested, as each name's is below: a text
//  names few of the brands, and making them all takes most of a second)
const made = source => {
	let pattern;
	return {
		test(text) {
			pattern ??= new RegExp(source, 'u');
			return pattern.test(text);
		},
	};
};

const qualified = (name, words, also = '') => made(String.raw`^${SEPARATOR}*${name}(?:${SEPARATOR}+(?:${words}))*${SEPARATOR}*$|(?<![\p{L}\p{N}])${name}${SEPARATOR}{0,3}(?:${words})(?!\p{Script=Latin})${also && `|${also}`}`);

// (a country's post is none of what came after something: "Canada post-secondary")
const POST_COMPOUND = /post-\p{L}/u;
// (a government's own domain, where many countries name an office alike:
//  "hmrc.gov.uk", "ird.govt.nz", "incometax.gov.in")
const GOVERNMENT = /\.go(?:b|v|vt)?\.[a-z]{2}$|\.gov$/;

const AMAZON = ['amazon', 'amazonaws', 'amazonses', 'amazonpay', 'amazonbusiness', 'aws', 'audible', 'primevideo', 'asurion'];
const MICROSOFT = ['microsoft', 'microsoftonline', 'microsoft365', 'microsoftstore', 'microsoftemail', 'microsoftstoreemail', 'microsoftrewards', 'office', 'office365', 'outlook', 'live', 'hotmail', 'msn', 'skype', 'xbox', 'sharepoint', 'sharepointonline', 'onmicrosoft', 'azure', 'bing', 'powerapps'];
const ALIBABA = ['alibaba', 'alibaba-inc', 'alibabacloud', 'alibabagroup', 'aliyun', 'aliexpress', 'alipay', 'taobao', 'tmall', '1688'];
const DHL = ['dhl', 'dhlparcel', 'dhlecommerce', 'dhlecs', 'dhl-news', 'dpdhl', 'deutschepost'];
const DPD = ['dpd', 'dpdgroup', 'dpdlocal', 'dpdpredict', 'geopost', 'chronopost', 'seur', 'brt'];
const LA_POSTE = ['laposte', 'colissimo', 'chronopost', 'labanquepostale', 'notif-colissimo-laposte.info'];
const ROYAL_MAIL = ['royalmail', 'royalmailgroup', 'parcelforce'];
const INTUIT = ['intuit', 'quickbooks', 'turbotax'];
const NATWEST = ['natwest', 'natwestgroup', 'natwestmarkets', 'natwestinternational', 'rbs', 'ulsterbank'];
const WESTPAC = ['westpac', 'westpacgroup', 'stgeorge', 'bankofmelbourne', 'banksa'];
const UNICREDIT = ['unicredit', 'unicreditgroup', 'unicreditbulbank', 'hypovereinsbank', 'bankaustria', 'zaba.hr'];
const ERSTE = ['erstebank', 'erstegroup', 'erste-group', 'sparkasse.at', 'csas.cz', 'slsp.sk', 'bcr.ro'];
const BNP = ['bnpparibas', 'bnpparibasfortis', 'bnpparibas-pf', 'hellobank', 'consorsbank', 'cetelem', 'bnl.it'];
const SOCIETE_GENERALE = ['societegenerale', 'socgen', 'sgcib', 'boursorama', 'boursobank', 'brd.ro', 'kb.cz'];
const BPCE = ['caisse-epargne', 'banquepopulaire', 'groupebpce', 'bpce', 'gbp.ma', 'groupebcp.com'];
const CREDIT_MUTUEL = ['creditmutuel', 'credit-mutuel', 'cic', 'cmb.fr', 'cmso.com'];
const RAIFFEISEN = ['volksbank', 'raiffeisen', 'raiffeisenbank', 'rbinternational', 'vr.de', 'rb.cz', 'rba.hr', 'tatrabanka', /^(?:(?:volksbank|vr-?bank|voba|raiba|raiffeisenbank|raiffeisen|rb)-?[a-z\d-]+|[a-z\d-]+-?(?:volksbank|vr-?bank|voba|raiba|raiffeisenbank))\.(?:de|at|ch|it)$/];
const KBC = ['kbc', 'kbcbrussels', 'kbc-group', 'cbc.be', 'csob', 'kh.hu'];
const TELEFONICA = ['telefonica', 'movistar', 'vivo', 'integratel'];
const SANTANDER = ['santander', 'bancosantander', 'santanderbank', 'santanderconsumer', 'santanderconsumerusa', 'openbank'];
const MERCADO_LIBRE = ['mercadolibre', 'mercadolivre', 'mercadopago', 'mercadoenvios', 'mercadoshops'];
const SMBC = ['smbc', 'smbc-card', 'smbcnikko', 'smbcgroup', 'smbc-comics', 'smbctb', 'smbc-fs', 'smfg', 'vpass.ne.jp'];
const MUFG = ['mufg', 'mufgbank', 'kabu.com'];
const RAKUTEN = ['rakuten', 'rakuten-bank', 'rakuten-card', 'rakuten-sec', 'rakutenkobo', 'kobo', 'viber', /^rakuten-[a-z\d]+\.(?:co\.jp|net|com)$/];
const KDDI = ['kddi', 'au.com', 'auone.jp', 'jibunbank', 'kddi-fs'];
const DOCOMO = ['docomo', 'nttdocomo', 'd-card.jp', 'ntt.com'];
const SOFTBANK = ['softbank', 'ymobile'];
const TENCENT = ['tencent', 'tencentcloud', 'qq', 'wechat', 'weixin', 'tenpay', 'wechatpay'];
const KAKAO = ['kakao', 'kakaocorp', 'kakaobank', 'kakaopay', 'kakaoenterprise', 'daum.net', 'hanmail.net'];
const SBERBANK = ['sberbank', 'sber', 'sbrf', 'sberbank-ast'];
const SAFARICOM = ['safaricom', 'vodacom', 'vodafone'];
const INTERAC = ['interac', 'scotiabank', 'rbc', 'rbcroyalbank', 'td', 'bmo', 'cibc', 'desjardins', 'tangerine', 'simplii', 'nbc.ca', 'bnc.ca', 'atb', 'eqbank', 'laurentianbank', 'vancity', 'meridiancu', 'coastcapitalsavings', 'servus', 'central1'];
const SBI = ['sbi', 'sbi.bank.in', 'onlinesbi', 'sbicard', 'sbisec', 'sbigroup', 'netbk', 'sbishinseibank'];
const CANADA = ['canada.ca', 'gc.ca'];

// (a name that says the brand's word of something else names no brand: the
//  department of Santander and its universities, the Amazon rainforest, an
//  outlook on something as a magazine or a report is named, an adobe house)
const BRANDS = [
	[['paypal', 'ペイパル'], ['paypal', 'paypal-communication.com', 'paypal-communications.com', 'paypal-community.com', 'paypal-prepaid.com', 'paypalobjects.com', 'synchrony', 'synchronybank', 'xoom']],
	['apple', ['apple', 'icloud', 'itunes', 'me.com'], APPLE],
	['icloud', ['apple', 'icloud', 'itunes', 'me.com']],
	['itunes', ['apple', 'icloud', 'itunes', 'me.com']],
	[['microsoft', 'マイクロソフト', '微软', '微軟'], MICROSOFT],
	['outlook', ['microsoft', 'microsoftonline', 'microsoft365', 'office', 'office365', 'outlook', 'live', 'hotmail', 'msn'], null, /(?<![\p{L}\p{N}])(?!(?:microsoft|ms|office|your|my|our|new|re|fwd?|to|for|of|in|on|from|with|and|via|an?)\s)[\p{L}\p{N}]+\s+outlook(?![\p{L}\p{N}])|\boutlook\s+(?:magazine|india|money|report|traveller|business)\b/u],
	['office 365', ['microsoft', 'microsoftonline', 'microsoft365', 'office', 'office365', 'outlook', 'onmicrosoft', 'sharepoint']],
	['windows defender', MICROSOFT],
	[['amazon', 'アマゾン', 'アマゾンジャパン', '亚马逊', '亞馬遜'], AMAZON, null, /\bamazon\s+(?:rainforest|river|basin|conservation|watch|frontlines|jungle|region)\b|アマゾン(?:川|熱帯|流域)/],
	[['netflix', 'ネットフリックス', '넷플릭스', 'нетфликс'], ['netflix']],
	['docusign', ['docusign']],
	['dhl', DHL],
	['fedex', ['fedex'], null, /fedex\s?(?:forum|cup)|fedex st\.? jude/],
	['ups', ['ups', 'upsemail', 'upscapital', 'theupsstore'], null, null, true],
	[['usps', 'united states postal service', 'us postal service'], ['usps']],
	['coinbase', ['coinbase']],
	[['binance', '币安', '幣安', 'バイナンス'], ['binance']],
	['metamask', ['metamask', 'consensys']],
	['wells fargo', ['wellsfargo', 'wellsfargoadvisors', 'wellsfargoemail'], null, /wells fargo cent(?:er|re)/],
	['chase', ['chase', 'jpmchase', 'jpmorgan', 'jpmorganchase', 'jpmorgansecurities'], /\b(?:bank(?:ing)?|card|credit|online|alerts?|security|support|fraud|customer|service|team|jpmorgan)\b/],
	['bank of america', ['bankofamerica', 'bofa', 'bofaml', 'bofasecurities', 'merrill', 'merrilledge', 'merrilllynch', 'ml.com']],
	[['american express', 'アメリカン・エキスプレス', 'アメックス'], ['americanexpress', 'aexp', 'amex', 'amexgiftcard', 'membershipmail', 'csid', 'breadfinancial']],
	['facebook', ['facebook', 'facebookmail', 'meta', 'metamail']],
	['instagram', ['instagram', 'facebookmail', 'meta', 'metamail']],
	['whatsapp', ['whatsapp', 'facebookmail', 'meta', 'metamail']],
	['meta', ['meta', 'metamail', 'facebook', 'facebookmail', 'instagram', 'fb.com', 'workplace.com'], qualified('meta', String.raw`for\s+business|business(?:\s+(?:suite|support|help(?:\s+cent(?:er|re))?))?|support|platforms?|ads(?:\s+(?:manager|support|team))?|verified|pay|security|accounts?\s+cent(?:er|re)|copyright|privacy|help\s+cent(?:er|re)`)],
	[['linkedin', '领英'], ['linkedin']],
	['dropbox', ['dropbox', 'dropboxmail', 'hellosign']],
	['adobe', ['adobe', 'adobesystems', 'adobesign', 'echosign', 'adobelogin', 'behance'], null, /\badobe\s+(?:animal|veterinary|creek|house|homes?|realty|ranch|inn|books?|gallery|cafe|grill|hacienda|springs|walls)\b/],
	['google', ['google', 'googlegroups', 'googlemail', 'gmail', 'withgoogle', 'youtube'], null, /\bgoogle developers? groups?\b/],
	['gmail', ['google', 'googlemail', 'gmail']],
	[['yahoo', 'ヤフー'], ['yahoo', 'yahooinc', 'yahoo-inc', 'yahoonews', 'yahoo-corp.jp', 'yahoo-net.jp', 'lycorp.co.jp', 'aol']],
	['norton', ['norton', 'nortonlifelock', 'lifelock', 'gendigital', 'symantec'], /\b(?:security|anti-?virus|360|lifelock|support|team|subscription|renewal|billing|protection)\b/],
	[['mcafee', 'マカフィー'], ['mcafee', 'mcafeemail']],
	['geek squad', ['geeksquad', 'bestbuy']],
	[['irs', 'internal revenue service'], ['irs']],
	[['hmrc', 'hm revenue'], ['hmrc', 'gov.uk']],
	['royal mail', ROYAL_MAIL],
	['la poste', LA_POSTE],
	[['sparkasse', 'sparkassen'], ['sparkasse', /^(?:sparkasse|kreissparkasse|stadtsparkasse|ksk)-[a-z\d-]+\.(?:de|at)$/]],
	['santander', SANTANDER, null, /\b(?:universi|escuela|general|gobernaci|alcald|ayuntamiento|departamento|puerto|norte de|de paula|racing)/],
	[['hsbc', '滙豐', '匯豐', '汇丰'], ['hsbc', 'hsbcnet', 'hangseng']],
	['barclays', ['barclays', 'barclaycard', 'barclaycardus', 'barclayspartnerfinance', 'barclaysus'], null, /\bbarclays\s+cent(?:er|re)\b/],
	[['alibaba', '阿里巴巴', '阿里云', '阿里雲'], ALIBABA],

	// Services people everywhere hold an account with
	['ebay', ['ebay', 'ebayinc']],
	['booking.com', ['booking', 'bookingholdings']],
	['airbnb', ['airbnb', 'airbnbmail']],
	['stripe', ['stripe'], qualified('stripe', 'support|billing|payments?|inc|notifications?|radar|atlas|connect|express|security|verification')],
	['wise', ['wise', 'transferwise'], qualified('wise', 'business|support|payments?|accounts?|security|transfers?|plc|europe')],
	['revolut', ['revolut']],
	['klarna', ['klarna']],
	['venmo', ['venmo']],
	['cash app', ['cash.app', 'square', 'squareup', 'block.xyz']],
	['afterpay', ['afterpay', 'clearpay', 'squareup', 'block.xyz']],
	['payoneer', ['payoneer']],
	['skrill', ['skrill', 'paysafe']],
	['western union', ['westernunion', 'wu.com']],
	['moneygram', ['moneygram']],
	['standard chartered', ['standardchartered', 'sc.com']],
	['trust wallet', ['trustwallet']],
	['ledger', ['ledger', 'ledgerwallet'], qualified('ledger', 'live|wallet|support|security|nano|recover|sas|stax|flex')],
	['trezor', ['trezor', 'satoshilabs']],
	['kraken', ['kraken', 'krakenfx', 'payward'], qualified('kraken', String.raw`exchange|support|security|pro|crypto|futures|digital\s+asset\s+exchange`)],
	['crypto.com', ['crypto.com']],
	['blockchain.com', ['blockchain.com', 'blockchain.info']],
	['bybit', ['bybit']],
	['okx', ['okx', 'okex']],
	['kucoin', ['kucoin']],
	['bitstamp', ['bitstamp']],
	['etoro', ['etoro']],
	['robinhood', ['robinhood']],
	['opensea', ['opensea']],
	['uniswap', ['uniswap']],
	['godaddy', ['godaddy']],
	['namecheap', ['namecheap']],
	['ionos', ['ionos', 'ionos-status', '1and1', '1und1']],
	['1&1', ['1and1', '1und1', 'ionos', 'united-internet.de']],
	[['ovh', 'ovhcloud'], ['ovh', 'ovhcloud']],
	['hostinger', ['hostinger']],
	['bluehost', ['bluehost']],
	['hostgator', ['hostgator']],
	['strato', ['strato'], qualified('strato', 'ag|hosting|webshop|hidrive|kundenservice|server|webmail|domain|domains|mail|login|rechnung')],
	['aruba', ['aruba', 'arubapec', 'arubabusiness'], /aruba\.it|aruba\s+(?:s\.?p\.?a|pec|hosting|business|cloud|staff)|(?:staff|team)\s+aruba/],
	['gandi', ['gandi']],
	['squarespace', ['squarespace']],
	['wetransfer', ['wetransfer']],
	['intuit', [...INTUIT, 'intuitdome'], null, /intuit dome/],
	['quickbooks', INTUIT],
	['turbotax', INTUIT],
	['xero', ['xero']],
	['canva', ['canva']],
	['dpd', DPD, null, null, true],
	['gls', ['gls', 'gls-group', /^gls-[a-z-]+\.[a-z.]{2,6}$/], qualified('gls', 'pakete?|parcel|group|germany|italy|spain|hungary|express|delivery|zustellung|sendung|shipment|bank|versand|colis|paczka|csomag|logistics|kundenservice|paketshop|pakkeshop'), null, true],
	['hermes', ['hermes', 'myhermes', 'hermesworld', 'hermes-europe'], /hermes\s*(?:paket|versand|logistik|germany|paketshop|zustellung|sendung|lieferung|bote)|my\s*hermes/],
	['evri', ['evri']],
	[['aramex', 'أرامكس', 'ارامكس'], ['aramex']],
	['vodafone', ['vodafone', 'vodafoneziggo', 'vodafonemail', 'vodacom']],
	[['shopee', '蝦皮', '虾皮'], ['shopee', 'shopeemobile', 'shopeepay']],
	['lazada', ['lazada', 'lazada-seller.cn', 'alibaba-inc']],

	// The United States and Canada
	['capital one', ['capitalone', 'capitalonebank', 'capitaloneshopping'], null, /capital one (?:cent(?:er|re)|hall|caf[eé]|cup)/],
	['citi', ['citi', 'citibank', 'citicards', 'citigroup', 'citibankonline', 'banamex', 'citibanamex'], qualified('citi', 'bank|cards?|alerts?|group|online|mobile|private|business|gold|priority|thankyou|customer|fraud|security')],
	['citibank', ['citi', 'citibank', 'citicards', 'citigroup', 'citibankonline', 'banamex', 'citibanamex']],
	['pnc', ['pnc', 'pncbank'], qualified('pnc', String.raw`bank|alerts?|online|financial|virtual\s+wallet`), null, true],
	['truist', ['truist']],
	[['td bank', 'td canada trust'], ['td', 'tdbank', 'tdcanadatrust', 'tdameritrade', 'tdnewissues']],
	['navy federal', ['navyfederal']],
	['usaa', ['usaa']],
	['charles schwab', ['schwab', 'aboutschwab']],
	['social security administration', ['ssa.gov']],
	[['canada revenue agency', 'agence du revenu du canada', 'service canada'], CANADA],
	[['canada post', 'postes canada'], ['canadapost', 'postescanada', 'canadapost-postescanada.ca'], null, POST_COMPOUND],
	['interac', INTERAC],
	['rbc', ['rbc', 'rbcroyalbank', 'royalbank', 'rbcwealthmanagement', 'rbccm', 'rbcinsurance'], qualified('rbc', String.raw`royal|bank|online|direct|rewards|insurance|wealth|dominion|capital|avion`), null, true],
	['royal bank of canada', ['rbc', 'rbcroyalbank', 'royalbank']],
	['scotiabank', ['scotiabank', 'scotiamail', 'scotiabankcolpatria'], null, /scotiabank (?:cent(?:er|re)|saddledome|place|theatre)/],
	['bmo', ['bmo', 'bmoharris', 'bmoinvestorline'], qualified('bmo', 'bank|harris|financial|online|alerts?|mastercard|investorline|nesbitt'), null, true],
	['bank of montreal', ['bmo', 'bmoharris']],
	['cibc', ['cibc'], null, /cibc (?:run|square|theatre)/],
	['desjardins', ['desjardins'], qualified('desjardins', 'bank|banque|caisses?|assurances?|insurance|group|groupe|online', String.raw`(?:caisses?|mouvement|services?|accès\s*d|acces\s*d)\s+desjardins|acc[eè]sd`)],

	// The United Kingdom and Ireland
	['gov.uk', ['gov.uk', 'gov.scot', 'gov.wales', 'nhs.uk', 'nhs.net', 'police.uk', 'mod.uk', 'parliament.uk']],
	['dvla', ['gov.uk', 'dvla']],
	['tv licensing', ['tvlicensing']],
	['parcelforce', ROYAL_MAIL],
	[['lloyds bank', 'lloyds banking group'], ['lloydsbank', 'lloydsbanking', 'lloydsbankinggroup', 'lloydstsb']],
	['halifax', ['halifax', 'halifax-online', 'lloydsbanking', 'lloydsbankinggroup'], qualified('halifax', String.raw`bank|online|building\s+society|mortgages?|share\s*dealing|customer|fraud|security|alerts?`)],
	['natwest', NATWEST],
	['royal bank of scotland', NATWEST],
	['nationwide building society', ['nationwide', 'nationwide-communications.co.uk']],
	['monzo', ['monzo']],
	['starling bank', ['starlingbank']],
	['metro bank', ['metrobankonline', 'metrobank', 'metrobankdirect', 'metrobankcard']],
	['virgin money', ['virginmoney', 'virgin']],
	['virgin media', ['virginmedia', 'virginmediao2', 'virgin']],
	['british gas', ['britishgas', 'centrica']],
	['octopus energy', ['octopus.energy', 'octopusenergy', 'octoenergy']],
	['an post', ['anpost'], null, POST_COMPOUND],
	['aib', ['aib', 'aibgroup', 'aibgb', 'aibms'], qualified('aib', String.raw`bank|internet|online|mobile|alerts?|card|security|merchant|group`, String.raw`allied\s+irish`), null, true],
	['bank of ireland', ['bankofireland', 'bankofirelanduk', 'boi.com', '365online.com']],
	['permanent tsb', ['permanenttsb', 'ptsb']],
	['revenue commissioners', ['revenue.ie', 'ros.ie']],

	// Germany, Austria and Switzerland
	[['volksbank', 'volksbanken', 'raiffeisenbank', 'raiffeisen', 'vr bank', 'райффайзен', 'райффайзенбанк'], RAIFFEISEN],
	['postbank', ['postbank', 'deutsche-bank', 'db.com']],
	['commerzbank', ['commerzbank', 'comdirect']],
	['comdirect', ['commerzbank', 'comdirect']],
	['deutsche bank', ['deutsche-bank', 'deutschebank', 'db.com', 'postbank', 'norisbank']],
	['dkb', ['dkb'], null, null, true],
	['ing-diba', ['ing', 'ing-diba', 'ingdirect', 'ingbank', 'ingwb']],
	['ing', ['ing', 'ing-diba', 'ingdirect', 'ingbank', 'ingwb'], qualified('ing', String.raw`bank|diba|direct|belgi(?:ë|e|que|um)|nederland|groe?p|españa|italia|luxembourg|australia|deutschland|polska|romania|business|banking|kundenservice|klantenservice|śląski|slaski`, String.raw`(?<![\p{L}\p{N}])(?:mijn|my|mein|mon)\s+ing(?![\p{L}\p{N}])`), null, true],
	['n26', ['n26', 'number26']],
	['targobank', ['targobank']],
	['hypovereinsbank', UNICREDIT],
	['consorsbank', BNP],
	['advanzia', ['advanzia']],
	['deutsche post', DHL],
	[['telekom', 'deutsche telekom', 't-online'], ['telekom', 't-online', 't-mobile', 'magenta', 'telekom-dienste.de', 'turktelekom', 'tm.com.my', 'mts.rs', 'hrvatskitelekom', 't.ht.hr', 'a1.net', 'a1.group']],
	['gmx', ['gmx', 'web.de', '1und1', 'united-internet.de', 'mail.com']],
	['web.de', ['web.de', 'gmx', '1und1', 'united-internet.de']],
	['elster', ['elster.de', 'bund.de'], qualified('elster', 'online|portal|steuer|zertifikat|team|service|benachrichtigung', String.raw`mein\s*elster`)],
	[['bundeszentralamt für steuern', 'bundeszentralamt fuer steuern', 'bzst'], ['bzst.de', 'bund.de']],
	[['österreichische post', 'oesterreichische post'], ['post.at']],
	[['erste bank', 'erste group'], ERSTE],
	['bawag', ['bawag', 'bawagpsk', 'bawaggroup', 'easybank']],
	['bank austria', UNICREDIT],
	['finanzonline', ['gv.at']],
	[['swiss post', 'schweizerische post', 'la poste suisse'], ['post.ch', 'swisspost', 'postfinance'], null, POST_COMPOUND],
	['postfinance', ['postfinance', 'post.ch']],
	['ubs', ['ubs', 'credit-suisse'], null, null, true],
	['credit suisse', ['credit-suisse', 'ubs']],
	[['zürcher kantonalbank', 'zuercher kantonalbank'], ['zkb.ch']],
	['swisscom', ['swisscom', 'bluewin.ch']],
	['twint', ['twint']],
	['sbb', ['sbb'], null, null, true],
	['serafe', ['serafe.ch']],

	// France, Belgium, the Netherlands and Luxembourg
	['colissimo', LA_POSTE],
	['chronopost', [...LA_POSTE, ...DPD]],
	['mondial relay', ['mondialrelay', 'inpost']],
	['crédit agricole', ['credit-agricole', 'creditagricole', 'ca-cib', /^ca-[a-z\d-]+\.fr$/]],
	['bnp paribas', BNP, null, /bnp paribas (?:open|masters)/],
	['société générale', SOCIETE_GENERALE],
	['caisse d\'épargne', BPCE],
	['banque populaire', BPCE],
	['crédit mutuel', CREDIT_MUTUEL],
	['cic', CREDIT_MUTUEL, qualified('cic', String.raw`banque|bank|filbanque|en\s+ligne`), null, true],
	['lcl', ['lcl', 'credit-agricole'], qualified('lcl', String.raw`banque|bank|le\s+cr[eé]dit\s+lyonnais|mes\s+comptes|particuliers`), null, true],
	['la banque postale', LA_POSTE],
	[['boursorama', 'boursobank'], SOCIETE_GENERALE],
	['fortuneo', ['fortuneo']],
	['hello bank', BNP],
	['ameli', ['ameli.fr', 'assurance-maladie.fr'], qualified('ameli', 'fr|assurance maladie|assurance|compte|carte vitale|remboursement|santé|sante|info|service', String.raw`(?:compte|espace|service|carte)\s+ameli(?![\p{L}\p{N}])|(?<![\p{L}\p{N}])ameli\s{0,2}[:\]\-–—|]`)],
	[['impots.gouv', 'impôts.gouv', 'direction générale des finances publiques', 'dgfip'], ['gouv.fr']],
	['antai', ['gouv.fr', 'antai.fr'], null, null, true],
	[['france travail', 'pôle emploi'], ['francetravail', 'pole-emploi', 'gouv.fr']],
	['orange', ['orange', 'orange-business', 'orangebank', 'sosh', 'wanadoo.fr'], qualified('orange', String.raw`france|business|bank|money|et\s+moi|pro|mobile|fibre|internet|polska|belgium|belgique|romania|españa|slovensko|luxembourg|service\s+clients?|espace\s+client|facturation`, String.raw`(?:service\s+clients?|espace\s+client|facture|votre\s+conseiller)\s+orange(?![\p{L}\p{N}])`)],
	['sfr', ['sfr', 'red-by-sfr.fr', 'altice'], null, null, true],
	['bouygues telecom', ['bouyguestelecom', 'bouygues-telecom', 'bouygues', 'bbox.fr']],
	['freebox', ['free', 'free-mobile.fr', 'freebox', 'freetelecom', 'iliad.fr']],
	['edf', ['edf', 'edf-re', 'enedis', 'edfenergy'], null, null, true],
	['engie', ['engie', 'gdfsuez']],
	['totalenergies', ['totalenergies', 'total']],
	['leboncoin', ['leboncoin', 'adevinta']],
	['vinted', ['vinted']],
	[['ulys', 'vinci autoroutes'], ['ulys', 'vinci-autoroutes', 'vinci']],
	['rabobank', ['rabobank', 'rabo']],
	['abn amro', ['abnamro']],
	['sns bank', ['snsbank', 'sns.nl', 'devolksbank.nl']],
	['asn bank', ['asnbank']],
	['bunq', ['bunq']],
	['knab', ['knab'], qualified('knab', 'bank|bankieren|zakelijk|klantenservice|app')],
	['triodos', ['triodos']],
	['postnl', ['postnl']],
	['belastingdienst', ['belastingdienst', 'overheid.nl', 'toeslagen.nl', 'rijksoverheid.nl']],
	['digid', ['digid', 'logius.nl', 'overheid.nl']],
	['mijnoverheid', ['mijnoverheid', 'overheid.nl']],
	['cjib', ['cjib'], null, null, true],
	['kpn', ['kpn', 'kpnmail.nl', 'xs4all.nl'], null, null, true],
	['ziggo', ['ziggo', 'vodafoneziggo']],
	['odido', ['odido', 't-mobile']],
	['international card services', ['icscards']],
	['tikkie', ['tikkie', 'abnamro']],
	['bol.com', ['bol.com']],
	['bpost', ['bpost', 'bpostgroup']],
	['kbc', KBC, null, null, true],
	['belfius', ['belfius']],
	['argenta', ['argenta'], qualified('argenta', 'bank|spaarbank|assuranties|app|banking|groep|be')],
	['itsme', ['itsme', 'itsme-id.com']],
	['proximus', ['proximus', 'skynet.be']],
	['telenet', ['telenet', 'telenetgroup']],
	['card stop', ['cardstop']],
	[['myminfin', 'spf finances', 'fod financiën'], ['fgov.be', 'belgium.be']],
	['luxtrust', ['luxtrust']],
	['post luxembourg', ['post.lu']],

	// Denmark, Norway, Sweden, Finland and Iceland
	['postnord', ['postnord', 'posten.se', 'postdanmark.dk']],
	['posten', ['posten', 'bring', 'postnord'], qualified('posten', 'norge|bring|pakke|sporing')],
	['bankid', ['bankid']],
	['mitid', ['mitid', 'digst.dk']],
	['e-boks', ['e-boks']],
	['mobilepay', ['mobilepay', 'vippsmobilepay']],
	['vipps', ['vipps', 'vippsmobilepay']],
	['kivra', ['kivra']],
	['swedbank', ['swedbank', 'swedbankpay']],
	['nordea', ['nordea']],
	['handelsbanken', ['handelsbanken']],
	['seb', ['seb', 'sebgroup', 'groupeseb'], qualified('seb', 'bank|banken|kort|internetbank|pank|bankas', String.raw`skandinaviska\s+enskilda`), null, true],
	['danske bank', ['danskebank']],
	['dnb', ['dnb'], qualified('dnb', 'bank|asa|nettbank|kundeservice|kort|sparing'), null, true],
	['sparebank 1', ['sparebank1']],
	['skatteverket', ['skatteverket']],
	['skatteetaten', ['skatteetaten', 'altinn.no']],
	[['skattestyrelsen', 'skat.dk'], ['skat.dk', 'skattestyrelsen.dk', 'sktst.dk', 'skatteforvaltningen.dk']],
	['altinn', ['altinn', 'digdir.no']],
	['borger.dk', ['borger.dk', 'digst.dk']],
	['telia', ['telia', 'teliacompany']],
	['telenor', ['telenor']],
	['posti', ['posti', 'opost.fi'], qualified('posti', 'oy|group|asiakaspalvelu|palvelut', 'omaposti')],
	[['osuuspankki', 'op financial group'], ['op.fi']],
	['s-pankki', ['s-pankki']],
	[['verohallinto', 'omavero'], ['vero.fi']],
	['suomi.fi', ['suomi.fi', 'dvv.fi']],
	['íslandsbanki', ['islandsbanki.is']],
	['landsbankinn', ['landsbankinn.is']],
	['arion banki', ['arionbanki.is']],
	['pósturinn', ['postur.is', 'posturinn.is']],

	// Spain, Portugal, Italy, Greece, Cyprus and Malta
	['correos', ['correos', 'correosexpress', 'gob.es'], qualified('correos', String.raw`españa|express|paq|paquetería|exprés|clientes|y\s+telégrafos`, String.raw`sociedad\s+estatal\s+correos|grupo\s+correos`)],
	[['agencia tributaria', 'aeat'], ['agenciatributaria', 'aeat', 'gob.es'], null, /agencia tributaria (?:de|canaria|valenciana)/],
	[['tesorería general de la seguridad social', 'dirección general de tráfico'], ['seg-social.es', 'dgt.es', 'gob.es']],
	['dgt', ['dgt.es', 'gob.es'], qualified('dgt', 'multas?|tráfico|trafico|sede|notificación|notificacion'), null, true],
	['bbva', ['bbva', 'bbvanet', 'bbvaprovincial', 'garantibbva']],
	[['caixabank', 'la caixa'], ['caixabank', 'lacaixa', 'caixabankpc', 'fundacionlacaixa', 'caixaforum', 'bancobpi', 'bpi.pt']],
	[['banco sabadell', 'banc sabadell'], ['bancsabadell', 'bancosabadell', 'grupbancsabadell']],
	['bankinter', ['bankinter']],
	['unicaja', ['unicaja', 'unicajabanco']],
	['abanca', ['abanca']],
	['kutxabank', ['kutxabank']],
	['openbank', SANTANDER],
	['ibercaja', ['ibercaja']],
	['cajamar', ['cajamar', 'grupocooperativocajamar']],
	['bizum', ['bizum']],
	['endesa', ['endesa', 'endesaclientes', 'enel']],
	['iberdrola', ['iberdrola', 'marketingiberdrola']],
	['naturgy', ['naturgy']],
	[['movistar', 'telefónica'], TELEFONICA],
	['mrw', ['mrw'], null, null, true],
	['seur', DPD, null, null, true],
	['wallapop', ['wallapop']],
	['ctt', ['ctt', 'cttexpresso', 'cttexpress'], qualified('ctt', String.raw`correios|expresso|e-?commerce|portugal|encomendas?`), null, true],
	[['autoridade tributária', 'portal das finanças'], ['gov.pt', GOVERNMENT]],
	['caixa geral de depósitos', ['cgd']],
	['millennium bcp', ['millenniumbcp', 'bcp.pt']],
	['novobanco', ['novobanco']],
	['banco bpi', ['bancobpi', 'bpi.pt', 'caixabank']],
	[['mb way', 'multibanco'], ['mbway', 'multibanco', 'sibs']],
	['edp', ['edp', 'e-redes.pt'], qualified('edp', 'comercial|energia|distribuição|renováveis|españa|brasil|cliente'), null, true],
	['meo', ['meo', 'altice.pt', 'telecom.pt', 'sapo.pt'], qualified('meo', 'empresas|clientes?|fatura|energia'), null, true],
	['via verde', ['viaverde'], qualified('via verde', 'portugal|serviços|servicos|pagamentos?|portagens')],
	[['poste italiane', 'poste.it', 'postepay', 'bancoposta', 'posteid'], ['poste', 'posteitaliane', 'postepay', 'postevita', 'sda.it']],
	['intesa sanpaolo', ['intesasanpaolo', 'bancaintesa', 'isybank', 'fideuram', 'vub']],
	['unicredit', UNICREDIT],
	['bper', ['bper', 'gruppobper']],
	['banco bpm', ['bancobpm', 'gruppobancobpm']],
	['monte dei paschi', ['mps.it', 'gruppomps.it', 'montepaschi']],
	['bnl', BNP, qualified('bnl', String.raw`bnp|gruppo|banca|positivity`, String.raw`banca\s+nazionale\s+del\s+lavoro`), null, true],
	[['fineco', 'finecobank'], ['fineco', 'finecobank']],
	['mediolanum', ['mediolanum', 'bancamediolanum']],
	['nexi', ['nexi', 'nexigroup', 'nets.eu']],
	['inps', ['inps', 'gov.it'], null, null, true],
	[['agenzia delle entrate', 'agenzia entrate'], ['agenziaentrate', 'agenziaentrateriscossione', 'gov.it']],
	['pagopa', ['pagopa', 'italia.it', 'gov.it']],
	['enel', ['enel', 'enelenergia', 'enelx', 'e-distribuzione', 'endesa']],
	['telepass', ['telepass']],
	['brt', DPD, qualified('brt', String.raw`corriere|espresso|s\.?p\.?a`, 'bartolini'), null, true],
	['libero', ['libero.it', 'italiaonline.it', 'virgilio.it', 'iol.it'], qualified('libero', 'mail', String.raw`staff\s+libero|libero\.it`)],
	['register.it', ['register.it']],
	['elta', ['elta.gr', 'elta-courier.gr'], null, null, true],
	[['ελτα', 'ελληνικά ταχυδρομεία'], ['elta.gr', 'elta-courier.gr']],
	[['national bank of greece', 'εθνική τράπεζα'], ['nbg']],
	[['piraeus bank', 'τράπεζα πειραιώς'], ['piraeusbank', 'winbank.gr', 'piraeusholdings.gr']],
	['alpha bank', ['alpha.gr', 'alphabank', 'alphaholdings.gr']],
	['eurobank', ['eurobank', 'eurobankholdings.gr']],
	[['aade', 'ααδε'], ['aade.gr', 'gov.gr', 'gsis.gr']],
	['gov.gr', ['gov.gr']],
	['bank of cyprus', ['bankofcyprus']],
	['hellenic bank', ['hellenicbank']],
	['bank of valletta', ['bov.com']],
	['maltapost', ['maltapost']],

	// Poland, Czechia, Slovakia, Hungary, Romania, Bulgaria, the Balkans and
	// the Baltic states
	['inpost', ['inpost', 'inpostpay', 'paczkomaty']],
	['poczta polska', ['poczta-polska', 'pocztapolska', 'envelo.pl', 'pocztex.pl']],
	[['pko bank polski', 'pko bp', 'ipko'], ['pkobp', 'ipko', 'pko.pl']],
	['mbank', ['mbank']],
	[['bank pekao', 'pekao'], ['pekao', 'pekao24', 'pekao.com.pl']],
	['alior bank', ['aliorbank', 'alior.pl']],
	['bank millennium', ['bankmillennium']],
	['allegro', ['allegro', 'allegromail.pl', 'allegrogroup', 'allegrolokalnie'], qualified('allegro', String.raw`pay|lokalnie|smart|finance|polska`, String.raw`allegro\.pl`)],
	['olx', ['olx', 'olxgroup', 'newsolx.com.br']],
	['blik', ['blik', 'polskistandardplatnosci.pl'], qualified('blik', String.raw`płatności|platnosci|kod|przelew|pay`)],
	['orlen paczka', ['orlenpaczka', 'orlen']],
	[['ministerstwo finansów', 'krajowa administracja skarbowa', 'e-urząd skarbowy', 'mobywatel'], ['gov.pl']],
	['zus', ['zus'], qualified('zus', String.raw`pue|eplatnik|płatnik`, String.raw`zak[lł]ad\s+ubezpiecze[nń]\s+spo[lł]ecznych`), null, true],
	['česká spořitelna', ERSTE],
	['čsob', KBC],
	['komerční banka', SOCIETE_GENERALE],
	['air bank', ['airbank']],
	['fio banka', ['fio']],
	['česká pošta', ['cpost.cz', 'ceskaposta', 'balikovna.cz']],
	[['zásilkovna', 'packeta'], ['zasilkovna', 'packeta']],
	['finanční správa', ['financnisprava', 'gov.cz', 'mfcr.cz']],
	['slovenská sporiteľňa', ERSTE],
	['tatra banka', RAIFFEISEN],
	[['všeobecná úverová banka', 'vúb banka'], ['vub', 'intesasanpaolo']],
	['slovenská pošta', ['posta.sk']],
	['finančná správa', ['financnasprava', 'gov.sk']],
	['otp bank', ['otpbank', 'otp.hu', 'otpbanka', 'otpmobil', 'simplepay.hu', 'dskbank']],
	['magyar posta', ['posta.hu']],
	['k&h bank', KBC],
	['mbh bank', ['mbhbank']],
	['nemzeti adó- és vámhivatal', ['gov.hu']],
	['mvm', ['mvm', 'mvmnext'], null, null, true],
	['foxpost', ['foxpost']],
	['banca transilvania', ['bancatransilvania', 'btrl.ro']],
	['bcr', [...ERSTE, 'bancobcr.com'], qualified('bcr', String.raw`banca|george|erste`, String.raw`banca\s+comercial[aă]\s+rom[aâ]n[aă]|banco\s+de\s+costa\s+rica`), null, true],
	['brd', SOCIETE_GENERALE, qualified('brd', String.raw`groupe|soci[eé]t[eé]\s+g[eé]n[eé]rale`), null, true],
	[['poșta română', 'poşta română'], ['posta-romana.ro', 'postaromana']],
	['fan courier', ['fancourier', 'fan-courier']],
	['cargus', ['cargus', 'urgentcargus']],
	['anaf', ['anaf.ro', 'mfinante.ro', 'gov.ro'], null, null, true],
	[['bulgarian posts', 'български пощи'], ['bgpost.bg']],
	[['econt', 'еконт'], ['econt']],
	['спиди', ['speedy.bg']],
	[['dsk bank', 'банка дск'], ['dskbank', 'otpbank']],
	['национална агенция за приходите', ['nra.bg', 'nap.bg', 'government.bg', 'egov.bg']],
	['hrvatska pošta', ['posta.hr', 'hp.hr']],
	['zagrebačka banka', UNICREDIT],
	['privredna banka zagreb', ['pbz.hr', 'intesasanpaolo']],
	['pošta slovenije', ['posta.si']],
	['nlb', ['nlb', 'nlbkb.rs'], null, null, true],
	[['pošta srbije', 'пошта србије'], ['posta.rs']],
	['luminor', ['luminor']],
	['lhv', ['lhv'], null, null, true],
	['omniva', ['omniva']],
	['latvijas pasts', ['pasts.lv']],
	['lietuvos paštas', ['post.lt', 'lp.lt']],
	['citadele', ['citadele']],

	// Russia, Ukraine, Belarus, Kazakhstan and Turkey
	[['sberbank', 'сбербанк', 'сбер'], SBERBANK],
	[['tinkoff', 'тинькофф', 'т-банк', 't-bank'], ['tinkoff', 'tbank', 'tcsbank.ru']],
	[['vtb', 'втб'], ['vtb', 'vtb24']],
	[['alfa-bank', 'alfa bank', 'альфа-банк', 'альфа банк'], ['alfabank', 'alfa-bank']],
	[['gazprombank', 'газпромбанк'], ['gazprombank', 'gpb.ru']],
	[['gosuslugi', 'госуслуги'], ['gosuslugi', 'gov.ru']],
	[['russian post', 'почта россии'], ['pochta', 'russianpost'], null, POST_COMPOUND],
	[['yandex', 'яндекс'], ['yandex', 'yandex-team.ru', 'ya.ru']],
	[['vkontakte', 'вконтакте'], ['vk.com', 'vk.ru', 'vkontakte', 'vk.company']],
	['mail.ru', ['mail.ru', 'vk.company', 'list.ru', 'bk.ru', 'inbox.ru']],
	['ozon', ['ozon', 'ozonbank'], qualified('ozon', String.raw`\.ru|bank|банк|travel|seller|маркетплейс|доставка`)],
	['озон', ['ozon', 'ozonbank'], qualified('озон', String.raw`банк|доставка|маркетплейс|\.ru`)],
	[['wildberries', 'вайлдберриз'], ['wildberries', 'wb.ru']],
	[['avito', 'авито'], ['avito']],
	[['cdek', 'сдэк'], ['cdek']],
	[['федеральная налоговая служба', 'фнс россии'], ['nalog.ru', 'gov.ru']],
	['мтс', ['mts'], null, null, true],
	['билайн', ['beeline']],
	[['privatbank', 'приватбанк', 'privat24', 'приват24'], ['privatbank', 'privat24', 'pb.ua']],
	[['monobank', 'монобанк'], ['monobank']],
	[['oschadbank', 'ощадбанк'], ['oschadbank']],
	[['nova poshta', 'нова пошта', 'nova post'], ['novaposhta', 'novapost', 'np.ua'], null, POST_COMPOUND],
	[['ukrposhta', 'укрпошта'], ['ukrposhta']],
	[['kyivstar', 'київстар'], ['kyivstar']],
	['rozetka', ['rozetka']],
	[['belarusbank', 'беларусбанк'], ['belarusbank', 'asb.by']],
	[['belpost', 'белпочта'], ['belpost']],
	['kaspi', ['kaspi', 'kaspibank']],
	[['halyk bank', 'халык банк'], ['halykbank', 'halyk', 'homebank.kz']],
	[['kazpost', 'казпочта'], ['kazpost', 'post.kz']],
	['egov.kz', ['egov.kz', 'gov.kz']],
	['ptt', ['ptt', 'pttkargo', 'pttavm', 'gov.tr'], qualified('ptt', String.raw`kargo|a\.?ş|avm|bank|posta`), null, true],
	[['garanti bbva', 'garanti bankası'], ['garantibbva', 'garanti', 'bbva']],
	['akbank', ['akbank']],
	[['iş bankası', 'isbank'], ['isbank', 'is.com.tr']],
	[['ziraat bankası', 'ziraat bank'], ['ziraatbank', 'ziraat', 'ziraatkatilim']],
	['yapı kredi', ['yapikredi']],
	['halkbank', ['halkbank']],
	['vakıfbank', ['vakifbank']],
	['denizbank', ['denizbank']],
	[['qnb', 'qnb finansbank', 'enpara'], ['qnb', 'qnbfinansbank', 'qnbalahli', 'enpara']],
	['papara', ['papara']],
	[['e-devlet', 'gelir idaresi başkanlığı'], ['gov.tr']],
	['turkcell', ['turkcell']],
	['türk telekom', ['turktelekom', 'ttnet.com.tr']],
	['trendyol', ['trendyol', 'trendyolmail']],
	['hepsiburada', ['hepsiburada']],
	['aras kargo', ['araskargo']],
	['mng kargo', ['mngkargo', 'dhlecommerce']],

	// The Middle East and Africa
	['emirates nbd', ['emiratesnbd']],
	[['emirates post', 'بريد الإمارات'], ['emiratespost', 'epg.gov.ae', '7x.ae'], null, POST_COMPOUND],
	[['adcb', 'abu dhabi commercial bank'], ['adcb']],
	['first abu dhabi bank', ['bankfab']],
	['mashreq', ['mashreq', 'mashreqbank'], qualified('mashreq', String.raw`bank|neo|online|al\s+islami|global`)],
	['etisalat', ['etisalat', 'eand.com']],
	[['uae pass', 'dubai police', 'شرطة دبي'], ['gov.ae', 'uaepass.ae']],
	['dewa', ['gov.ae'], null, null, true],
	[['al rajhi bank', 'alrajhi bank', 'مصرف الراجحي'], ['alrajhibank']],
	[['saudi national bank', 'البنك الأهلي السعودي'], ['alahli']],
	[['riyad bank', 'بنك الرياض'], ['riyadbank']],
	['stc', ['stc', 'stcpay', 'stcbank'], qualified('stc', 'pay|bank|business|ksa|bahrain|kuwait', String.raw`saudi\s+telecom`), null, true],
	[['absher', 'zatca', 'هيئة الزكاة والضريبة والجمارك'], ['gov.sa', 'absher.sa']],
	[['saudi post', 'البريد السعودي'], ['splonline.com.sa', 'sp.com.sa', 'spl.com.sa'], null, POST_COMPOUND],
	[['qatar post', 'بريد قطر'], ['qatarpost.qa', 'qpost.com.qa'], null, POST_COMPOUND],
	[['national bank of kuwait', 'بنك الكويت الوطني'], ['nbk']],
	[['kuwait finance house', 'بيت التمويل الكويتي'], ['kfh']],
	[['national bank of egypt', 'البنك الأهلي المصري'], ['nbe.com.eg']],
	[['banque misr', 'بنك مصر'], ['banquemisr']],
	[['egypt post', 'البريد المصري'], ['egyptpost', 'gov.eg'], null, POST_COMPOUND],
	['fawry', ['fawry', 'myfawry']],
	[['israel post', 'דואר ישראל'], ['israelpost'], null, POST_COMPOUND],
	[['bank hapoalim', 'בנק הפועלים'], ['bankhapoalim', 'poalim.co.il']],
	[['bank leumi', 'בנק לאומי'], ['leumi', 'bankleumi', 'leumi-card.co.il', 'max.co.il']],
	['בנק דיסקונט', ['discountbank.co.il', 'telebank.co.il']],
	[['mizrahi tefahot', 'מזרחי טפחות'], ['mizrahi-tefahot.co.il', 'umtb.co.il']],
	[['isracard', 'ישראכרט'], ['isracard']],
	['ויזה כאל', ['cal-online.co.il']],
	[['רשות המסים', 'ביטוח לאומי'], ['gov.il']],
	['standard bank', ['standardbank', 'stanbicbank', 'stanbicibtc', 'stanbic'], null, /standard bank(?:ing)? (?:transfer|account|details|holiday|wire|practice|procedure|fee|charge)/],
	['absa', ['absa']],
	['capitec', ['capitec', 'capitecbank']],
	['nedbank', ['nedbank']],
	['fnb', ['fnb', 'firstrand', 'fnbnamibia', 'fnbbotswana', /^fnb[a-z\d-]*\.(?:com|bank|net|us)$/], qualified('fnb', String.raw`south\s+africa|online|app|ebucks|connect|rewards|incontact|namibia|botswana|zambia`), null, true],
	['sars', ['gov.za', 'sarsefiling.co.za'], qualified('sars', String.raw`e-?filing|refund|notification|tax|south\s+africa`, String.raw`south\s+african\s+revenue`), null, true],
	[['sa post office', 'south african post office'], ['postoffice.co.za', 'sapo.co.za']],
	['vodacom', SAFARICOM],
	['mtn', ['mtn', 'mtnonline'], qualified('mtn', String.raw`momo|mobile\s+money|group|nigeria|ghana|south\s+africa|uganda|business|online`), null, true],
	['telkom', ['telkom', 'telkomsa.net']],
	[['safaricom', 'm-pesa', 'm pesa'], SAFARICOM],
	['equity bank', ['equitybank', 'equitygroupholdings', 'equitybankgroup'], null, /home\s*equity bank/],
	[['gtbank', 'guaranty trust bank'], ['gtbank', 'gtcoplc', 'gtco']],
	['zenith bank', ['zenithbank']],
	['access bank plc', ['accessbankplc']],
	['first bank of nigeria', ['firstbanknigeria', 'firstbankgroup', 'fbnholdings']],
	['united bank for africa', ['ubagroup']],
	['ecobank', ['ecobank']],
	['flutterwave', ['flutterwave', 'flutterwavego']],
	['paystack', ['paystack']],
	['attijariwafa bank', ['attijariwafa', 'attijariwafabank']],
	[['poste maroc', 'barid al-maghrib', 'بريد المغرب'], ['poste.ma', 'baridbank.ma', 'albaridbank.ma']],
	[['algérie poste', 'بريد الجزائر'], ['poste.dz']],
	[['la poste tunisienne', 'البريد التونسي'], ['poste.tn']],

	// India, Pakistan and Bangladesh
	['sbi', SBI, qualified('sbi', String.raw`bank|cards?|yono|online|net\s*banking|kyc|rewards|life|securities|alerts?|customer|credit|証券|新生銀行|ホールディングス|holdings`, '住信sbiネット銀行'), null, true],
	['state bank of india', SBI],
	['hdfc bank', ['hdfcbank', 'hdfc', 'hdfc.bank.in', 'hdfcbank.bank.in']],
	['icici bank', ['icicibank', 'icici.bank.in', 'icicibank.bank.in', 'icicidirect']],
	['axis bank', ['axisbank', 'axis.bank.in', 'axisbank.bank.in']],
	[['kotak mahindra', 'kotak bank'], ['kotak', 'kotakbank', 'kotak.bank.in']],
	['punjab national bank', ['pnbindia', 'pnb.bank.in']],
	['bank of baroda', ['bankofbaroda', 'bankofbaroda.bank.in']],
	['paytm', ['paytm', 'paytmbank']],
	['phonepe', ['phonepe']],
	[['india post', 'भारतीय डाक'], ['gov.in', 'ippbonline.com'], null, POST_COMPOUND],
	[['income tax department', 'आयकर विभाग', 'uidai'], ['gov.in', 'uidai.net.in', GOVERNMENT]],
	['irctc', ['irctc']],
	['airtel', ['airtel']],
	['habib bank', ['hbl', 'habibbank']],
	['easypaisa', ['easypaisa.com.pk', 'telenorbank.pk']],
	['jazzcash', ['jazzcash.com.pk', 'jazz.com.pk']],
	['bkash', ['bkash']],

	// Japan
	[['smbc', '三井住友', 'sumitomo mitsui'], SMBC],
	[['mufg', '三菱ufj'], MUFG],
	[['mizuho bank', 'みずほ銀行', 'みずほ証券', 'みずほダイレクト', 'みずほフィナンシャル'], ['mizuhobank', 'mizuho-fg', 'mizuho-sc', 'mizuho-tb', 'mizuhogroup']],
	[['japan post bank', 'ゆうちょ銀行', 'ゆうちょダイレクト', 'ゆうちょ認証'], ['japanpost']],
	[['resona bank', 'りそな銀行', 'りそなグループ', '埼玉りそな'], ['resonabank', 'resona-gr', 'saitamaresona']],
	[['rakuten', '楽天'], RAKUTEN, null, /楽天(?:的|家|主義|市場店)/],
	[['aeon card', 'イオンカード', 'イオン銀行', 'イオンフィナンシャル', 'イオンクレジット'], ['aeon', 'aeonbank', 'aeoncredit']],
	[['saison card', 'セゾンカード', 'クレディセゾン'], ['saisoncard', 'saison']],
	[['エポスカード', 'エポスnet'], ['eposcard', '0101.co.jp', '01epos.jp']],
	['jcb', ['jcb', 'jcbcard'], qualified('jcb', String.raw`カード|card|co\.?,?\s*ltd|会員|ブランド|ご利用`, String.raw`my\s*jcb|ジェーシービー`), null, true],
	[['ビューカード', 'view\'s net'], ['viewsnet.jp', 'jreast.co.jp', 'viewcard.co.jp']],
	[['えきねっと', 'jr東日本'], ['eki-net.com', 'jreast.co.jp']],
	[['jr東海', 'スマートex', 'エクスプレス予約'], ['jr-central.co.jp', 'expy.jp', 'smart-ex.jp']],
	['jr西日本', ['westjr.co.jp', 'jr-odekake.net']],
	[['etc利用照会サービス', 'etcマイレージ'], ['etc-meisai.jp', 'smile-etc.jp']],
	[['yamato transport', 'ヤマト運輸', 'クロネコヤマト', 'クロネコメンバーズ'], ['kuronekoyamato', 'yamato-hd']],
	[['sagawa express', '佐川急便'], ['sagawa-exp', 'sg-hldgs']],
	[['japan post', '日本郵便', '日本郵政'], ['japanpost'], null, POST_COMPOUND],
	[['mercari', 'メルカリ', 'メルペイ'], ['mercari', 'merpay']],
	[['paypay', 'ペイペイ'], ['paypay', 'paypay-bank', 'paypay-card', 'paypay-corp', 'paypay-sec']],
	[['kddi', 'au pay', 'auじぶん銀行', 'auかんたん決済'], KDDI],
	[['docomo', 'ドコモ', 'ドコモメール', 'ドコモオンライン', 'dアカウント', 'd払い', 'dカード'], DOCOMO],
	[['softbank', 'ソフトバンク', 'ワイモバイル'], SOFTBANK],
	['line', ['line.me', 'linecorp', 'lycorp.co.jp', 'linepay', 'naver.jp', 'linebiz'], qualified('line', String.raw`pay(?![a-z])|ヤフー|公式|サポート|セキュリティ|アカウント|corporation|株式会社|安全|通知`, 'line株式会社'), null, true],
	['国税庁', ['go.jp']],
	[['マイナポータル', '日本年金機構', 'ねんきんネット'], ['go.jp']],
	[['tepco', '東京電力'], ['tepco']],
	['東京ガス', ['tokyo-gas.co.jp']],
	[['ヨドバシ', 'ヨドバシカメラ', 'ヨドバシ・ドット・コム'], ['yodobashi']],
	[['野村證券', '野村証券'], ['nomura', 'nomuraholdings']],
	[['monex', 'マネックス証券'], ['monex', 'monexgroup']],
	['松井証券', ['matsui.co.jp']],
	['大和証券', ['daiwa.co.jp', 'daiwa.jp']],
	[['オリコ', 'オリエントコーポレーション'], ['orico.co.jp', 'orico.jp']],
	['ジャックス', ['jaccs.co.jp']],
	['ニフティ', ['nifty.com', 'nifty.co.jp']],
	[['biglobe', 'ビッグローブ'], ['biglobe']],
	['ocn', ['ocn.ne.jp', 'ocn.ad.jp', 'ntt.com', 'nttdocomo'], qualified('ocn', 'メール|会員|サポート|マイページ|サービス|モバイル|光'), null, true],
	[['xserver', 'エックスサーバー'], ['xserver']],
	['お名前.com', ['onamae.com', 'gmo.jp']],
	[['さくらインターネット', 'さくらのレンタルサーバ'], ['sakura.ad.jp', 'sakura.ne.jp']],

	// China, Hong Kong and Taiwan
	[['alipay', '支付宝', '支付寶'], ALIBABA],
	[['taobao', '淘宝', '淘寶', 'tmall', '天猫'], ALIBABA, null, /(?:淘宝|淘寶|天猫)(?:店|网店|商家|卖家)/],
	[['wechat pay', '微信支付', '微信团队', '微信安全中心', 'wechat team'], TENCENT],
	[['tencent', '腾讯', '騰訊', 'qq邮箱'], TENCENT],
	[['jd.com', '京东', '京東'], ['jd', '360buy.com', 'jdcloud.com']],
	[['pinduoduo', '拼多多'], ['pinduoduo', 'pddholdings']],
	[['netease', '网易'], ['netease', '163.com', '126.com', 'yeah.net', '188.com']],
	[['bank of china', '中国银行', '中國銀行'], ['bankofchina', 'bank-of-china', 'boc', 'bochk'], null, /中[国國][银銀]行(?:业|業|保险|保險|间|間)/],
	[['icbc', '工商银行', '工商銀行'], ['icbc', 'icbcasia', 'icbc-ltd']],
	[['china construction bank', '建设银行', '建設銀行'], ['ccb']],
	[['agricultural bank of china', '农业银行', '農業銀行'], ['abchina', '95599.cn']],
	[['china merchants bank', '招商银行', '招商銀行'], ['cmbchina', 'cmbwinglungbank']],
	[['bank of communications', '交通银行', '交通銀行'], ['bankcomm', '95559.com.cn']],
	[['china post', '中国邮政', '中國郵政'], ['chinapost', 'ems.com.cn', 'psbc', '11185.cn'], null, POST_COMPOUND],
	[['sf express', '顺丰', '順豐'], ['sf-express', 'sf-international']],
	[['中国移动', '中國移動'], ['10086.cn', 'chinamobile', 'chinamobileltd', '139.com'], null, /中[国國]移[动動](?:互联|互聯|端|应用|應用|游戏|遊戲|电商|電商)/],
	[['中国电信', '中國電信'], ['189.cn', 'chinatelecom', 'chinatelecom-h', 'chinatelecomglobal', '21cn.com'], null, /中[国國][电電]信(?:业|業|行业|行業|诈骗|詐騙|网络诈骗)/],
	[['china unicom', '中国联通', '中國聯通'], ['10010.com', 'chinaunicom', 'wo.cn']],
	[['国家税务总局', '國家稅務總局'], ['gov.cn']],
	[['unionpay', '银联', '銀聯', '云闪付'], ['unionpay', 'unionpayintl', '95516.com']],
	[['hang seng bank', '恒生銀行', '恒生银行'], ['hangseng', 'hsbc']],
	[['bochk', '中銀香港', '中银香港'], ['bochk', 'boc', 'bankofchina']],
	[['八達通', '八达通'], ['octopus.com.hk', 'octopuscards.com']],
	[['hongkong post', 'hong kong post', '香港郵政'], ['hongkongpost', 'gov.hk'], null, POST_COMPOUND],
	[['chunghwa post', '中華郵政'], ['gov.tw'], null, POST_COMPOUND],
	[['chunghwa telecom', '中華電信'], ['cht.com.tw', 'hinet.net', 'emome.net']],
	[['cathay united bank', '國泰世華'], ['cathaybk', 'cathayholdings']],
	[['ctbc bank', '中國信託'], ['ctbcbank', 'ctbcholding']],
	[['e.sun bank', '玉山銀行'], ['esunbank', 'esunfhc']],
	[['taishin', '台新銀行'], ['taishinbank']],
	[['fubon', '富邦'], ['fubon', 'taipeifubon']],
	[['bank of taiwan', '台灣銀行', '臺灣銀行', '兆豐銀行'], ['bot.com.tw', 'megabank.com.tw']],
	['遠通電收', ['fetc.net.tw']],

	// Korea
	[['naver', '네이버'], ['naver', 'navercorp', 'navercloudcorp', 'worksmobile']],
	[['kakao', 'kakaotalk', 'kakaobank', 'kakaopay', '카카오톡', '카카오뱅크', '카카오페이', '카카오계정', '카카오팀', '카카오 고객센터'], KAKAO],
	[['kb kookmin', 'kookmin bank', '국민은행', 'kb국민카드'], ['kbstar', 'kbfg', 'kbcard']],
	[['shinhan bank', 'shinhan card', '신한은행', '신한카드'], ['shinhan', 'shinhancard', 'shinhangroup']],
	[['woori bank', '우리은행', '우리카드'], ['wooribank', 'wooricard', 'woorifg']],
	[['hana bank', '하나은행', '하나카드'], ['hanabank', 'kebhana', 'hanacard', 'hanafn']],
	[['nonghyup', '농협은행', 'nh농협'], ['nonghyup', 'nhbank']],
	[['toss bank', 'toss payments', '토스뱅크', '토스증권', '토스페이먼츠'], ['toss.im', 'tossbank', 'tosspayments', 'tossinvest']],
	[['coupang', '쿠팡'], ['coupang', 'coupangcorp', 'coupangpay']],
	[['korea post', '국세청', '홈택스', '우체국택배', '인터넷우체국', '우정사업본부', '경찰청', '검찰청'], ['go.kr'], null, POST_COMPOUND],
	[['국민건강보험', '건강보험공단'], ['nhis.or.kr']],
	['삼성카드', ['samsungcard']],
	['현대카드', ['hyundaicard']],
	['롯데카드', ['lottecard']],
	['cj대한통운', ['cjlogistics', 'doortodoor.co.kr']],

	// Singapore, Malaysia, Indonesia, the Philippines, Thailand and Vietnam
	['dbs', ['dbs', 'dbsbank', 'posb'], qualified('dbs', String.raw`bank|posb|digibank|ideal|vickers|paylah|cards?|treasures|group|alerts?`), null, true],
	['posb', ['dbs', 'posb'], null, null, true],
	['ocbc', ['ocbc', 'ocbcnisp', 'ocbcwhhk', 'bankofsingapore']],
	['uob', ['uob', 'uobgroup', 'uobkayhian'], qualified('uob', String.raw`bank|group|tmrw|kay\s*hian|personal|business|infinity|cards?`, String.raw`united\s+overseas\s+bank`), null, true],
	[['singpass', 'cpf board', 'inland revenue authority of singapore'], ['gov.sg']],
	[['singpost', 'singapore post'], ['singpost', 'speedpost.com.sg'], null, POST_COMPOUND],
	[['grabpay', 'grabfood', 'grab holdings'], ['grab', 'grabpay', 'grabtaxi']],
	[['maybank', 'maybank2u'], ['maybank', 'maybank2u', 'maybank2e']],
	['cimb', ['cimb', 'cimbclicks', 'cimbniaga', 'cimbthai', 'cimbbank']],
	[['public bank berhad', 'pbebank'], ['pbebank', 'publicbank', 'publicbankgroup']],
	['rhb bank', ['rhbgroup', 'rhb']],
	['hong leong bank', ['hlb.com.my', 'hongleongconnect.my', 'hongleong.com.my', 'hlisb.com.my']],
	[['touch \'n go', 'touch n go', 'tng ewallet'], ['touchngo', 'tngdigital']],
	[['pos malaysia', 'poslaju'], ['pos.com.my', 'poslaju.com.my']],
	[['lhdn', 'lembaga hasil dalam negeri'], ['gov.my']],
	['bca', ['bca', 'klikbca', 'bcadigital', 'bcasyariah', 'bcafinance'], qualified('bca', String.raw`mobile|syariah|finance|digital|sekuritas|life|kartu|bank`, String.raw`bank\s+bca|klik\s*bca|mybca|halo\s*bca`), null, true],
	[['bank central asia', 'klikbca'], ['bca', 'klikbca']],
	[['bank mandiri', 'livin by mandiri', 'livin\' by mandiri'], ['bankmandiri', 'mandiri.co.id', 'livin.co.id']],
	[['bank rakyat indonesia', 'bank bri', 'brimo'], ['bri']],
	[['bank negara indonesia', 'bank bni'], ['bni']],
	['bank syariah indonesia', ['bankbsi']],
	[['gojek', 'gopay'], ['gojek', 'gopay', 'gotocompany', 'gotofinancial']],
	['tokopedia', ['tokopedia']],
	['bukalapak', ['bukalapak']],
	['pos indonesia', ['posindonesia']],
	[['direktorat jenderal pajak', 'djp online'], ['go.id']],
	['telkomsel', ['telkomsel', 'telkom']],
	['j&t express', ['jtexpress', 'jet.co.id']],
	['gcash', ['gcash', 'mynt.xyz', 'globe.com.ph']],
	['bdo', ['bdo', 'bdounibank'], qualified('bdo', String.raw`unibank|online|pay|bank`, String.raw`banco\s+de\s+oro`), null, true],
	['bpi', ['bpi', 'bpiexpressonline', 'bancobpi', 'bpifrance'], qualified('bpi', String.raw`online|express|bank|cards?|family|direct|capital|wealth`, String.raw`bank\s+of\s+the\s+philippine|banco\s+bpi`), null, true],
	['landbank', ['landbank', 'lbp-eservices'], qualified('landbank', 'of the philippines|philippines|iaccess|weaccess|mobile|advisory|alert|alerts|ph')],
	['paymaya', ['paymaya', 'maya.ph']],
	[['phlpost', 'philpost'], ['gov.ph']],
	['pldt', ['pldt', 'pldthome', 'smart.com.ph']],
	[['thailand post', 'ไปรษณีย์ไทย'], ['thailandpost'], null, POST_COMPOUND],
	[['kasikornbank', 'kbank', 'กสิกรไทย'], ['kasikornbank', 'kasikornbankgroup', 'kasikornasset', 'kbtg.tech', 'kbanknow']],
	['scb', ['scb', 'scbeasy', 'scb10x', 'scbx', 'sc.com', 'standardchartered', 'santanderconsumer'], qualified('scb', String.raw`easy|thailand|connect|business|10x`, String.raw`siam\s+commercial`), null, true],
	[['siam commercial bank', 'ไทยพาณิชย์'], ['scb', 'scbeasy', 'scbx']],
	[['bangkok bank', 'ธนาคารกรุงเทพ'], ['bangkokbank']],
	[['krungthai', 'krung thai bank', 'กรุงไทย'], ['krungthai', 'ktb.co.th', 'ktc.co.th']],
	[['krungsri', 'ธนาคารกรุงศรี'], ['krungsri']],
	['กรมสรรพากร', ['go.th']],
	[['truemoney', 'ทรูมันนี่'], ['truemoney', 'ascendcorp', 'truecorp.co.th', 'true.th']],
	['kerry express', ['kerryexpress', 'kex-express', 'kerrylogistics']],
	['flash express', ['flashexpress']],
	['vietcombank', ['vietcombank', 'vcb.com.vn']],
	['techcombank', ['techcombank']],
	['vietinbank', ['vietinbank']],
	['bidv', ['bidv']],
	['vpbank', ['vpbank', 'vpb.com.vn']],
	[['mbbank', 'mb bank'], ['mbbank']],
	['agribank', ['agribank']],
	['sacombank', ['sacombank']],
	['tpbank', ['tpb.vn', 'tpbank']],
	[['ví momo', 'momo wallet'], ['momo.vn', 'mservice.com.vn', 'mservice.io']],
	[['zalopay', 'zalo'], ['zalopay', 'zalo', 'vng.com.vn']],
	[['viettel', 'viettelpay'], ['viettel', 'viettelpost', 'vietteltelecom', 'viettelmoney']],
	[['vnpt', 'vinaphone'], ['vnpt', 'vinaphone']],
	['mobifone', ['mobifone']],
	[['vnpost', 'vietnam post', 'bưu điện việt nam'], ['vnpost', 'ems.com.vn'], null, POST_COMPOUND],
	[['tổng cục thuế', 'vneid', 'bộ công an'], ['gov.vn']],

	// Australia and New Zealand
	[['australia post', 'auspost'], ['auspost', 'australiapost', 'startrack'], null, POST_COMPOUND],
	[['mygov', 'australian taxation office', 'centrelink', 'services australia', 'service nsw'], ['gov.au', 'mygov']],
	[['commonwealth bank', 'commbank'], ['commbank', 'cba.com.au', 'commsec', 'commonwealthbank', 'bankwest']],
	['westpac', WESTPAC],
	[['st.george bank', 'st george bank'], WESTPAC],
	['anz', ['anz', 'anzrewards'], qualified('anz', String.raw`bank|internet\s+banking|plus|app|go\s*money|transactive|share\s+investing|new\s+zealand|rewards|cards?|fraud|security`), null, true],
	['nab', ['nab', 'nabgroup', 'nabtrade', 'ubank'], qualified('nab', String.raw`bank|internet\s+banking|connect|app|rewards|business|trade|cards?|security|defence|fraud`, String.raw`national\s+australia\s+bank`), null, true],
	['bendigo bank', ['bendigobank', 'bendigoadelaide']],
	['suncorp', ['suncorp', 'suncorpbank', 'suncorpgroup']],
	['macquarie bank', ['macquarie', 'macquariebank']],
	['bankwest', ['bankwest', 'commbank']],
	['telstra', ['telstra', 'bigpond.com']],
	['optus', ['optus', 'optusnet.com.au']],
	['linkt', ['linkt', 'transurban']],
	['origin energy', ['originenergy']],
	[['nz post', 'new zealand post'], ['nzpost', 'courierpost'], null, POST_COMPOUND],
	['kiwibank', ['kiwibank']],
	['asb', ['asb', 'asbhawaii'], qualified('asb', 'bank|fastnet|mobile|securities|kiwisaver'), null, true],
	['bnz', ['bnz'], qualified('bnz', String.raw`bank|internet\s+banking|app|advantage`, String.raw`bank\s+of\s+new\s+zealand`), null, true],
	[['inland revenue', 'waka kotahi', 'nz transport agency'], ['govt.nz', GOVERNMENT]],
	['trademe', ['trademe']],

	// Latin America
	[['itaú', 'itau unibanco'], ['itau', 'itau-unibanco', 'itauunibanco', 'itaucard', 'itaupersonnalite', 'itaubba', 'itaucultural']],
	['bradesco', ['bradesco', 'bradescoseguros', 'bradescard', 'campanhasbradesco', 'infobradesco']],
	['banco do brasil', ['bb.com.br', 'bancodobrasil', 'bancobrasil']],
	['caixa', ['caixa', 'gov.br'], qualified('caixa', String.raw`tem|federal|econômica\s+federal|economica\s+federal`, String.raw`caixa\s+econ[oô]mica|fgts\s+caixa|internet\s+banking\s+caixa`)],
	['nubank', ['nubank', 'nu.com.mx', 'nu.com.co']],
	['banco inter', ['bancointer', 'inter.co']],
	['c6 bank', ['c6bank']],
	['picpay', ['picpay']],
	[['pagseguro', 'pagbank'], ['pagseguro', 'pagbank', 'uol.com.br']],
	[['mercado libre', 'mercado livre', 'mercado pago'], MERCADO_LIBRE, null, /mercado livre de energia|(?:el|un|del|al|de)\s+mercado\s+libre(?!\s*\.com)/],
	['correios', ['correios', 'ctt.pt', 'gov.br'], qualified('correios', String.raw`brasil|do\s+brasil|rastreamento|rastreio|encomendas?|sedex|logística|logistica|celular|empresas|atendimento`, String.raw`empresa\s+brasileira\s+de\s+correios|(?<![\p{L}\p{N}])correios\s*[:|–-]\s`)],
	[['receita federal', 'gov.br', 'detran'], ['gov.br']],
	['serasa', ['serasa', 'serasaexperian', 'experian']],
	['sicredi', ['sicredi']],
	['sicoob', ['sicoob']],
	['banrisul', ['banrisul']],
	['claro', ['claro', 'americamovil', 'embratel', 'clarobrasil'], qualified('claro', String.raw`brasil|móvel|movel|tv|net|empresas|fatura|residencial|colombia|argentina|chile|perú|peru|música|video|pay|shop`, String.raw`(?:minha|mi|fatura)\s+claro(?![\p{L}\p{N}])`)],
	['vivo', TELEFONICA, qualified('vivo', String.raw`fibra|empresas|móvel|movel|fatura|valoriza|easy|pay`, String.raw`(?:meu|fatura)\s+vivo(?![\p{L}\p{N}])`)],
	['uol', ['uol', 'uolinc', 'uolhost', 'bol.com.br', 'pagseguro'], qualified('uol', String.raw`mail|host|assinaturas?|pagseguro|segurança|antivírus|cobrança`), null, true],
	['locaweb', ['locaweb']],
	['registro.br', ['registro.br', 'nic.br']],
	[['banamex', 'citibanamex'], ['banamex', 'citibanamex', 'citi']],
	['banorte', ['banorte']],
	['banco azteca', ['bancoazteca', 'bazdigital']],
	['bancoppel', ['bancoppel', 'coppel']],
	['coppel', ['bancoppel', 'coppel'], qualified('coppel', 'pay|crédito|credito|digital|com|mx|clientes|tienda|abonos|app')],
	['inbursa', ['inbursa']],
	[['servicio de administración tributaria', 'correos de méxico'], ['gob.mx']],
	['telcel', ['telcel', 'americamovil']],
	['telmex', ['telmex']],
	['cfe', ['cfe.mx', 'gob.mx'], qualified('cfe', String.raw`contigo|mi\s+espacio|suministro|recibo`, String.raw`comisi[oó]n\s+federal\s+de\s+electricidad`), null, true],
	[['bancolombia', 'nequi'], ['bancolombia', 'grupobancolombia', 'notificacionesbancolombia', 'nequi']],
	[['davivienda', 'daviplata'], ['davivienda', 'daviplata', 'davibank']],
	['banco de bogotá', ['bancodebogota']],
	['dian', ['gov.co'], qualified('dian', String.raw`colombia|muisca|notificación|notificacion`, String.raw`direcci[oó]n\s+de\s+impuestos\s+y\s+aduanas`), null, true],
	['servientrega', ['servientrega']],
	['rappi', ['rappi', 'rappipay']],
	['banco galicia', ['bancogalicia', 'galicia.ar']],
	[['banco nación', 'banco de la nación argentina'], ['bna', 'bn.com.pe']],
	['banco macro', ['macro.com.ar', 'bancomacro']],
	['banco provincia', ['bancoprovincia', 'bapro.com.ar']],
	['naranja x', ['naranjax', 'naranja']],
	['ualá', ['uala', 'ua.la']],
	[['afip', 'anses'], ['gob.ar', 'gov.ar', 'anses.fr']],
	['correo argentino', ['correoargentino']],
	['banco de chile', ['bancochile', 'banchile', 'bancoedwards']],
	['bancoestado', ['bancoestado']],
	['bci', ['bci'], qualified('bci', 'banco|seguros|empresas|personas', String.raw`banco\s+bci`), null, true],
	[['banco falabella', 'cmr falabella'], ['bancofalabella', 'falabella', 'cmrfalabella']],
	[['servicio de impuestos internos', 'tesorería general de la república'], ['sii.cl', 'tgr.cl', 'tesoreria.cl', 'gob.cl']],
	[['correos de chile', 'correoschile'], ['correos', 'correoschile']],
	['chilexpress', ['chilexpress']],
	['starken', ['starken'], qualified('starken', 'chile|cl|envíos|envios|encomienda|encomiendas|sucursal|seguimiento')],
	['bcp', ['bcp', 'viabcp', 'millenniumbcp', 'credicorp'], qualified('bcp', String.raw`banca|perú|peru|bolivia|millennium|empresas|digital`, String.raw`banco\s+de\s+cr[eé]dito|v[ií]a\s*bcp`), null, true],
	['interbank', ['interbank', 'intercorp'], qualified('interbank', 'perú|peru', String.raw`banca\s+por\s+internet\s+interbank`)],
	['yape', ['yape', 'viabcp', 'bcp']],
	[['sunat', 'reniec'], ['gob.pe']],
	['serpost', ['serpost']],
	['banco pichincha', ['pichincha', 'bancopichincha']],
	['brou', ['brou'], null, null, true],
	['banco república', ['brou']],
	['antel', ['antel']],
	['banco nacional de costa rica', ['bncr.fi.cr']],
	['banco popular dominicano', ['popularenlinea.com', 'bpd.com.do']],
	['banreservas', ['banreservas']],
	['banesco', ['banesco']],
	['banco de venezuela', ['bancodevenezuela', 'banvenez.com']],
];

// Scripts written without spaces between words, where a name stands right
// beside the words around it ("Amazonプライム会員", "【重要】三井住友カード")
const UNSPACED = String.raw`\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}`;
const KATAKANA = /^[\p{Script=Katakana}ー]$/u;
const JOINED = new RegExp(`^[${UNSPACED}]$`, 'u');

// The letters of a name without their accents ("itaú" is "itau", "crédit
// agricole" is "credit agricole", "τράπεζα" is "τραπεζα" as in capitals),
// in Latin and Greek
const PLAIN = {
	ł: 'l', ø: 'o', đ: 'd', ı: 'i', ß: 'ss', æ: 'ae', œ: 'oe',
};
const unaccented = name => name.replaceAll(/[\p{Script=Latin}\p{Script=Greek}]/gu, letter => PLAIN[letter] ?? letter.normalize('NFD').replaceAll(/\p{M}/gu, ''));

// The ways a name is spelled: as it is, as capitals turned to small letters
// spell it ("İŞ BANKASI" is "iş bankasi"), without accents, and, in Arabic,
// with a plain alef
const spellings = name => [...new Set([name, name.toUpperCase().toLowerCase(), unaccented(name), name.replaceAll(/[أإآ]/g, 'ا')])];

// (the longest of the words of a spelling)
function longest(words) {
	let found = '';
	for (const word of words) {
		found = word.length > found.length ? word : found;
	}

	return found;
}

// (a text as a pattern of itself)
const literal = text => text.replaceAll(/[$()*+.?[\\\]^{|}]/g, String.raw`\$&`);

// A pattern that finds a spelling as a name of its own: not inside a word
// ("purchase" names no Chase), but for a script written without spaces, where
// only more Katakana before a name in Katakana, or after a short one, makes
// another word ("ライオン" names no イオン, "オリコン" no オリコ); a name of
// three letters or fewer also not joined by a "-" or "'" ("Volunteer
// Sign-ups" does not name UPS); the words of a name together or apart
// ("wells fargo", "wellsfargo", "wells-fargo"), and one written with a
// hyphen with or without it ("e-boks", "eboks": not apart, as "M&T Bank" is
// no T-Bank)
function spelled(spelling) {
	const letters = [...spelling];
	const short = letters.length <= 3 ? String.raw`'’-` : '';
	const edge = (letter, before) => {
		if (KATAKANA.test(letter)) {
			return before || letters.length <= 3 ? `(?${before ? '<' : ''}![\\p{Script=Katakana}ー])` : '';
		}

		return JOINED.test(letter) ? '' : `(?${before ? '<' : ''}!(?![${UNSPACED}])[\\p{L}\\p{M}\\p{N}${short}])`;
	};

	return edge(letters[0], true) + literal(spelling).replaceAll('-', '-?').replaceAll(' ', String.raw`[\s._-]*`) + edge(letters.at(-1), false);
}

/**
 * The brands display names and subjects are read for (see above): each with
 * its names, the first the brand's own, the domains that are its own, what
 * makes a name that is also a word the brand, what makes it something else,
 * whether it is read only in capitals, and for each name the pattern that
 * finds it and the longest word of each of its spellings, one of which a text
 * that names it holds.
 * @type {Array<{brand: string, names: Array<{name: string, words: string[], pattern: RegExp}>, official: Array<string|RegExp>, qualifier: {test: Function}|null, not: RegExp|null, capitals: boolean}>}
 */
export const DISPLAY_BRANDS = BRANDS.map(([names, official, qualifier = null, not = null, capitals = false]) => ({
	brand: [names].flat()[0],
	names: [names].flat().map(name => {
		// (read in the display name as written for a name only in capitals)
		const written = spellings(name).map(spelling => (capitals ? spelling.toUpperCase() : spelling));
		let pattern;
		return {
			name,
			words: [...new Set(written.map(spelling => longest(spelling.split(/[ -]/))))],
			get pattern() {
				pattern ??= new RegExp(written.map(spelling => spelled(spelling)).join('|'), 'u');
				return pattern;
			},
		};
	}),
	official,
	qualifier,
	not,
	capitals,
}));

// A word of any of the names, in small letters and in capitals: a text that
// holds none names no brand, so only one that does is read for each name
const anyWord = capitals => new RegExp(DISPLAY_BRANDS.filter(entry => entry.capitals === capitals).flatMap(entry => entry.names.flatMap(({words}) => words)).map(word => literal(word)).join('|'), 'u');
const WORD = anyWord(false);
const CAPITAL_WORD = anyWord(true);

// A place named for the brand that pays for its name is no brand ("UBS Arena",
// "Truist Park", "Estadio Banorte")
const VENUE_AFTER = /^[\s-]{1,3}(?:arena|stadium|stadion|park|field|dome|pavilion|coliseum|amphitheat(?:er|re)|ballpark|speedway|bowl)(?![\p{L}\p{N}])/iu;
const VENUE_BEFORE = /(?<![\p{L}\p{N}])(?:arena|estadio|estádio|stade|stadio|stadion)\s{1,3}$/iu;
const VENUE_WORD = 16;
const isVenue = (text, found) => VENUE_AFTER.test(text.slice(found.index + found[0].length, found.index + found[0].length + VENUE_WORD)) || VENUE_BEFORE.test(text.slice(Math.max(0, found.index - VENUE_WORD), found.index));

// (in small letters, a capital "İ" an "i")
const smallLetters = text => text.toLowerCase().replaceAll('i\u0307', 'i');

/**
 * The brands a display name or a subject names, each as the name found of
 * it, and the text as it was read for them: as its reader sees it, invisible
 * characters removed, compatibility forms folded (wide and styled letters are
 * plain ones) and any apostrophe a "'"; a word that mixes scripts in the one
 * most of its letters are in ("pаypal" with a Cyrillic "а" is "paypal") and
 * the letters of the phonetic alphabet that look like plain ones as those
 * (see unmixedText); in small letters, a capital "İ" an "i"; a name read only
 * in capitals is read in the text as written. A brand is `lookalike` when only
 * lookalike letters that no keyboard explains name it ("pаypal",
 * "p\u0251yp\u0251l", not "Νetflix" with a Greek "Ν": see unmixedText).
 * @param {string} text
 * @returns {{small: string, brands: Array<{brand: string, lookalike: boolean, names: Array<{name: string}>, official: Array<string|RegExp>}>}}
 */
export function brandsIn(text) {
	const plain = readableText(text).replaceAll(/[\u2019\u02BC]/g, '\'');
	const written = unmixedText(plain);
	const small = smallLetters(written);
	const brands = [];
	if (!WORD.test(small) && !CAPITAL_WORD.test(written)) {
		return {small, brands};
	}

	for (const entry of DISPLAY_BRANDS) {
		const read = entry.capitals ? written : small;
		const named = entry.names.find(name => name.words.some(word => read.includes(word)) && name.pattern.test(read));
		if (named && (!entry.qualifier || entry.qualifier.test(small, written)) && !entry.not?.test(small) && !isVenue(read, named.pattern.exec(read))) {
			const typed = written === plain ? plain : unmixedText(plain, true);
			brands.push({...entry, brand: named.name, lookalike: !named.pattern.test(entry.capitals ? typed : smallLetters(typed))});
		}
	}

	return {small, brands};
}
