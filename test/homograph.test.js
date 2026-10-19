import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import HomographDetector, {
	BRANDS, brandWithPhishingWord, editDistance, isDroppedOrDoubled, isSwap, skeleton,
} from '../src/homograph.js';
import {cpuTime} from './helpers/cpu-time.js';

const detector = new HomographDetector();
const risk = domain => detector.detectHomographAttack(domain);

describe('homograph detection', () => {
	it('leaves brands, legitimate international domains and ordinary domains alone', () => {
		for (const domain of ['paypal.com', 'paypal.de', 'mail.google.com', 'support.apple.com', 'bücher.de', 'xn--mnchen-3ya.de', '日本.jp', 'сайт.рф', 'домен.рф', '中文.中国', 'example.com', 'appleseed.com', 'steamcommunity.com', 'upstream.io', '192.0.2.1', 'localhost', '']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}
	});

	it('reads names full of tricks quickly, and still finds the brand in the first seven kinds', () => {
		const started = cpuTime();
		for (let i = 0; i < 200; i++) {
			assert.equal(risk(`xrnvvcl0134578${i}-rnvvcl0134578-rnvvcl0134578.com`).brand, null);
		}

		assert.ok(cpuTime() - started < 1000);
		// (a brand imitated with seven kinds of trick, then more)
		assert.equal(risk('rnvvcl0134paypa1.com').brand, null);
		assert.equal(risk('paypa1-rnvvcl0134578.com').brand, 'paypal');
	});

	it('catches lookalike letters from other scripts, in Unicode and punycode', () => {
		for (const [domain, brand] of [['xn--pple-43d.com', 'apple'], ['аррӏе.com', 'apple'], ['gооgle.com', 'google'], ['раураl.com', 'paypal'], ['ρaypal.com', 'paypal'], ['páypal.com', 'paypal']]) {
			const result = risk(domain);
			assert.ok(result.riskScore >= 0.95, domain);
			assert.equal(result.brand, brand);
			assert.equal(result.isIDN, true);
			assert.match(result.recommendations[0], new RegExp(brand));
		}
	});

	it('catches digit swaps and letter pairs', () => {
		for (const [domain, brand] of [['g00gle.com', 'google'], ['faceb00k.com', 'facebook'], ['rnicrosoft.com', 'microsoft'], ['www.paypa1.com', 'paypal'], ['1nstagram.com', 'instagram'], ['paypa1-secure.top', 'paypal']]) {
			const result = risk(domain);
			assert.equal(result.riskScore, 0.85, domain);
			assert.equal(result.brand, brand);
		}
	});

	it('flags one-letter typos, brands inside other names and brands as subdomains, more weakly', () => {
		assert.equal(risk('amazom.com').riskScore, 0.5);
		assert.equal(risk('paypal-secure-login.com').riskScore, 0.6);
		assert.equal(risk('paypal.com.account-check.example').riskScore, 0.6);
		assert.equal(risk('paypal.evil.example').riskScore, 0);
		assert.equal(new HomographDetector({strictMode: true}).detectHomographAttack('paypal.evil.example').riskScore, 0.6);
		assert.equal(risk('a-b.com').riskScore, 0);
	});

	it('flags swapped neighbouring letters as typos, but not words', () => {
		for (const [domain, brand] of [['paypla.com', 'paypal'], ['amzaon.com', 'amazon'], ['gmial.com', 'gmail'], ['hotmial.com', 'hotmail']]) {
			const result = risk(domain);
			assert.equal(result.riskScore, 0.5, domain);
			assert.equal(result.brand, brand);
		}

		for (const domain of ['applied.com', 'venom.io', 'appel.nl', 'alzada.es', 'stirpe.it', 'raketen.de', 'mercati.it', 'lavada.es', 'phoneme.com', 'klara.se']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		// (typos that are not words are still typos)
		for (const domain of ['googel.com', 'twittre.com', 'striep.com']) {
			assert.equal(risk(domain).riskScore, 0.5, domain);
		}
	});

	it('flags a brand joined to a phishing word, also with swapped characters', () => {
		for (const [domain, brand] of [['paypallogin.com', 'paypal'], ['verifyamazon.com', 'amazon'], ['paypa1login.net', 'paypal'], ['secure-netflixbilling.top', 'netflix']]) {
			const result = risk(domain);
			assert.equal(result.riskScore, 0.6, domain);
			assert.equal(result.brand, brand);
			assert.match(result.riskFactors.at(-1), /phishing word/);
		}

		// Not: brands that are words themselves (either way round), a brand's
		// own product domains, short brands, or ordinary words.
		for (const domain of ['securebooking.com', 'updateoffice.com', 'officesecurity.com', 'ledgerupdate.com', 'amazonpay.com', 'googlemail.com', 'facebookmail.com', 'visaupdate.com', 'loginhelp.com', 'login.com']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		const brands = new Set(['paypal', 'booking']);
		assert.equal(brandWithPhishingWord('paypalverify', brands), 'paypal');
		assert.equal(brandWithPhishingWord('verifypaypal', brands), 'paypal');
		assert.equal(brandWithPhishingWord('securebooking', brands), null);
		assert.equal(brandWithPhishingWord('bookingsecure', brands), null);
		assert.equal(brandWithPhishingWord('verify', brands), null);
		assert.equal(brandWithPhishingWord('paypal', brands), null);
	});

	it('flags a brand\'s address continued into another domain', () => {
		for (const domain of ['paypal.com-verify.top', 'www.paypal.com-account.info', 'аpple.com-id.example']) {
			const result = risk(domain);
			assert.equal(result.riskScore, 0.85, domain);
			assert.match(result.riskFactors.at(-1), /address and continues/);
		}

		for (const domain of ['paypal.comverify.top', 'shop.com-deals.example', 'paypal.secure-com.example']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		// (a country code and the like, which many names start with: fully
		// only with a phishing word after it)
		for (const domain of ['office.it-haus.de', 'microsoft.co-op.org', 'google.de-cix.net', 'paypal.de-sicherheit.top']) {
			assert.equal(risk(domain).riskScore, 0.6, domain);
		}

		assert.equal(risk('paypal.de-login.top').riskScore, 0.85);
		assert.equal(risk('paypal.co-uk.example').riskScore, 0.85);
		// (a multi-tenant domain with its own brand in its name is flagged)
		assert.equal(risk('paypal.com.my.salesforce-sites.com').riskScore >= 0.6, true);
	});

	it('knows banks, shops and services imitated in other languages, and leaves their own domains alone', () => {
		for (const domain of ['rakuten.co.jp', 'yandex.ru', 'mercadolibre.com.ar', 'mercadolivre.com.br', 'sberbank.ru', 'flipkart.com', 'commerzbank.de', 'klarna.com', 'deutsche-bank.de', 'credit-agricole.fr', 'rakuten-bank.co.jp', 'yandex-team.ru', 'adobelogin.com', 'paypal-objects.com', 'images-amazon.com', 'google-analytics.com', 't-mobile.com']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		for (const domain of ['rakutten.com', 'yanbex.ru', 'mercadolibré.com', 'sberbank-online.top', 'flipkart-verify.shop', 'klarnalogin.top']) {
			assert.ok(risk(domain).riskScore >= 0.5, domain);
		}
	});

	it('analyses a long label of lookalike tricks quickly', () => {
		const started = cpuTime();
		for (let i = 0; i < 20; i++) {
			risk(`${'rnvvcl01345678'.repeat(4)}${i}.com`);
			risk(`${'rnvvcl01345678-'.repeat(4)}${i}.com`);
		}

		assert.ok(cpuTime() - started < 2000);
	});

	it('flags labels mixing scripts even without a brand', () => {
		const result = risk('exаmple.com'); // Cyrillic а
		assert.equal(result.riskScore, 0.6);
		assert.equal(result.brand, null);
		assert.match(result.riskFactors[0], /mixes/);
		assert.deepEqual(result.recommendations, ['Treat links to this domain as untrusted']);
	});

	it('takes custom brands and allowlists', () => {
		const custom = new HomographDetector({brands: ['acme'], extraBrands: ['widgets'], allowlist: ['acrne.com']});
		assert.equal(custom.detectHomographAttack('acrne.com').riskScore, 0);
		// (a brand of four letters reached by letters alone counts less, as
		//  real names read so; by a digit fully)
		assert.equal(custom.detectHomographAttack('acrne.net').riskScore, 0.6);
		assert.equal(custom.detectHomographAttack('acm3.net').riskScore, 0.85);
		assert.equal(custom.detectHomographAttack('w1dgets.com').brand, 'widgets');
		assert.equal(custom.detectHomographAttack('paypa1.com').riskScore, 0);
		assert.ok(BRANDS.includes('paypal'));
	});

	it('caches results and stays bounded', () => {
		const local = new HomographDetector();
		assert.equal(local.detectHomographAttack('g00gle.com'), local.detectHomographAttack('G00GLE.com.'));
		for (let i = 0; i < 5002; i++) {
			local.detectHomographAttack(`host${i}.example`);
		}

		assert.equal(local.cache.size, 5000);
		assert.equal(local.detectHomographAttack(null).riskScore, 0);
		assert.equal(new HomographDetector(null).detectHomographAttack('paypa1.com').riskScore, 0.85);
	});
});

describe('helpers', () => {
	it('folds lookalikes to Latin', () => {
		assert.equal(skeleton('Раураl'), 'paypal');
		assert.equal(skeleton('ＡＢＣ'), 'abc');
	});

	it('measures edit distance with an early exit', () => {
		assert.equal(editDistance('amazon', 'amazom'), 1);
		assert.equal(editDistance('kitten', 'sittin'), 2);
		assert.equal(editDistance('abc', 'abcdefg'), 3);
		assert.equal(editDistance('abcdef', 'uvwxyz', 1), 2);
		// Two neighbouring letters swapped are one edit.
		assert.equal(editDistance('paypal', 'paypla'), 1);
		assert.equal(editDistance('ab', 'ba'), 1);
		assert.equal(editDistance('abcd', 'badc'), 2);
	});
});

describe('brands that are words', () => {
	it('takes only swapped neighbouring letters for a typo of a brand that is near a word', () => {
		for (const domain of ['finance.gov.au', 'mobile.de', 'email.com', 'cloud.gov', 'cloud.com', 'cooking.com', 'stack.com', 'black.com', 'strip.com', 'stride.com', 'apply.com', 'ample.com', 'morton.com', 'horton.com', 'photon.io', 'adore.me', 'stream.tv', 'steak.com', 'officer.com', 'tiktokv.com']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		for (const domain of ['gmial.com', 'binacne.com', 'icluod.com']) {
			assert.equal(risk(domain).riskScore, 0.5, domain);
		}

		// (and brands one letter from words and places of other languages)
		for (const domain of ['belle.com', 'welle.de', 'celle.de', 'delle.it', 'venlo.nl', 'cedex.fr', 'tresor.de', 'samsun.com.tr', 'twister.com']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		for (const domain of ['zlele.com', 'vemno.com', 'fdeex.com', 'trezro.com', 'smasung.com', 'twtiter.com']) {
			assert.equal(risk(domain).riskScore, 0.5, domain);
		}
	});

	it('takes a letter left out inside, or one doubled, for a typo of a brand near a word that is no word itself', () => {
		for (const [domain, brand] of [['twiter.com', 'twitter'], ['samsng.com', 'samsung'], ['twittter.com', 'twitter'], ['samssung.com', 'samsung'], ['icoud.com', 'icloud'], ['binnance.com', 'binance'], ['gmaill.com', 'gmail'], ['tmoble.com', 'tmobile']]) {
			const result = risk(domain);
			assert.equal(result.riskScore, 0.5, domain);
			assert.equal(result.brand, brand, domain);
		}

		// (not the first or the last letter left out, another letter added,
		//  a typo that is a word, or a brand that is a word)
		for (const domain of ['cloud.com', 'mobile.de', 'samsun.com.tr', 'tmobil.com', 'tiktokv.com', 'titter.com', 'ample.com', 'booing.com', 'stipe.com', 'leger.nl']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		assert.equal(isDroppedOrDoubled('twiter', 'twitter'), true);
		assert.equal(isDroppedOrDoubled('twitterr', 'twitter'), true);
		assert.equal(isDroppedOrDoubled('twitterx', 'twitter'), false);
		assert.equal(isDroppedOrDoubled('witter', 'twitter'), false);
		assert.equal(isDroppedOrDoubled('twitter', 'twitter'), false);
	});

	it('tells a swap of two neighbouring letters from the same name', () => {
		assert.equal(isSwap('gmial', 'gmail'), true);
		assert.equal(isSwap('gmail', 'gmail'), false);
		assert.equal(isSwap('gmai', 'gmail'), false);
	});

	it('takes a brand that is a word or short inside another name only beside a phishing word', () => {
		for (const domain of ['home-office.de', 'post-office.co.uk', 'box-office.com', 'uk-visa-services.com', 'e-visa.example', 'apple-tree.com', 'steam-cleaning.com', 'zoom-lens.com', 'wise-investments.com', 'ledger-accounting.com', 'sparkasse-koelnbonn.de', 'paypal-communication.com', 'cloudflare-ipfs.com', 'ebay-kleinanzeigen.de']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		for (const domain of ['office-login.com', 'zoom-verify.top', 'sparkasse-login.de', 'paypal-business.example']) {
			assert.equal(risk(domain).riskScore, 0.6, domain);
		}
	});

	it('takes a brand that is a word or short in a subdomain only as the start of an address', () => {
		for (const domain of ['www.office.example.edu', 'www.steam.ncsu.edu', 'login.okta.acme.com']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		for (const domain of ['apple.com.verify.example', 'www.okta.com.login.example']) {
			assert.equal(risk(domain).riskScore, 0.6, domain);
		}
	});

	it('counts a short brand or a word reached by letters alone less than one reached by a digit', () => {
		for (const [domain, brand] of [['lrs.com', 'irs'], ['stearn.com', 'steam'], ['arnex.ch', 'amex'], ['arnex-online.ch', 'amex']]) {
			assert.equal(risk(domain).riskScore, 0.6, domain);
			assert.equal(risk(domain).brand, brand, domain);
		}

		for (const domain of ['1rs.com', 'app1e.com', 'rnicrosoft.com', 'ste4rn-online.com']) {
			assert.equal(risk(domain).riskScore, 0.85, domain);
		}

		// (a digit in another part of the name is no trick)
		for (const [domain, brand] of [['stearn-24.com', 'steam'], ['arnex-2.ch', 'amex'], ['zoorn-360.com', 'zoom']]) {
			assert.equal(risk(domain).riskScore, 0.6, domain);
			assert.equal(risk(domain).brand, brand, domain);
		}
	});

	it('reads a capital I as l in a name of small letters', () => {
		for (const [domain, brand] of [['googIe.com', 'google'], ['paypaI.com', 'paypal'], ['PaypaI-secure.top', 'paypal']]) {
			assert.equal(risk(domain).riskScore, 0.85, domain);
			assert.equal(risk(domain).brand, brand, domain);
		}

		// (not in a name all in capitals, or in the suffix)
		for (const domain of ['AIRBNB.com', 'google.IE', 'Google.com', 'Instagram.com', 'Icloud.com']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}

		// (and remembered apart from the name in small letters)
		assert.equal(risk('googie.com').riskScore, 0.5);
	});

	it('counts "cl" for "d", "vv" for "w" and "l" for "i" fully in a brand of five letters or more that is a word', () => {
		for (const [domain, brand] of [['discorcl.com', 'discord'], ['strlpe.com', 'stripe'], ['offlce.com', 'office'], ['discorcl-login.com', 'discord']]) {
			assert.equal(risk(domain).riskScore, 0.85, domain);
			assert.equal(risk(domain).brand, brand, domain);
		}

		// ("rn" for "m" is in names: "stearn")
		assert.equal(risk('stearn.com').riskScore, 0.6);
	});

	it('takes a brand that is a word beside only words of its services, or a phishing word in another label, for the brand', () => {
		for (const domain of ['apple-support.com', 'support-apple.com', 'apple-help.com', 'apple-id-support.com', 'chase-bank.com', 'chase-online.com', 'discord-gift.com', 'discord-nitro.gift', 'steam-gift.com', 'steam-trade.com', 'steam-community.ru', 'ledger-live.com', 'ledger-wallet.com', 'slack-files.com', 'blockchain-wallet.com', 'stripe-payments.com', 'kraken-trade.com', 'proton-wallet.com', 'ledger-support.com', 'kraken-support.com', 'blockchain-support.com', 'proton-support.com', 'steam-support.com', 'stripe-help.com', 'login.steam.example.com', 'secure.apple.verify-account.com', 'login.apple.example.com']) {
			assert.equal(risk(domain).riskScore, 0.6, domain);
		}

		// (not beside other words, nor "office" and "booking", the most common
		//  nouns, nor a short brand)
		for (const domain of ['apple-valley-bank.com', 'candy-apple-gifts.com', 'golden-apple-trading.com', 'steam-trains-online.com', 'steam-engine-help.com', 'live-steam.com', 'apple-community.com', 'chase-hotel.com', 'office-help.com', 'office-service.de', 'booking-online.de', 'hotel-booking-service.com', 'uk-visa-services.com', 'visa-services.com', 'www.apple.example.com', 'secure.office.example.edu', 'login.okta.acme.com', 'ledger-services.com', 'ledger-online.com', 'stripe-service.com', 'steam-service.com', 'blockchain-services.com', 'kraken-services.com', 'proton-services.com', 'auth.steam.uni.edu', 'login.office.example.edu', 'office-support.com']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}
	});

	it('counts lookalike letters in a short brand beside other words only with a phishing word', () => {
		assert.equal(risk('e-vísa.com').riskScore, 0);
		assert.equal(risk('vísa-login.com').riskScore, 0.95);
		assert.equal(risk('applé-store.com').riskScore, 0.95);
	});

	it('does not take a Japanese long vowel mark for another script', () => {
		for (const domain of ['コーヒー.jp', 'ゲーム.jp', 'ヤフー.jp']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}
	});

	it('counts lookalike letters in a part of a name fully', () => {
		const result = risk('pаypal-login.com'); // Cyrillic а
		assert.equal(result.riskScore, 0.95);
		assert.equal(result.brand, 'paypal');
		assert.ok(result.riskScore > risk('paypa1-login.com').riskScore);
	});
});
