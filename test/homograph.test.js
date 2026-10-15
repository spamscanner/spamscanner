import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import HomographDetector, {
	BRANDS, brandWithPhishingWord, editDistance, skeleton,
} from '../src/homograph.js';

const detector = new HomographDetector();
const risk = domain => detector.detectHomographAttack(domain);

describe('homograph detection', () => {
	it('leaves brands, legitimate international domains and ordinary domains alone', () => {
		for (const domain of ['paypal.com', 'paypal.de', 'mail.google.com', 'support.apple.com', 'bücher.de', 'xn--mnchen-3ya.de', '日本.jp', 'сайт.рф', 'домен.рф', '中文.中国', 'example.com', 'appleseed.com', 'steamcommunity.com', 'upstream.io', '192.0.2.1', 'localhost', '']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}
	});

	it('reads names full of tricks quickly, and still finds the brand in the first seven kinds', () => {
		const started = Date.now();
		for (let i = 0; i < 200; i++) {
			assert.equal(risk(`xrnvvcl0134578${i}-rnvvcl0134578-rnvvcl0134578.com`).brand, null);
		}

		assert.ok(Date.now() - started < 1000);
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
		const started = Date.now();
		for (let i = 0; i < 20; i++) {
			risk(`${'rnvvcl01345678'.repeat(4)}${i}.com`);
			risk(`${'rnvvcl01345678-'.repeat(4)}${i}.com`);
		}

		assert.ok(Date.now() - started < 2000);
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
		assert.equal(custom.detectHomographAttack('acrne.net').riskScore, 0.85);
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
