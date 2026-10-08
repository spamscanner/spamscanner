import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import HomographDetector, {BRANDS, editDistance, skeleton} from '../src/homograph.js';

const detector = new HomographDetector();
const risk = domain => detector.detectHomographAttack(domain);

describe('homograph detection', () => {
	it('leaves brands, legitimate international domains and ordinary domains alone', () => {
		for (const domain of ['paypal.com', 'paypal.de', 'mail.google.com', 'support.apple.com', 'bücher.de', 'xn--mnchen-3ya.de', '日本.jp', 'сайт.рф', 'домен.рф', '中文.中国', 'example.com', 'appleseed.com', 'steamcommunity.com', 'upstream.io', '192.0.2.1', 'localhost', '']) {
			assert.equal(risk(domain).riskScore, 0, domain);
		}
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
	});
});
