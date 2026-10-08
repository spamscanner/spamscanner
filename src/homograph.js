import {domainToUnicode} from 'node:url';
import {parse as parseDomain} from 'tldts';
import {scriptOf} from './language.js';

/**
 * Brands most often imitated in phishing: banks, payment services, mail and
 * cloud providers, shops, couriers and tax offices. A domain whose name is a
 * brand's ("paypal" in paypal.com, paypal.de, ...) is the brand's own and is
 * never flagged.
 */
export const BRANDS = [
	'adobe', 'airbnb', 'alibaba', 'aliexpress', 'amazon', 'americanexpress', 'amex', 'apple', 'appleid', 'att', 'binance', 'bankofamerica', 'barclays', 'bestbuy', 'blockchain', 'booking', 'bybit', 'cashapp', 'chase', 'citibank', 'cloudflare', 'coinbase', 'comcast', 'costco', 'dhl', 'discord', 'docusign', 'dropbox', 'ebay', 'facebook', 'fedex', 'forwardemail', 'github', 'gitlab', 'gmail', 'godaddy', 'google', 'hmrc', 'hotmail', 'hsbc', 'icloud', 'instagram', 'intuit', 'irs', 'kraken', 'ledger', 'linkedin', 'mastercard', 'mcafee', 'metamask', 'microsoft', 'microsoftonline', 'namecheap', 'netflix', 'norton', 'office', 'office365', 'okta', 'onedrive', 'outlook', 'paypal', 'proton', 'protonmail', 'quickbooks', 'revolut', 'roblox', 'royalmail', 'salesforce', 'samsung', 'santander', 'sharepoint', 'shopify', 'skype', 'slack', 'sparkasse', 'spotify', 'steam', 'steampowered', 'stripe', 'telegram', 'tiktok', 'tmobile', 'trezor', 'tutanota', 'twitter', 'uber', 'ups', 'usps', 'venmo', 'verizon', 'visa', 'walmart', 'wellsfargo', 'whatsapp', 'wise', 'xfinity', 'yahoo', 'zelle', 'zoom',
];

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

function trickVariants(label) {
	const variants = new Set([label]);
	for (const [pattern, letter] of ASCII_TRICKS) {
		for (const value of variants) {
			variants.add(value.replace(pattern, letter));
		}
	}

	// "1" and "l" also stand for "i" (paypa1, 1nstagram).
	for (const value of variants) {
		variants.add(value.replaceAll('l', 'i'));
	}

	variants.delete(label);
	return variants;
}

/**
 * Levenshtein distance, giving up once it exceeds `max`.
 * @param {string} a
 * @param {string} b
 * @param {number} [max]
 * @returns {number}
 */
export function editDistance(a, b, max = 2) {
	if (Math.abs(a.length - b.length) > max) {
		return max + 1;
	}

	let previous = Array.from({length: b.length + 1}, (_, i) => i);
	for (let i = 1; i <= a.length; i++) {
		const current = [i];
		let best = i;
		for (let j = 1; j <= b.length; j++) {
			const cost = a[i - 1] === b[j - 1] ? 0 : 1;
			current[j] = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost);
			best = Math.min(best, current[j]);
		}

		if (best > max) {
			return max + 1;
		}

		previous = current;
	}

	return previous[b.length];
}

function labelScripts(label) {
	const scripts = new Set();
	for (const char of label) {
		if (/\p{L}/u.test(char)) {
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
	constructor(options = {}) {
		this.options = options;
		this.brands = new Set([...(options.brands || BRANDS), ...(options.extraBrands || [])].map(brand => brand.toLowerCase()));
		this.allowlist = new Set((options.allowlist || []).map(domain => domain.toLowerCase()));
		this.cache = new Map();
	}

	/**
	 * Analyse a host name, in Unicode or punycode.
	 * @param {string} domain
	 * @returns {{domain: string, unicode: string, isIDN: boolean, riskScore: number, riskFactors: string[], brand: string|null, recommendations: string[], confidence: number}}
	 */
	detectHomographAttack(domain) {
		const input = typeof domain === 'string' ? domain.trim().toLowerCase().replace(/\.$/, '') : '';
		if (this.cache.has(input)) {
			return this.cache.get(input);
		}

		const result = this.analyse(input);
		this.cache.set(input, result);
		if (this.cache.size > 5000) {
			this.cache.delete(this.cache.keys().next().value);
		}

		return result;
	}

	analyse(input) {
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
		if (!name || parsed.isIp || this.allowlist.has(parsed.domain)) {
			return result;
		}

		const flag = (score, factor, brand) => {
			result.riskFactors.push(factor);
			if (score > result.riskScore) {
				result.riskScore = score;
				result.brand = brand;
			}
		};

		if (this.brands.has(name)) {
			// The brand's own domain, under any suffix.
			return result;
		}

		const scripts = labelScripts(name);
		const folded = skeleton(name);
		if (isSuspiciousMix(scripts)) {
			flag(0.6, `"${unicode}" mixes ${[...scripts].join(' and ')} letters`, null);
		}

		const viaConfusable = folded === name ? null : [folded, folded.replaceAll('-', '')].find(value => this.brands.has(value));
		if (viaConfusable) {
			flag(0.95, `"${unicode}" imitates ${viaConfusable} with lookalike letters`, viaConfusable);
		} else if (/^[a-z\d-]+$/.test(folded)) {
			const trick = [...trickVariants(folded)].find(variant => this.brands.has(variant));
			if (trick) {
				flag(0.85, `"${unicode}" imitates ${trick} by swapping characters`, trick);
			} else if (folded.length >= 5) {
				const near = [...this.brands].find(brand => brand.length >= 5 && editDistance(folded, brand, 1) === 1);
				if (near) {
					flag(0.5, `"${unicode}" is one letter away from ${near}`, near);
				}
			}

			if (folded.includes('-')) {
				for (const piece of folded.split('-')) {
					if (piece.length < 4) {
						continue;
					}

					if (this.brands.has(piece)) {
						flag(0.6, `"${unicode}" puts ${piece} inside another domain name`, piece);
						break;
					}

					const disguised = [...trickVariants(piece)].find(variant => this.brands.has(variant));
					if (disguised) {
						flag(0.85, `"${unicode}" imitates ${disguised} by swapping characters`, disguised);
						break;
					}
				}
			}
		}

		// "paypal.com.account-check.example": a brand as a subdomain label.
		const subdomain = parsed.subdomain ? parsed.subdomain.split('.') : [];
		const brandLabel = subdomain.map(label => skeleton(label)).find(label => label.length >= 4 && this.brands.has(label));
		if (brandLabel && (this.options.strictMode || subdomain.length >= 2)) {
			flag(0.6, `"${unicode}" puts ${brandLabel} in front of another domain`, brandLabel);
		}

		result.confidence = result.riskScore;
		if (result.riskScore >= 0.5) {
			result.recommendations.push(result.brand ? `Do not sign in from this link; go to ${result.brand}'s site directly` : 'Treat links to this domain as untrusted');
		}

		return result;
	}
}

export {HomographDetector};
