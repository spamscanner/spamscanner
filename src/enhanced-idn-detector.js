#!/usr/bin/env node
/**
 * Enhanced IDN Homograph Attack Detection
 * Based on comprehensive research and best practices
 */

import {createHash} from 'node:crypto';
import confusables from 'confusables';

// Unicode confusable character mappings (subset for demonstration)
const CONFUSABLE_CHARS = new Map([
	// Cyrillic to Latin confusables
	['а', 'a'],
	['е', 'e'],
	['о', 'o'],
	['р', 'p'],
	['с', 'c'],
	['х', 'x'],
	['у', 'y'],
	['А', 'A'],
	['В', 'B'],
	['Е', 'E'],
	['К', 'K'],
	['М', 'M'],
	['Н', 'H'],
	['О', 'O'],
	['Р', 'P'],
	['С', 'C'],
	['Т', 'T'],
	['Х', 'X'],
	['У', 'Y'],

	// Greek to Latin confusables
	['α', 'a'],
	['ο', 'o'],
	['ρ', 'p'],
	['υ', 'u'],
	['ν', 'v'],
	['ι', 'i'],
	['Α', 'A'],
	['Β', 'B'],
	['Ε', 'E'],
	['Ζ', 'Z'],
	['Η', 'H'],
	['Ι', 'I'],
	['Κ', 'K'],
	['Μ', 'M'],
	['Ν', 'N'],
	['Ο', 'O'],
	['Ρ', 'P'],
	['Τ', 'T'],
	['Υ', 'Y'],

	// Mathematical symbols
	['𝐚', 'a'],
	['𝐛', 'b'],
	['𝐜', 'c'],
	['𝐝', 'd'],
	['𝐞', 'e'],
	['𝟎', '0'],
	['𝟏', '1'],
	['𝟐', '2'],
	['𝟑', '3'],
	['𝟒', '4'],

	// Other common confusables
	['ℯ', 'e'],
	['ℊ', 'g'],
	['ℎ', 'h'],
	['ℓ', 'l'],
	['ℴ', 'o'],
	['ℯ', 'e'],
	['ⅰ', 'i'],
	['ⅱ', 'ii'],
	['ⅲ', 'iii'],
	['ⅳ', 'iv'],
	['ⅴ', 'v'],
]);

// Known legitimate international domains (whitelist approach)
const LEGITIMATE_IDN_DOMAINS = new Set([
	'xn--fsq.xn--0zwm56d', // 中国
	'xn--fiqs8s', // 中国
	'xn--fiqz9s', // 中囯
	'xn--j6w193g', // 香港
	'xn--55qx5d', // 公司
	'xn--io0a7i', // 网络
	// Add more legitimate domains as needed
]);

// Popular brand domains for comparison
const POPULAR_BRANDS = [
	'google',
	'facebook',
	'amazon',
	'apple',
	'microsoft',
	'twitter',
	'instagram',
	'linkedin',
	'youtube',
	'netflix',
	'paypal',
	'ebay',
	'yahoo',
	'adobe',
	'salesforce',
	'oracle',
	'ibm',
	'cisco',
	'intel',
	'nvidia',
	'tesla',
	'citibank',
	'bankofamerica',
	'wellsfargo',
	'chase',
	'americanexpress',
];

class EnhancedIDNDetector {
	constructor(options = {}) {
		this.options = {
			strictMode: false,
			enableWhitelist: true,
			enableBrandProtection: true,
			enableContextAnalysis: true,
			maxSimilarityThreshold: 0.8,
			minDomainAge: 30, // Days
			...options,
		};

		this.cache = new Map();
	}

	/**
	 * Main detection method with comprehensive analysis
	 */
	detectHomographAttack(domain, context = {}) {
		const cacheKey = this.getCacheKey(domain, context);
		if (this.cache.has(cacheKey)) {
			return this.cache.get(cacheKey);
		}

		const result = this.analyzeComprehensive(domain, context);
		this.cache.set(cacheKey, result);
		return result;
	}

	/**
	 * Comprehensive analysis combining multiple detection methods
	 */
	analyzeComprehensive(domain, context) {
		const analysis = {
			domain,
			isIDN: this.isIDNDomain(domain),
			riskScore: 0,
			riskFactors: [],
			recommendations: [],
			confidence: 0,
		};

		// Skip analysis for whitelisted domains
		if (this.options.enableWhitelist && this.isWhitelisted(domain)) {
			analysis.riskScore = 0;
			analysis.confidence = 1;
			analysis.recommendations.push('Domain is whitelisted as legitimate');
			return analysis;
		}

		// Basic IDN detection
		if (analysis.isIDN) {
			analysis.riskScore += 0.3;
			analysis.riskFactors.push('Contains non-ASCII characters');
		}

		// Confusable character analysis
		const confusableAnalysis = this.analyzeConfusableCharacters(domain);
		analysis.riskScore += confusableAnalysis.score;
		analysis.riskFactors.push(...confusableAnalysis.factors);

		// Brand similarity analysis
		if (this.options.enableBrandProtection) {
			const brandAnalysis = this.analyzeBrandSimilarity(domain);
			analysis.riskScore += brandAnalysis.score;
			analysis.riskFactors.push(...brandAnalysis.factors);
		}

		// Script mixing analysis
		const scriptAnalysis = this.analyzeScriptMixing(domain);
		analysis.riskScore += scriptAnalysis.score;
		analysis.riskFactors.push(...scriptAnalysis.factors);

		// Context analysis
		if (this.options.enableContextAnalysis && context) {
			const contextAnalysis = this.analyzeContext(domain, context);
			analysis.riskScore += contextAnalysis.score;
			analysis.riskFactors.push(...contextAnalysis.factors);
		}

		// Punycode analysis
		if (domain.includes('xn--')) {
			const punycodeAnalysis = this.analyzePunycode(domain);
			analysis.riskScore += punycodeAnalysis.score;
			analysis.riskFactors.push(...punycodeAnalysis.factors);
		}

		// Calculate final confidence and recommendations
		analysis.confidence = Math.min(analysis.riskScore, 1);
		analysis.recommendations = this.generateRecommendations(analysis);

		return analysis;
	}

	/**
	 * Detect if domain contains IDN characters
	 */
	isIDNDomain(domain) {
		// eslint-disable-next-line no-control-regex
		return domain.includes('xn--') || /[^\u0000-\u007F]/.test(domain);
	}

	/**
	 * Check if domain is in whitelist
	 */
	isWhitelisted(domain) {
		const normalized = domain.toLowerCase();
		return LEGITIMATE_IDN_DOMAINS.has(normalized);
	}

	/**
	 * Analyze confusable characters
	 */
	analyzeConfusableCharacters(domain) {
		const analysis = {score: 0, factors: []};
		let confusableCount = 0;
		let totalChars = 0;

		// Use confusables library to detect and normalize
		try {
			const normalized = confusables(domain);
			if (normalized !== domain) {
				// Domain contains confusable characters
				for (const char of domain) {
					totalChars++;
					const normalizedChar = confusables(char);
					if (normalizedChar !== char) {
						confusableCount++;
						analysis.factors.push(`Confusable character: ${char} → ${normalizedChar}`);
					}
				}

				if (confusableCount > 0) {
					const ratio = confusableCount / totalChars;
					analysis.score = Math.min(ratio * 0.8, 0.6);
					analysis.factors.push(`${confusableCount}/${totalChars} characters are confusable`, `Normalized domain: ${normalized}`);
				}
			}
		} catch {
			// Fallback to manual detection
			for (const char of domain) {
				totalChars++;
				if (CONFUSABLE_CHARS.has(char)) {
					confusableCount++;
					analysis.factors.push(`Confusable character: ${char} → ${CONFUSABLE_CHARS.get(char)}`);
				}
			}

			if (confusableCount > 0) {
				const ratio = confusableCount / totalChars;
				analysis.score = Math.min(ratio * 0.8, 0.6);
				analysis.factors.push(`${confusableCount}/${totalChars} characters are confusable`);
			}
		}

		return analysis;
	}

	/**
	 * Analyze similarity to popular brands
	 */
	analyzeBrandSimilarity(domain) {
		const analysis = {score: 0, factors: []};
		const cleanDomain = this.normalizeDomain(domain);

		for (const brand of POPULAR_BRANDS) {
			const similarity = this.calculateSimilarity(cleanDomain, brand);
			if (similarity > this.options.maxSimilarityThreshold) {
				analysis.score = Math.max(analysis.score, similarity * 0.7);
				analysis.factors.push(`High similarity to ${brand}: ${(similarity * 100).toFixed(1)}%`);
			}
		}

		return analysis;
	}

	/**
	 * Analyze script mixing patterns
	 */
	analyzeScriptMixing(domain) {
		const analysis = {score: 0, factors: []};
		const scripts = this.detectScripts(domain);

		if (scripts.size > 1) {
			// Mixed scripts can be suspicious
			const scriptList = [...scripts].join(', ');
			analysis.factors.push(`Mixed scripts detected: ${scriptList}`);

			// Higher risk for certain combinations
			if (scripts.has('Latin') && (scripts.has('Cyrillic') || scripts.has('Greek'))) {
				analysis.score += 0.4;
				analysis.factors.push('Suspicious Latin/Cyrillic or Latin/Greek mixing');
			} else {
				analysis.score += 0.2;
			}
		}

		return analysis;
	}

	/**
	 * Analyze context (email headers, content, etc.)
	 */
	analyzeContext(domain, context) {
		const analysis = {score: 0, factors: []};

		// Check if display text differs from actual domain
		if (context.displayText && context.displayText !== domain) {
			analysis.score += 0.3;
			analysis.factors.push('Display text differs from actual domain');
		}

		// Check sender reputation
		if (context.senderReputation && context.senderReputation < 0.5) {
			analysis.score += 0.2;
			analysis.factors.push('Low sender reputation');
		}

		// Check for suspicious email patterns
		if (context.emailContent) {
			const suspiciousPatterns = [
				/urgent/i,
				/verify.*account/i,
				/suspended/i,
				/click.*here/i,
				/limited.*time/i,
				/act.*now/i,
				/confirm.*identity/i,
			];

			for (const pattern of suspiciousPatterns) {
				if (pattern.test(context.emailContent)) {
					analysis.score += 0.1;
					analysis.factors.push(`Suspicious email pattern: ${pattern.source}`);
				}
			}
		}

		return analysis;
	}

	/**
	 * Analyze punycode domains
	 */
	analyzePunycode(domain) {
		const analysis = {score: 0, factors: []};

		try {
			// Decode punycode to see actual characters
			const decoded = this.decodePunycode(domain);
			analysis.factors.push(`Punycode decoded: ${decoded}`);

			// Check if decoded version looks suspicious
			const decodedAnalysis = this.analyzeConfusableCharacters(decoded);
			analysis.score += decodedAnalysis.score * 0.8;
			analysis.factors.push(...decodedAnalysis.factors);
		} catch {
			analysis.score += 0.2;
			analysis.factors.push('Invalid punycode encoding');
		}

		return analysis;
	}

	/**
	 * Normalize domain for comparison
	 */
	normalizeDomain(domain) {
		let normalized = domain.toLowerCase();

		// Use confusables library to remove confusable characters
		try {
			normalized = confusables(normalized);
		} catch {
			// Fallback to manual replacement if confusables fails
			for (const [confusable, latin] of CONFUSABLE_CHARS) {
				normalized = normalized.replaceAll(confusable, latin);
			}
		}

		// Remove common TLD for comparison
		normalized = normalized.replace(/\.(com|org|net|edu|gov)$/, '');

		return normalized;
	}

	/**
	 * Calculate string similarity using Levenshtein distance
	 */
	calculateSimilarity(string1, string2) {
		const matrix = [];
		const length1 = string1.length;
		const length2 = string2.length;

		for (let i = 0; i <= length2; i++) {
			matrix[i] = [i];
		}

		for (let j = 0; j <= length1; j++) {
			matrix[0][j] = j;
		}

		for (let i = 1; i <= length2; i++) {
			for (let j = 1; j <= length1; j++) {
				if (string2.charAt(i - 1) === string1.charAt(j - 1)) {
					matrix[i][j] = matrix[i - 1][j - 1];
				} else {
					matrix[i][j] = Math.min(
						matrix[i - 1][j - 1] + 1,
						matrix[i][j - 1] + 1,
						matrix[i - 1][j] + 1,
					);
				}
			}
		}

		const maxLength = Math.max(length1, length2);
		return maxLength === 0 ? 1 : (maxLength - matrix[length2][length1]) / maxLength;
	}

	/**
	 * Detect scripts used in domain
	 */
	detectScripts(domain) {
		const scripts = new Set();

		for (const char of domain) {
			const code = char.codePointAt(0);

			if ((code >= 0x00_41 && code <= 0x00_5A) || (code >= 0x00_61 && code <= 0x00_7A)) {
				scripts.add('Latin');
			} else if (code >= 0x04_00 && code <= 0x04_FF) {
				scripts.add('Cyrillic');
			} else if (code >= 0x03_70 && code <= 0x03_FF) {
				scripts.add('Greek');
			} else if (code >= 0x4E_00 && code <= 0x9F_FF) {
				scripts.add('CJK');
			} else if (code >= 0x05_90 && code <= 0x05_FF) {
				scripts.add('Hebrew');
			} else if (code >= 0x06_00 && code <= 0x06_FF) {
				scripts.add('Arabic');
			}
		}

		return scripts;
	}

	/**
	 * Simple punycode decoder (basic implementation)
	 */
	decodePunycode(domain) {
		// This is a simplified implementation
		// In production, use a proper punycode library
		try {
			const url = new URL(`http://${domain}`);
			return url.hostname;
		} catch {
			return domain;
		}
	}

	/**
	 * Generate recommendations based on analysis
	 */
	generateRecommendations(analysis) {
		const recommendations = [];

		if (analysis.riskScore > 0.8) {
			recommendations.push('HIGH RISK: Likely homograph attack - block or quarantine');
		} else if (analysis.riskScore > 0.6) {
			recommendations.push('MEDIUM RISK: Suspicious domain - flag for review');
		} else if (analysis.riskScore > 0.3) {
			recommendations.push('LOW RISK: Monitor domain activity');
		} else {
			recommendations.push('SAFE: Domain appears legitimate');
		}

		if (analysis.isIDN) {
			recommendations.push('Consider displaying punycode representation to users');
		}

		if (analysis.riskFactors.some(f => f.includes('brand'))) {
			recommendations.push('Verify domain authenticity through official channels');
		}

		return recommendations;
	}

	/**
	 * Generate cache key
	 */
	getCacheKey(domain, context) {
		const contextHash = createHash('md5')
			.update(JSON.stringify(context))
			.digest('hex')
			.slice(0, 8);
		return `${domain}:${contextHash}`;
	}
}

export default EnhancedIDNDetector;

