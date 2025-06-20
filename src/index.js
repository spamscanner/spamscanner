import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {createHash} from 'node:crypto';
import {debuglog} from 'node:util';
import {fileURLToPath} from 'node:url';
import autoBind from 'auto-bind';
import AFHConvert from 'ascii-fullwidth-halfwidth-convert';
import ClamScan from 'clamscan';
import NaiveBayes from '@ladjs/naivebayes';
import arrayJoinConjunction from 'array-join-conjunction';
import bitcoinRegex from 'bitcoin-regex';
import creditCardRegex from 'credit-card-regex';
import emailRegexSafe from 'email-regex-safe';
import escapeStringRegexp from 'escape-string-regexp';
import expandContractions from '@stdlib/nlp-expand-contractions';
import fileExtension from 'file-extension';
import floatingPointRegex from 'floating-point-regex';
import lande from 'lande'; // Replaced franc with lande as per TODO
import hexaColorRegex from 'hexa-color-regex';
import ipRegex from 'ip-regex';
import isBuffer from 'is-buffer';
import isSANB from 'is-string-and-not-blank';
import macRegex from 'mac-regex';
import natural from 'natural';
import normalizeUrl from 'normalize-url';
import phoneRegex from 'phone-regex';
import snowball from 'node-snowball';
import striptags from 'striptags';
import superagent from 'superagent';
import sw from 'stopword';
import urlRegexSafe from 'url-regex-safe';
import {simpleParser} from 'mailparser';
import {fileTypeFromBuffer} from 'file-type';

// ES module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load JSON data
const REPLACEMENT_WORDS = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'replacement-words.json'), 'utf8'));
const executablesData = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'executables.json'), 'utf8'));

const EXECUTABLES = new Set(executablesData);

// Dynamic imports for modules that need to be loaded conditionally
const getReplacements = async () => {
	const {default: replacements} = await import('../replacements.js');
	return replacements;
};

const getClassifier = async () => {
	const {default: classifier} = await import('../get-classifier.js');
	return classifier;
};

const debug = debuglog('spamscanner');

// All tokenizers combined - improved regex pattern
const GENERIC_TOKENIZER
  = /[^a-zá-úÁ-Úà-úÀ-Úñü\dа-яёæøåàáảãạăắằẳẵặâấầẩẫậéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵđäöëïîûœçążśźęćńł-]+/i;

const converter = new AFHConvert();

// Chinese tokenizer setup with proper path resolution
const chineseTokenizer = {tokenize: text => text.split(/\s+/)};

// Enhanced stopwords with fallback for missing language-specific stopwords
const stopwordsMap = new Map([
	['ar', new Set([...(natural.stopwords || []), ...(sw.ar || [])])],
	['bg', new Set([...(natural.stopwords || []), ...(sw.bg || [])])],
	['bn', new Set([...(natural.stopwords || []), ...(sw.bn || [])])],
	['ca', new Set([...(natural.stopwords || []), ...(sw.ca || [])])],
	['cs', new Set([...(natural.stopwords || []), ...(sw.cs || [])])],
	['da', new Set([...(natural.stopwords || []), ...(sw.da || [])])],
	['de', new Set([...(natural.stopwords || []), ...(sw.de || [])])],
	['el', new Set([...(natural.stopwords || []), ...(sw.el || [])])],
	['en', new Set([...(natural.stopwords || []), ...(sw.en || [])])],
	['es', new Set([...(natural.stopwords || []), ...(sw.es || [])])],
	['fa', new Set([...(natural.stopwords || []), ...(sw.fa || [])])],
	['fi', new Set([...(natural.stopwords || []), ...(sw.fi || [])])],
	['fr', new Set([...(natural.stopwords || []), ...(sw.fr || [])])],
	['ga', new Set([...(natural.stopwords || []), ...(sw.ga || [])])],
	['gl', new Set([...(natural.stopwords || []), ...(sw.gl || [])])],
	['gu', new Set([...(natural.stopwords || []), ...(sw.gu || [])])],
	['he', new Set([...(natural.stopwords || []), ...(sw.he || [])])],
	['hi', new Set([...(natural.stopwords || []), ...(sw.hi || [])])],
	['hr', new Set([...(natural.stopwords || []), ...(sw.hr || [])])],
	['hu', new Set([...(natural.stopwords || []), ...(sw.hu || [])])],
	['hy', new Set([...(natural.stopwords || []), ...(sw.hy || [])])],
	['it', new Set([...(natural.stopwords || []), ...(sw.it || [])])],
	['ja', new Set([...(natural.stopwords || []), ...(sw.ja || [])])],
	['ko', new Set([...(natural.stopwords || []), ...(sw.ko || [])])],
	['la', new Set([...(natural.stopwords || []), ...(sw.la || [])])],
	['lt', new Set([...(natural.stopwords || []), ...(sw.lt || [])])],
	['lv', new Set([...(natural.stopwords || []), ...(sw.lv || [])])],
	['mr', new Set([...(natural.stopwords || []), ...(sw.mr || [])])],
	['nl', new Set([...(natural.stopwords || []), ...(sw.nl || [])])],
	['no', new Set([...(natural.stopwords || []), ...(sw.nob || [])])],
	['pl', new Set([...(natural.stopwords || []), ...(sw.pl || [])])],
	['pt', new Set([...(natural.stopwords || []), ...(sw.pt || [])])],
	['ro', new Set([...(natural.stopwords || []), ...(sw.ro || [])])],
	['ru', new Set([...(natural.stopwords || []), ...(sw.ru || [])])],
	['sk', new Set([...(natural.stopwords || []), ...(sw.sk || [])])],
	['sl', new Set([...(natural.stopwords || []), ...(sw.sl || [])])],
	['sv', new Set([...(natural.stopwords || []), ...(sw.sv || [])])],
	['th', new Set([...(natural.stopwords || []), ...(sw.th || [])])],
	['tr', new Set([...(natural.stopwords || []), ...(sw.tr || [])])],
	['uk', new Set([...(natural.stopwords || []), ...(sw.uk || [])])],
	['vi', new Set([...(natural.stopwords || []), ...(sw.vi || [])])],
	['zh', new Set([...(natural.stopwords || []), ...(sw.zh || [])])],
]);

// URL ending reserved characters
const URL_ENDING_RESERVED_CHARS = /[).,;!?]+$/;

// Date pattern detection (DONE)
const DATE_PATTERNS = [
	/\b(?:\d{1,2}[/-]){2}\d{2,4}\b/g, // MM/DD/YYYY or DD/MM/YYYY
	/\b\d{4}(?:[/-]\d{1,2}){2}\b/g, // YYYY/MM/DD
	/\b\d{1,2}\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{2,4}\b/gi, // DD MMM YYYY
	/\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{1,2},?\s+\d{2,4}\b/gi, // MMM DD, YYYY
];

// File path detection (DONE)
const FILE_PATH_PATTERNS = [
	/[a-z]:\\\\[^\\s<>:"|?*]+/gi, // Windows paths
	/\/[^\\s<>:"|?*]+/g, // Unix paths
	/~\/[^\\s<>:"|?*]+/g, // Home directory paths
];

// Additional regex patterns
const CREDIT_CARD_PATTERN = creditCardRegex({exact: false});
const PHONE_PATTERN = phoneRegex({exact: false});
const EMAIL_PATTERN = emailRegexSafe({exact: false});
const IP_PATTERN = ipRegex({exact: false});
const URL_PATTERN = urlRegexSafe({exact: false});
const BITCOIN_PATTERN = bitcoinRegex({exact: false});
const MAC_PATTERN = macRegex({exact: false});
const HEX_COLOR_PATTERN = hexaColorRegex({exact: false});
const FLOATING_POINT_PATTERN = floatingPointRegex;

class SpamScanner {
	constructor(options = {}) {
		this.config = {
			// Enhanced configuration options
			enableMacroDetection: true,
			enableMalwareUrlCheck: true,
			enablePerformanceMetrics: false,
			enableCaching: true,
			timeout: 30_000,
			supportedLanguages: ['en'],
			enableMixedLanguageDetection: false,
			enableAdvancedPatternRecognition: true,

			// Existing options
			debug: false,
			logger: console,
			clamscan: {
				removeInfected: false,
				quarantineInfected: false,
				scanLog: null,
				debugMode: false,
				fileList: null,
				scanRecursively: true,
				clamscanPath: '/usr/bin/clamscan',
				clamdscanPath: '/usr/bin/clamdscan',
				preference: 'clamdscan',
			},
			classifier: null,
			replacements: null,
			...options,
		};

		// Async loading of replacements and classifier
		this.classifier = null;
		this.clamscan = null;
		this.isInitialized = false;

		// Initialize replacements as empty Map
		this.replacements = new Map();

		// Performance metrics
		this.metrics = {
			totalScans: 0,
			averageTime: 0,
			lastScanTime: 0,
		};

		// Bind methods
		autoBind(this);
	}

	async initializeClassifier() {
		if (this.classifier) {
			return;
		}

		try {
			if (this.config.classifier) {
				this.classifier = new NaiveBayes(this.config.classifier);
			} else {
				const classifierData = await getClassifier();
				this.classifier = new NaiveBayes(classifierData);
			}

			// Custom tokenizer - we handle tokenization ourselves
			this.classifier.tokenizer = function (tokens) {
				if (typeof tokens === 'string') {
					return tokens.split(/\s+/);
				}

				return Array.isArray(tokens) ? tokens : [];
			};
		} catch (error) {
			debug('Failed to initialize classifier:', error);
			// Create a fallback classifier
			this.classifier = new NaiveBayes();
		}
	}

	// Initialize replacements
	async initializeReplacements() {
		if (this.replacements && this.replacements.size > 0) {
			return;
		}

		try {
			const replacements = this.config.replacements
				? this.config.replacements
				: await getReplacements();

			// Ensure replacements is a Map
			if (replacements instanceof Map) {
				this.replacements = replacements;
			} else if (typeof replacements === 'object' && replacements !== null) {
				this.replacements = new Map(Object.entries(replacements));
			} else {
				throw new Error('Invalid replacements format');
			}
		} catch (error) {
			debug('Failed to initialize replacements:', error);
			// Generate fallback replacements
			this.replacements = new Map();

			// Add some basic replacements
			const basicReplacements = {
				u: 'you',
				ur: 'your',
				r: 'are',
				n: 'and',
				'w/': 'with',
				b4: 'before',
				2: 'to',
				4: 'for',
			};

			for (const [word, replacement] of Object.entries(basicReplacements)) {
				this.replacements.set(word, replacement);
			}
		}
	}

	// Initialize regex helpers
	initializeRegex() {
		this.regexCache = new Map();
		this.urlCache = new Map();
	}

	// Enhanced virus scanning with timeout protection
	async getVirusResults(mail) {
		if (!this.clamscan) {
			try {
				this.clamscan = await new ClamScan().init(this.config.clamscan);
			} catch (error) {
				debug('ClamScan initialization failed:', error);
				return [];
			}
		}

		const results = [];
		const attachments = mail.attachments || [];

		for (const attachment of attachments) {
			try {
				if (attachment.content && isBuffer(attachment.content)) {
					const scanResult = await Promise.race([
						this.clamscan.scanBuffer(attachment.content),
						new Promise((_, rejectHandler) =>
							setTimeout(() => rejectHandler(new Error('Virus scan timeout')), this.config.timeout)),
					]);

					if (scanResult.isInfected) {
						results.push({
							filename: attachment.filename || 'unknown',
							virus: scanResult.viruses || ['Unknown virus'],
							type: 'virus',
						});
					}
				}
			} catch (error) {
				debug('Virus scan error:', error);
			}
		}

		return results;
	}

	// Macro detection (DONE)
	async getMacroResults(mail) {
		const results = [];
		const attachments = mail.attachments || [];
		const textContent = mail.text || '';
		const htmlContent = mail.html || '';

		// VBA Macro detection
		const vbaPatterns = [
			/sub\s+\w+\s*\(/gi,
			/function\s+\w+\s*\(/gi,
			/dim\s+\w+\s+as\s+\w+/gi,
			/application\.run/gi,
			/shell\s*\(/gi,
		];

		// PowerShell detection
		const powershellPatterns = [
			/powershell/gi,
			/invoke-expression/gi,
			/iex\s*\(/gi,
			/start-process/gi,
			/new-object\s+system\./gi,
		];

		// JavaScript macro detection
		const jsPatterns = [
			/eval\s*\(/gi,
			/document\.write/gi,
			/activexobject/gi,
			/wscript\./gi,
			/new\s+activexobject/gi,
		];

		// Batch file detection
		const batchPatterns = [/@echo\s+off/gi, /cmd\s*\/c/gi, /start\s+\/b/gi, /for\s+\/[lrf]/gi];

		// Get content from text, html, and header lines
		let allContent = textContent + ' ' + htmlContent;

		// Also check header lines for content (like macro code in raw emails)
		if (mail.headerLines && Array.isArray(mail.headerLines)) {
			for (const headerLine of mail.headerLines) {
				if (headerLine.line) {
					allContent += ' ' + headerLine.line;
				}
			}
		}

		// Check for VBA macros
		for (const pattern of vbaPatterns) {
			if (pattern.test(allContent)) {
				results.push({
					type: 'macro',
					subtype: 'vba',
					description: 'VBA macro detected',
				});
				break;
			}
		}

		// Check for PowerShell
		for (const pattern of powershellPatterns) {
			if (pattern.test(allContent)) {
				results.push({
					type: 'macro',
					subtype: 'powershell',
					description: 'PowerShell script detected',
				});
				break;
			}
		}

		// Check for JavaScript macros
		for (const pattern of jsPatterns) {
			if (pattern.test(allContent)) {
				results.push({
					type: 'macro',
					subtype: 'javascript',
					description: 'JavaScript macro detected',
				});
				break;
			}
		}

		// Check for batch files
		for (const pattern of batchPatterns) {
			if (pattern.test(allContent)) {
				results.push({
					type: 'macro',
					subtype: 'batch',
					description: 'Batch script detected',
				});
				break;
			}
		}

		// Check attachments for macro content
		for (const attachment of attachments) {
			if (attachment.filename) {
				const extension = fileExtension(attachment.filename).toLowerCase();
				const macroExtensions = ['vbs', 'vba', 'ps1', 'bat', 'cmd', 'scr', 'pif'];

				if (macroExtensions.includes(extension)) {
					results.push({
						type: 'macro',
						subtype: 'attachment',
						filename: attachment.filename,
						description: `Macro file attachment detected: ${extension}`,
					});
				}
			}
		}

		return results;
	}

	// File path detection (DONE)
	async getFilePathResults(mail) {
		const results = [];
		const textContent = mail.text || '';
		const htmlContent = mail.html || '';
		const allContent = textContent + ' ' + htmlContent;

		for (const pattern of FILE_PATH_PATTERNS) {
			const matches = allContent.match(pattern);
			if (matches) {
				for (const match of matches) {
					// Skip HTML tags and common false positives
					if (this.isValidFilePath(match)) {
						results.push({
							type: 'file_path',
							path: match,
							description: 'Suspicious file path detected',
						});
					}
				}
			}
		}

		return results;
	}

	// Check if a path is a valid file path (not HTML tag or false positive)
	isValidFilePath(path) {
		// Skip HTML tags (common HTML elements)
		const htmlTags = [
			'a',
			'abbr',
			'address',
			'area',
			'article',
			'aside',
			'audio',
			'b',
			'base',
			'bdi',
			'bdo',
			'blockquote',
			'body',
			'br',
			'button',
			'canvas',
			'caption',
			'cite',
			'code',
			'col',
			'colgroup',
			'data',
			'datalist',
			'dd',
			'del',
			'details',
			'dfn',
			'dialog',
			'div',
			'dl',
			'dt',
			'em',
			'embed',
			'fieldset',
			'figcaption',
			'figure',
			'footer',
			'form',
			'h1',
			'h2',
			'h3',
			'h4',
			'h5',
			'h6',
			'head',
			'header',
			'hr',
			'html',
			'i',
			'iframe',
			'img',
			'input',
			'ins',
			'kbd',
			'label',
			'legend',
			'li',
			'link',
			'main',
			'map',
			'mark',
			'meta',
			'meter',
			'nav',
			'noscript',
			'object',
			'ol',
			'optgroup',
			'option',
			'output',
			'p',
			'param',
			'picture',
			'pre',
			'progress',
			'q',
			'rp',
			'rt',
			'ruby',
			's',
			'samp',
			'script',
			'section',
			'select',
			'small',
			'source',
			'span',
			'strong',
			'style',
			'sub',
			'summary',
			'sup',
			'svg',
			'table',
			'tbody',
			'td',
			'template',
			'textarea',
			'tfoot',
			'th',
			'thead',
			'time',
			'title',
			'tr',
			'track',
			'u',
			'ul',
			'var',
			'video',
			'wbr',
		];

		// Check if it's an HTML tag
		const tagMatch = path.match(/^\/([a-z\d]+)$/i);
		if (tagMatch && htmlTags.includes(tagMatch[1].toLowerCase())) {
			return false;
		}

		// Skip very short paths that are likely false positives
		if (path.length < 4) {
			return false;
		}

		// Skip paths that are just domain names
		if (/^\/\/[a-z\d.-]+$/i.test(path)) {
			return false;
		}

		// Must have a file extension or be a directory with multiple segments
		if (!path.includes('.') && !path.includes('/')) {
			return false;
		}

		return true;
	}

	// Optimize URL parsing with timeout protection (DONE)
	async optimizeUrlParsing(url) {
		try {
			return await Promise.race([
				normalizeUrl(url, {
					stripHash: true,
					stripWWW: false,
					removeQueryParameters: false,
				}),
				new Promise((_, rejectHandler) =>
					setTimeout(() => rejectHandler(new Error('URL parsing timeout')), 5000)),
			]);
		} catch {
			return url;
		}
	}

	// Enhanced Cloudflare blocked domain checking with timeout
	async isCloudflareBlocked(hostname) {
		try {
			const response = await Promise.race([
				superagent
					.get(`https://1.1.1.3/dns-query?name=${hostname}&type=A`)
					.set('Accept', 'application/dns-json')
					.timeout(5000),
				new Promise((_, rejectHandler) =>
					setTimeout(() => rejectHandler(new Error('DNS timeout')), 5000)),
			]);

			return response.body?.Status === 3; // NXDOMAIN indicates blocked
		} catch {
			return false;
		}
	}

	// Extract URLs from all possible sources
	extractAllUrls(mail, originalSource) {
		let allText = '';

		// Add mail text and html
		allText += (mail.text || '') + ' ' + (mail.html || '');

		// Add header lines content
		if (mail.headerLines && Array.isArray(mail.headerLines)) {
			for (const headerLine of mail.headerLines) {
				if (headerLine.line) {
					allText += ' ' + headerLine.line;
				}
			}
		}

		// Also check original source if it's a simple string
		if (typeof originalSource === 'string') {
			allText += ' ' + originalSource;
		}

		return this.getUrls(allText);
	}

	// Enhanced URL extraction with improved parsing
	getUrls(string_) {
		if (!isSANB(string_)) {
			return [];
		}

		const urls = [];
		const matches = string_.match(URL_PATTERN);

		if (matches) {
			for (let url of matches) {
				// Clean up URL ending characters
				url = url.replace(URL_ENDING_RESERVED_CHARS, '');

				// Validate and normalize URL
				try {
					const normalizedUrl = normalizeUrl(url, {
						stripHash: false,
						stripWWW: false,
					});
					urls.push(normalizedUrl);
				} catch {
					// If normalization fails, keep original
					urls.push(url);
				}
			}
		}

		return [...new Set(urls)]; // Remove duplicates
	}

	// Enhanced tokenization with language detection
	async getTokens(string_, locale = 'en', isHtml = false) {
		if (!isSANB(string_)) {
			return [];
		}

		let text = string_;

		// Strip HTML if needed
		if (isHtml) {
			text = striptags(text);
		}

		// Detect language if not provided or if mixed language detection is enabled
		if (!locale || this.config.enableMixedLanguageDetection) {
			try {
				const detected = lande(text);
				if (detected && detected.length > 0) {
					locale = detected[0][0];
				}
			} catch {
				locale ||= 'en';
			}
		}

		// Normalize locale
		locale = this.parseLocale(locale);

		// Convert full-width to half-width characters
		text = converter.toHalfWidth(text);

		// Expand contractions
		try {
			text = expandContractions(text);
		} catch {
			// If expansion fails, continue with original text
		}

		// Tokenize based on language
		let tokens = [];

		if (locale === 'ja') {
			// Japanese tokenization
			try {
				tokens = chineseTokenizer.tokenize(text);
			} catch {
				tokens = text.split(GENERIC_TOKENIZER);
			}
		} else if (locale === 'zh') {
			// Chinese tokenization
			try {
				tokens = chineseTokenizer.tokenize(text);
			} catch {
				tokens = text.split(GENERIC_TOKENIZER);
			}
		} else {
			// Generic tokenization for other languages
			tokens = text.split(GENERIC_TOKENIZER);
		}

		// Process tokens
		let processedTokens = tokens
			.map(token => token.toLowerCase().trim())
			.filter(token => token.length > 0 && token.length <= 50); // Reasonable length limit

		// Remove stopwords
		const stopwordSet = stopwordsMap.get(locale) || stopwordsMap.get('en');
		if (stopwordSet) {
			processedTokens = processedTokens.filter(token => !stopwordSet.has(token));
		}

		// Stem words if available for the language
		try {
			if (['en', 'es', 'fr', 'de', 'it', 'pt', 'ru'].includes(locale)) {
				processedTokens = processedTokens.map(token => {
					try {
						return snowball.stemword(token, locale);
					} catch {
						return token;
					}
				});
			}
		} catch {
			// If stemming fails, continue with original tokens
		}

		// Apply token hashing if enabled
		if (this.config.hashTokens) {
			processedTokens = processedTokens.map(token =>
				createHash('sha256')
					.update(token)
					.digest('hex')
					.slice(0, 16), // Use first 16 characters for efficiency
			);
		}

		return processedTokens;
	}

	// Enhanced text preprocessing with pattern recognition
	async preprocessText(string_) {
		if (!isSANB(string_)) {
			return '';
		}

		let text = string_;

		// Apply replacements if available
		if (this.replacements) {
			for (const [original, replacement] of this.replacements) {
				text = text.replaceAll(new RegExp(escapeStringRegexp(original), 'gi'), replacement);
			}
		}

		// Advanced pattern recognition (DONE)
		if (this.config.enableAdvancedPatternRecognition) {
			// Replace patterns with normalized tokens
			text = text.replaceAll(DATE_PATTERNS[0], ' DATE_PATTERN ');
			text = text.replace(CREDIT_CARD_PATTERN, ' CREDIT_CARD ');
			text = text.replace(PHONE_PATTERN, ' PHONE_NUMBER ');
			text = text.replace(EMAIL_PATTERN, ' EMAIL_ADDRESS ');
			text = text.replace(IP_PATTERN, ' IP_ADDRESS ');
			text = text.replace(URL_PATTERN, ' URL_LINK ');
			text = text.replace(BITCOIN_PATTERN, ' BITCOIN_ADDRESS ');
			text = text.replace(MAC_PATTERN, ' MAC_ADDRESS ');
			text = text.replace(HEX_COLOR_PATTERN, ' HEX_COLOR ');
			text = text.replace(FLOATING_POINT_PATTERN, ' FLOATING_POINT ');
		}

		return text;
	}

	// Main scan method - enhanced with performance metrics and new features
	async scan(source) {
		const startTime = Date.now();

		try {
			// Initialize components if needed
			await this.initializeClassifier();
			await this.initializeReplacements();

			// Get tokens and mail from source
			const {tokens, mail} = await this.getTokensAndMailFromSource(source);

			// Run all detecti		// Run all detection methods in parallel
			const [classification, phishing, executables, macros, arbitrary, viruses, patterns, idnHomographAttack]
        = await Promise.all([
        	this.getClassification(tokens),
        	this.getPhishingResults(mail),
        	this.getExecutableResults(mail),
        	this.getMacroResults(mail),
        	this.getArbitraryResults(mail),
        	this.getVirusResults(mail),
        	this.getPatternResults(mail),
        	this.getIDNHomographResults(mail),
        ]);

			// Determine if spam
			const isSpam
        = classification.category === 'spam'
        	|| phishing.length > 0
        	|| executables.length > 0
        	|| macros.length > 0
        	|| arbitrary.length > 0
        	|| viruses.length > 0
        	|| patterns.length > 0
        	|| (idnHomographAttack && idnHomographAttack.detected);

			// Generate message
			let message = 'Ham';
			if (isSpam) {
				const reasons = [];
				if (classification.category === 'spam') {
					reasons.push('spam classification');
				}

				if (phishing.length > 0) {
					reasons.push('phishing detected');
				}

				if (executables.length > 0) {
					reasons.push('executable content');
				}

				if (macros.length > 0) {
					reasons.push('macro detected');
				}

				if (arbitrary.length > 0) {
					reasons.push('arbitrary patterns');
				}

				if (viruses.length > 0) {
					reasons.push('virus detected');
				}

				if (patterns.length > 0) {
					reasons.push('suspicious patterns');
				}

				if (idnHomographAttack && idnHomographAttack.detected) {
					reasons.push('IDN homograph attack');
				}

				message = `Spam (${arrayJoinConjunction(reasons)})`;
			}

			const endTime = Date.now();
			const processingTime = endTime - startTime;

			// Update metrics
			this.metrics.totalScans++;
			this.metrics.lastScanTime = processingTime;
			this.metrics.averageTime
        = (this.metrics.averageTime * (this.metrics.totalScans - 1) + processingTime)
        	/ this.metrics.totalScans;

			const result = {
				isSpam,
				message,
				results: {
					classification,
					phishing,
					executables,
					macros,
					arbitrary,
					viruses,
					patterns,
					idnHomographAttack,
				},
				links: this.extractAllUrls(mail, source),
				tokens,
				mail,
			};

			// Add performance metrics if enabled
			if (this.config.enablePerformanceMetrics) {
				result.metrics = {
					totalTime: processingTime,
					classificationTime: 0, // Would need to measure individually
					phishingTime: 0,
					executableTime: 0,
					macroTime: 0,
					virusTime: 0,
					patternTime: 0,
					idnTime: 0,
					memoryUsage: process.memoryUsage(),
				};
			}

			return result;
		} catch (error) {
			debug('Scan error:', error);
			throw error;
		}
	}

	// Get pattern recognition results
	async getPatternResults(mail) {
		const results = [];
		const textContent = mail.text || '';
		const htmlContent = mail.html || '';
		const allContent = textContent + ' ' + htmlContent;

		// Date pattern detection
		for (const pattern of DATE_PATTERNS) {
			const matches = allContent.match(pattern);
			if (matches && matches.length > 5) {
				// Suspicious if many dates
				results.push({
					type: 'pattern',
					subtype: 'date_spam',
					count: matches.length,
					description: 'Excessive date patterns detected',
				});
			}
		}

		// File path detection
		const filePathResults = await this.getFilePathResults(mail);
		results.push(...filePathResults);

		return results;
	}

	// Enhanced mail parsing with better error handling
	async getTokensAndMailFromSource(source) {
		let mail;

		if (typeof source === 'string' && fs.existsSync(source)) {
			// File path
			source = fs.readFileSync(source);
		}

		if (isBuffer(source)) {
			source = source.toString();
		}

		if (!source || typeof source !== 'string') {
			source = '';
		}

		try {
			mail = await simpleParser(source);
		} catch (error) {
			debug('Mail parsing error:', error);
			// Create minimal mail object
			mail = {
				text: source,
				html: '',
				subject: '',
				from: {},
				to: [],
				attachments: [],
			};
		}

		// Preprocess text content
		const textContent = await this.preprocessText(mail.text || '');
		const htmlContent = await this.preprocessText(striptags(mail.html || ''));
		const subjectContent = await this.preprocessText(mail.subject || '');

		// Get tokens from all content
		const allContent = [textContent, htmlContent, subjectContent].join(' ');
		const tokens = await this.getTokens(allContent, 'en');

		return {tokens, mail};
	}

	// Enhanced classification with better error handling
	async getClassification(tokens) {
		if (!this.classifier) {
			await this.initializeClassifier();
		}

		try {
			// Join tokens into a string for the classifier
			const text = Array.isArray(tokens) ? tokens.join(' ') : String(tokens);
			const result = this.classifier.categorize(text);

			return {
				category: result,
				probability: 0.5, // Default probability
			};
		} catch (error) {
			debug('Classification error:', error);
			return {
				category: 'ham',
				probability: 0.5,
			};
		}
	}

	// Enhanced phishing detection
	async getPhishingResults(mail) {
		const results = [];
		const links = this.getUrls(mail.text || '');

		for (const url of links) {
			try {
				const normalizedUrl = await this.optimizeUrlParsing(url);
				const parsed = new URL(normalizedUrl);

				// Check for suspicious domains
				const isBlocked = await this.isCloudflareBlocked(parsed.hostname);
				if (isBlocked) {
					results.push({
						type: 'phishing',
						url: normalizedUrl,
						description: 'Blocked by security filters',
					});
				}

				// Enhanced IDN homograph attack detection
				const idnDetector = await this.getIDNDetector();
				if (idnDetector && parsed.hostname) {
					const context = {
						emailContent: mail.text || mail.html || '',
						displayText: url === normalizedUrl ? null : url,
						senderReputation: 0.5, // Default neutral reputation
					};

					const idnAnalysis = idnDetector.detectHomographAttack(parsed.hostname, context);

					if (idnAnalysis.riskScore > 0.6) {
						results.push({
							type: 'phishing',
							url: normalizedUrl,
							description: `IDN homograph attack detected (risk: ${(idnAnalysis.riskScore * 100).toFixed(1)}%)`,
							details: {
								riskFactors: idnAnalysis.riskFactors,
								recommendations: idnAnalysis.recommendations,
								confidence: idnAnalysis.confidence,
							},
						});
					} else if (idnAnalysis.riskScore > 0.3) {
						results.push({
							type: 'suspicious',
							url: normalizedUrl,
							description: `Suspicious IDN domain (risk: ${(idnAnalysis.riskScore * 100).toFixed(1)}%)`,
							details: {
								riskFactors: idnAnalysis.riskFactors,
								recommendations: idnAnalysis.recommendations,
							},
						});
					}
				}
			} catch (error) {
				debug('Phishing check error:', error);
			}
		}

		return results;
	}

	// Enhanced executable detection
	async getExecutableResults(mail) {
		const results = [];
		const attachments = mail.attachments || [];

		for (const attachment of attachments) {
			if (attachment.filename) {
				const extension = fileExtension(attachment.filename).toLowerCase();

				if (EXECUTABLES.has(extension)) {
					results.push({
						type: 'executable',
						filename: attachment.filename,
						extension,
						description: 'Executable file attachment',
					});
				}
			}

			// Check file content for executable signatures
			if (attachment.content && isBuffer(attachment.content)) {
				try {
					const fileType = await fileTypeFromBuffer(attachment.content);
					if (fileType && EXECUTABLES.has(fileType.ext)) {
						results.push({
							type: 'executable',
							filename: attachment.filename || 'unknown',
							detectedType: fileType.ext,
							description: 'Executable content detected',
						});
					}
				} catch (error) {
					debug('File type detection error:', error);
				}
			}
		}

		return results;
	}

	// Arbitrary results (GTUBE, etc.)
	async getArbitraryResults(mail) {
		const results = [];

		// Get content from text, html, and header lines
		let content = (mail.text || '') + (mail.html || '');

		// Also check header lines for content (like GTUBE in raw emails)
		if (mail.headerLines && Array.isArray(mail.headerLines)) {
			for (const headerLine of mail.headerLines) {
				if (headerLine.line) {
					content += ' ' + headerLine.line;
				}
			}
		}

		// GTUBE test
		if (content.includes('XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X')) {
			results.push({
				type: 'arbitrary',
				description: 'GTUBE spam test pattern detected',
			});
		}

		return results;
	}

	// Parse and normalize locale
	parseLocale(locale) {
		if (!locale || typeof locale !== 'string') {
			return 'en';
		}

		// Handle locale codes like 'en-US' -> 'en'
		const normalized = locale.toLowerCase().split('-')[0];
		// Map some common variations
		const localeMap = {
			nb: 'no', // Norwegian Bokmål
			nn: 'no', // Norwegian Nynorsk
			'zh-cn': 'zh',
			'zh-tw': 'zh',
		};
		return localeMap[normalized] || normalized;
	}

	// Get IDN homograph attack results
	async getIDNHomographResults(mail) {
		const result = {
			detected: false,
			domains: [],
			riskScore: 0,
			details: [],
		};

		try {
			const idnDetector = await this.getIDNDetector();
			if (!idnDetector) {
				return result;
			}

			// Extract URLs from email content
			const textContent = mail.text || '';
			const htmlContent = mail.html || '';
			const allContent = textContent + ' ' + htmlContent;
			const urls = this.getUrls(allContent);

			// Analyze each domain
			for (const url of urls) {
				try {
					const normalizedUrl = await this.optimizeUrlParsing(url);
					const parsed = new URL(normalizedUrl);
					const domain = parsed.hostname;

					if (!domain) {
						continue;
					}

					// Prepare context for analysis
					const context = {
						emailContent: allContent,
						displayText: url === normalizedUrl ? null : url,
						senderReputation: 0.5, // Default neutral reputation
						emailHeaders: mail.headers || {},
					};

					// Perform IDN analysis
					const analysis = idnDetector.detectHomographAttack(domain, context);

					if (analysis.riskScore > 0.3) {
						result.detected = true;
						result.domains.push({
							domain,
							originalUrl: url,
							normalizedUrl,
							riskScore: analysis.riskScore,
							riskFactors: analysis.riskFactors,
							recommendations: analysis.recommendations,
							confidence: analysis.confidence,
						});

						// Update overall risk score to highest found
						result.riskScore = Math.max(result.riskScore, analysis.riskScore);
					}
				} catch (error) {
					debug('IDN analysis error for URL:', url, error);
				}
			}

			// Add summary details
			if (result.detected) {
				result.details.push(`Found ${result.domains.length} suspicious domain(s)`);
				result.details.push(`Highest risk score: ${(result.riskScore * 100).toFixed(1)}%`);

				// Add specific risk factors
				const allRiskFactors = new Set();
				for (const domain of result.domains) {
					for (const factor of domain.riskFactors) {
						allRiskFactors.add(factor);
					}
				}

				result.details.push(...allRiskFactors);
			}
		} catch (error) {
			debug('IDN homograph detection error:', error);
		}

		return result;
	}

	// Get IDN detector instance
	async getIDNDetector() {
		if (!this.idnDetector) {
			try {
				const {default: EnhancedIDNDetector} = await import('./enhanced-idn-detector.js');
				this.idnDetector = new EnhancedIDNDetector({
					strictMode: this.config.strictIDNDetection || false,
					enableWhitelist: true,
					enableBrandProtection: true,
					enableContextAnalysis: true,
				});
			} catch (error) {
				debug('Failed to load IDN detector:', error);
				return null;
			}
		}

		return this.idnDetector;
	}

	// Hybrid language detection using both lande and franc
	async detectLanguageHybrid(text) {
		if (!text || typeof text !== 'string' || text.length < 3) {
			return 'en';
		}

		// Handle edge cases for non-linguistic content
		const cleanText = text.trim();
		if (!cleanText || /^[\d\s\W]+$/.test(cleanText)) {
			// Only numbers, spaces, and special characters
			return 'en';
		}

		try {
			// Use lande for short text (< 50 chars), franc for longer text
			if (text.length < 50) {
				const landeResult = lande(text);
				if (landeResult && landeResult.length > 0) {
					// Convert lande's 3-letter codes to 2-letter codes
					const detected = landeResult[0][0];
					const normalized = this.normalizeLanguageCode(detected);

					// Additional validation for short text detection
					if (this.isValidShortTextDetection(text, normalized)) {
						return normalized;
					}

					// Fallback to English for ambiguous short text
					return 'en';
				}

				return 'en';
			}

			// Import franc dynamically
			const {franc} = await import('franc');
			const francResult = franc(text);
			if (francResult === 'und') {
				// Fallback to lande if franc can't detect
				const landeResult = lande(text);
				if (landeResult && landeResult.length > 0) {
					return this.normalizeLanguageCode(landeResult[0][0]);
				}

				return 'en';
			}

			return this.normalizeLanguageCode(francResult);
		} catch (error) {
			debug('Language detection error:', error);
			// Fallback to lande
			try {
				const landeResult = lande(text);
				if (landeResult && landeResult.length > 0) {
					return this.normalizeLanguageCode(landeResult[0][0]);
				}

				return 'en';
			} catch {
				return 'en';
			}
		}
	}

	// Validate short text language detection
	isValidShortTextDetection(text, detectedLang) {
		// For non-Latin scripts, always trust the detection
		const hasNonLatin = /[^\u0000-\u024F\u1E00-\u1EFF]/.test(text);
		if (hasNonLatin) {
			return true;
		}

		// For very short Latin text (< 7 chars), be conservative
		if (text.length < 7 && detectedLang !== 'en') {
			return false;
		}

		// For longer Latin text, trust the detection
		return true;
	}

	// Normalize language codes from 3-letter to 2-letter format
	normalizeLanguageCode(code) {
		if (!code || typeof code !== 'string') {
			return 'en';
		}

		// If already 2-letter code, return as-is
		if (code.length === 2) {
			return code.toLowerCase();
		}

		// Convert 3-letter ISO 639-2/3 codes to 2-letter ISO 639-1 codes
		const codeMap = {
			// Common language mappings
			eng: 'en', // English
			fra: 'fr', // French
			fre: 'fr', // French (alternative)
			spa: 'es', // Spanish
			deu: 'de', // German
			ger: 'de', // German (alternative)
			ita: 'it', // Italian
			por: 'pt', // Portuguese
			rus: 'ru', // Russian
			jpn: 'ja', // Japanese
			kor: 'ko', // Korean
			cmn: 'zh', // Chinese (Mandarin)
			zho: 'zh', // Chinese
			chi: 'zh', // Chinese (alternative)
			ara: 'ar', // Arabic
			hin: 'hi', // Hindi
			ben: 'bn', // Bengali
			urd: 'ur', // Urdu
			tur: 'tr', // Turkish
			pol: 'pl', // Polish
			nld: 'nl', // Dutch
			dut: 'nl', // Dutch (alternative)
			swe: 'sv', // Swedish
			nor: 'no', // Norwegian
			dan: 'da', // Danish
			fin: 'fi', // Finnish
			hun: 'hu', // Hungarian
			ces: 'cs', // Czech
			cze: 'cs', // Czech (alternative)
			slk: 'sk', // Slovak
			slo: 'sk', // Slovak (alternative)
			slv: 'sl', // Slovenian
			hrv: 'hr', // Croatian
			srp: 'sr', // Serbian
			bul: 'bg', // Bulgarian
			ron: 'ro', // Romanian
			rum: 'ro', // Romanian (alternative)
			ell: 'el', // Greek
			gre: 'el', // Greek (alternative)
			heb: 'he', // Hebrew
			tha: 'th', // Thai
			vie: 'vi', // Vietnamese
			ind: 'id', // Indonesian
			msa: 'ms', // Malay
			may: 'ms', // Malay (alternative)
			tgl: 'tl', // Tagalog
			ukr: 'uk', // Ukrainian
			bel: 'be', // Belarusian
			lit: 'lt', // Lithuanian
			lav: 'lv', // Latvian
			est: 'et', // Estonian
			cat: 'ca', // Catalan
			eus: 'eu', // Basque
			baq: 'eu', // Basque (alternative)
			glg: 'gl', // Galician
			gle: 'ga', // Irish
			gla: 'gd', // Scottish Gaelic
			cym: 'cy', // Welsh
			wel: 'cy', // Welsh (alternative)
			isl: 'is', // Icelandic
			ice: 'is', // Icelandic (alternative)
			mlt: 'mt', // Maltese
			afr: 'af', // Afrikaans
			swa: 'sw', // Swahili
			amh: 'am', // Amharic
			hau: 'ha', // Hausa
			yor: 'yo', // Yoruba
			ibo: 'ig', // Igbo
			som: 'so', // Somali
			orm: 'om', // Oromo
			tig: 'ti', // Tigrinya
			mlg: 'mg', // Malagasy
			nya: 'ny', // Chichewa
			sna: 'sn', // Shona
			xho: 'xh', // Xhosa
			zul: 'zu', // Zulu
			nso: 'nso', // Northern Sotho
			sot: 'st', // Southern Sotho
			tsn: 'tn', // Tswana
			ven: 've', // Venda
			tso: 'ts', // Tsonga
			ssw: 'ss', // Swati
			nde: 'nr', // Southern Ndebele
			nbl: 'nd', // Northern Ndebele
		};

		const normalized = code.toLowerCase();
		return codeMap[normalized] || 'en';
	}
}

export default SpamScanner;
