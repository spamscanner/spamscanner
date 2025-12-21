/**
 * Runtime tests for TypeScript type definitions
 *
 * These tests verify that the TypeScript type definitions correctly match
 * the actual JavaScript implementation at runtime.
 */

import {Buffer} from 'node:buffer';
import {test} from 'node:test';
import assert from 'node:assert';
import SpamScanner from '../src/index.js';

// Test: SpamScanner constructor and config types
test('SpamScanner constructor accepts valid config options', () => {
	const scanner = new SpamScanner({
		debug: true,
		timeout: 60_000,
		enableMacroDetection: true,
		enablePerformanceMetrics: false,
		supportedLanguages: ['en', 'es'],
		enableMixedLanguageDetection: false,
		enableAdvancedPatternRecognition: true,
	});

	assert.strictEqual(typeof scanner.config, 'object');
	assert.strictEqual(scanner.config.debug, true);
	assert.strictEqual(scanner.config.timeout, 60_000);
	assert.strictEqual(scanner.config.enableMacroDetection, true);
	assert.strictEqual(scanner.config.enablePerformanceMetrics, false);
	assert.deepStrictEqual(scanner.config.supportedLanguages, ['en', 'es']);
});

// Test: SpamScanner constructor with ClamScan config
test('SpamScanner accepts ClamScan configuration', () => {
	const scanner = new SpamScanner({
		clamscan: {
			removeInfected: false,
			quarantineInfected: false,
			scanRecursively: true,
			preference: 'clamdscan',
		},
	});

	assert.strictEqual(typeof scanner.config.clamscan, 'object');
	assert.strictEqual(scanner.config.clamscan.removeInfected, false);
	assert.strictEqual(scanner.config.clamscan.preference, 'clamdscan');
});

// Test: SpamScanner constructor with replacements as Map
test('SpamScanner accepts replacements as Map', () => {
	const replacements = new Map([
		['u', 'you'],
		['r', 'are'],
	]);

	const scanner = new SpamScanner({replacements});
	assert.strictEqual(typeof scanner.config.replacements, 'object');
});

// Test: SpamScanner constructor with replacements as object
test('SpamScanner accepts replacements as object', () => {
	const scanner = new SpamScanner({
		replacements: {
			u: 'you',
			r: 'are',
		},
	});

	assert.strictEqual(typeof scanner.config.replacements, 'object');
});

// Test: scan method returns correct structure
test('scan method returns ScanResult structure', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const result = await scanner.scan('This is a test email message');

	// Verify top-level properties
	assert.strictEqual(typeof result.isSpam, 'boolean');
	assert.strictEqual(typeof result.message, 'string');
	assert.strictEqual(typeof result.results, 'object');
	assert.ok(Array.isArray(result.links));
	assert.ok(Array.isArray(result.tokens));
	assert.strictEqual(typeof result.mail, 'object');
});

// Test: ScanResults structure
test('scan results contain all expected detection arrays', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const result = await scanner.scan('Test email');

	// Classification
	assert.strictEqual(typeof result.results.classification, 'object');
	assert.strictEqual(typeof result.results.classification.category, 'string');
	assert.ok(['spam', 'ham'].includes(result.results.classification.category));
	assert.strictEqual(typeof result.results.classification.probability, 'number');

	// Detection arrays
	assert.ok(Array.isArray(result.results.phishing));
	assert.ok(Array.isArray(result.results.executables));
	assert.ok(Array.isArray(result.results.macros));
	assert.ok(Array.isArray(result.results.arbitrary));
	assert.ok(Array.isArray(result.results.viruses));
	assert.ok(Array.isArray(result.results.patterns));
	assert.ok(Array.isArray(result.results.toxicity));
	assert.ok(Array.isArray(result.results.nsfw));

	// IDN Homograph result
	assert.strictEqual(typeof result.results.idnHomographAttack, 'object');
	assert.strictEqual(typeof result.results.idnHomographAttack.detected, 'boolean');
	assert.ok(Array.isArray(result.results.idnHomographAttack.domains));
	assert.strictEqual(typeof result.results.idnHomographAttack.riskScore, 'number');
	assert.ok(Array.isArray(result.results.idnHomographAttack.details));
});

// Test: scan with GTUBE returns spam with arbitrary result
test('GTUBE detection returns correct ArbitraryResult structure', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const gtube = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';
	const result = await scanner.scan(gtube);

	assert.strictEqual(result.isSpam, true);
	assert.ok(result.results.arbitrary.length > 0);

	const arbitraryResult = result.results.arbitrary[0];
	assert.strictEqual(arbitraryResult.type, 'arbitrary');
	assert.strictEqual(typeof arbitraryResult.description, 'string');
});

// Test: macro detection returns correct MacroResult structure
test('macro detection returns correct MacroResult structure', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const macroContent = String.raw`Sub AutoOpen()\nShell "malware.exe"\nEnd Sub`;
	const result = await scanner.scan(macroContent);

	assert.strictEqual(result.isSpam, true);
	assert.ok(result.results.macros.length > 0);

	const macroResult = result.results.macros[0];
	assert.strictEqual(macroResult.type, 'macro');
	assert.strictEqual(typeof macroResult.subtype, 'string');
	assert.ok([
		'vba',
		'powershell',
		'javascript',
		'batch',
		'script',
		'office_document',
		'legacy_office',
		'pdf_javascript',
	].includes(macroResult.subtype));
	assert.strictEqual(typeof macroResult.description, 'string');
});

// Test: getTokensAndMailFromSource returns correct structure
test('getTokensAndMailFromSource returns TokensAndMailResult', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const result = await scanner.getTokensAndMailFromSource('Test email content');

	assert.ok(Array.isArray(result.tokens));
	assert.strictEqual(typeof result.mail, 'object');
});

// Test: getClassification returns ClassificationResult
test('getClassification returns ClassificationResult', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	await scanner.initializeClassifier();

	const result = await scanner.getClassification(['test', 'tokens']);

	assert.strictEqual(typeof result.category, 'string');
	assert.ok(['spam', 'ham'].includes(result.category));
	assert.strictEqual(typeof result.probability, 'number');
});

// Test: getTokens returns string array
test('getTokens returns array of strings', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const tokens = await scanner.getTokens('Hello world test message', 'en', false);

	assert.ok(Array.isArray(tokens));
	for (const token of tokens) {
		assert.strictEqual(typeof token, 'string');
	}
});

// Test: getUrls returns string array
test('getUrls returns array of URL strings', () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const urls = scanner.getUrls('Visit https://example.com and http://test.org');

	assert.ok(Array.isArray(urls));
	assert.ok(urls.length > 0);
	for (const url of urls) {
		assert.strictEqual(typeof url, 'string');
	}
});

// Test: optimizeUrlParsing returns string
test('optimizeUrlParsing returns normalized URL string', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const result = await scanner.optimizeUrlParsing('https://example.com/path?query=1');

	assert.strictEqual(typeof result, 'string');
});

// Test: parseUrlWithTldts returns ParsedUrl or null
test('parseUrlWithTldts returns ParsedUrl structure', () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const result = scanner.parseUrlWithTldts('https://www.example.com/path');

	if (result !== null) {
		assert.strictEqual(typeof result.domain, 'string');
		assert.strictEqual(typeof result.hostname, 'string');
		assert.strictEqual(typeof result.isIp, 'boolean');
	}
});

// Test: detectLanguageHybrid returns language code
test('detectLanguageHybrid returns language code string', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const result = await scanner.detectLanguageHybrid('This is English text');

	assert.strictEqual(typeof result, 'string');
	assert.strictEqual(result.length, 2); // 2-letter ISO code
});

// Test: parseLocale normalizes locale codes
test('parseLocale returns normalized locale code', () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	assert.strictEqual(scanner.parseLocale('en-US'), 'en');
	assert.strictEqual(scanner.parseLocale('EN'), 'en');
	assert.strictEqual(scanner.parseLocale('nb'), 'no'); // Norwegian Bokmål
});

// Test: normalizeLanguageCode converts 3-letter to 2-letter
test('normalizeLanguageCode converts ISO 639-2 to ISO 639-1', () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	assert.strictEqual(scanner.normalizeLanguageCode('eng'), 'en');
	assert.strictEqual(scanner.normalizeLanguageCode('fra'), 'fr');
	assert.strictEqual(scanner.normalizeLanguageCode('deu'), 'de');
	assert.strictEqual(scanner.normalizeLanguageCode('spa'), 'es');
	assert.strictEqual(scanner.normalizeLanguageCode('jpn'), 'ja');
	assert.strictEqual(scanner.normalizeLanguageCode('zho'), 'zh');
});

// Test: preprocessText returns string
test('preprocessText returns processed string', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const result = await scanner.preprocessText('Hello u r awesome');

	assert.strictEqual(typeof result, 'string');
});

// Test: isValidFilePath returns boolean
test('isValidFilePath returns boolean', () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	assert.strictEqual(typeof scanner.isValidFilePath('/usr/bin/test'), 'boolean');
	assert.strictEqual(typeof scanner.isValidFilePath('/a'), 'boolean');
});

// Test: scanner metrics structure
test('scanner metrics have correct structure', () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	assert.strictEqual(typeof scanner.metrics, 'object');
	assert.strictEqual(typeof scanner.metrics.totalScans, 'number');
	assert.strictEqual(typeof scanner.metrics.averageTime, 'number');
	assert.strictEqual(typeof scanner.metrics.lastScanTime, 'number');
});

// Test: performance metrics when enabled
test('performance metrics included when enabled', async () => {
	const scanner = new SpamScanner({
		enablePerformanceMetrics: true,
		supportedLanguages: [],
	});
	const result = await scanner.scan('Test email');

	assert.strictEqual(typeof result.metrics, 'object');
	assert.strictEqual(typeof result.metrics.totalTime, 'number');
	assert.strictEqual(typeof result.metrics.memoryUsage, 'object');
});

// Test: individual detection methods return correct array types
test('getPhishingResults returns PhishingResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {
		text: 'Visit https://fake-paypal.com to verify',
		html: '',
	};
	const results = await scanner.getPhishingResults(mail);

	assert.ok(Array.isArray(results));
	for (const result of results) {
		assert.ok(['phishing', 'suspicious'].includes(result.type));
		assert.strictEqual(typeof result.url, 'string');
		assert.strictEqual(typeof result.description, 'string');
	}
});

// Test: getExecutableResults returns ExecutableResult array
test('getExecutableResults returns ExecutableResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {
		attachments: [
			{filename: 'test.exe', contentType: 'application/octet-stream'},
			{filename: 'document.pdf', contentType: 'application/pdf'},
		],
	};
	const results = await scanner.getExecutableResults(mail);

	assert.ok(Array.isArray(results));
	for (const result of results) {
		assert.ok(['executable', 'archive'].includes(result.type));
		assert.strictEqual(typeof result.filename, 'string');
		assert.strictEqual(typeof result.description, 'string');
	}
});

// Test: getMacroResults returns MacroResult array
test('getMacroResults returns MacroResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {
		text: 'Sub AutoOpen()\nEnd Sub',
		html: '',
	};
	const results = await scanner.getMacroResults(mail);

	assert.ok(Array.isArray(results));
	for (const result of results) {
		assert.strictEqual(result.type, 'macro');
		assert.strictEqual(typeof result.subtype, 'string');
		assert.strictEqual(typeof result.description, 'string');
	}
});

// Test: getArbitraryResults returns ArbitraryResult array
test('getArbitraryResults returns ArbitraryResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const gtube = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';
	const mail = {text: gtube, html: ''};
	const results = await scanner.getArbitraryResults(mail);

	assert.ok(Array.isArray(results));
	assert.ok(results.length > 0);
	assert.strictEqual(results[0].type, 'arbitrary');
	assert.strictEqual(typeof results[0].description, 'string');
});

// Test: getVirusResults returns VirusResult array
test('getVirusResults returns VirusResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {attachments: []};
	const results = await scanner.getVirusResults(mail);

	assert.ok(Array.isArray(results));
	// Results will be empty without actual virus content
});

// Test: getPatternResults returns PatternResult array
test('getPatternResults returns PatternResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {text: 'Some text content', html: ''};
	const results = await scanner.getPatternResults(mail);

	assert.ok(Array.isArray(results));
	for (const result of results) {
		assert.ok(['pattern', 'file_path'].includes(result.type));
		assert.strictEqual(typeof result.description, 'string');
	}
});

// Test: getIDNHomographResults returns IDNHomographResult
test('getIDNHomographResults returns IDNHomographResult structure', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {
		text: 'Visit https://аpple.com', // Cyrillic 'а'
		html: '',
	};
	const result = await scanner.getIDNHomographResults(mail);

	assert.strictEqual(typeof result.detected, 'boolean');
	assert.ok(Array.isArray(result.domains));
	assert.strictEqual(typeof result.riskScore, 'number');
	assert.ok(Array.isArray(result.details));
});

// Test: getToxicityResults returns ToxicityResult array
test('getToxicityResults returns ToxicityResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {text: 'Normal text', html: ''};
	const results = await scanner.getToxicityResults(mail);

	assert.ok(Array.isArray(results));
	// Results depend on toxicity model availability
});

// Test: getNSFWResults returns NSFWResult array
test('getNSFWResults returns NSFWResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {attachments: []};
	const results = await scanner.getNSFWResults(mail);

	assert.ok(Array.isArray(results));
	// Results depend on NSFW model and image attachments
});

// Test: initializeClassifier sets classifier
test('initializeClassifier initializes the classifier', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	assert.strictEqual(scanner.classifier, null);

	await scanner.initializeClassifier();
	assert.ok(scanner.classifier !== null);
});

// Test: initializeReplacements sets replacements Map
test('initializeReplacements initializes replacements Map', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	await scanner.initializeReplacements();

	assert.ok(scanner.replacements instanceof Map);
});

// Test: extractAllUrls extracts URLs from mail and source
test('extractAllUrls extracts URLs from multiple sources', () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {
		text: 'Visit https://example.com',
		html: '<a href="https://test.org">Link</a>',
	};
	const urls = scanner.extractAllUrls(mail, 'Also check https://another.com');

	assert.ok(Array.isArray(urls));
	assert.ok(urls.length > 0);
});

// Test: isCloudflareBlocked returns boolean
test('isCloudflareBlocked returns boolean', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const result = await scanner.isCloudflareBlocked('example.com');

	assert.strictEqual(typeof result, 'boolean');
});

// Test: isValidShortTextDetection returns boolean
test('isValidShortTextDetection returns boolean', () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	assert.strictEqual(typeof scanner.isValidShortTextDetection('Hello', 'en'), 'boolean');
	assert.strictEqual(typeof scanner.isValidShortTextDetection('こんにちは', 'ja'), 'boolean');
});

// Test: getFilePathResults returns PatternResult array
test('getFilePathResults returns PatternResult array', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const mail = {
		text: 'Check file at /usr/local/bin/test.sh',
		html: '',
	};
	const results = await scanner.getFilePathResults(mail);

	assert.ok(Array.isArray(results));
	for (const result of results) {
		assert.ok(['pattern', 'file_path'].includes(result.type));
	}
});

// Test: scan with Buffer input
test('scan accepts Buffer input', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const buffer = Buffer.from('This is a test email message');
	const result = await scanner.scan(buffer);

	assert.strictEqual(typeof result.isSpam, 'boolean');
	assert.strictEqual(typeof result.message, 'string');
});

// Test: custom logger configuration
test('SpamScanner accepts custom logger', () => {
	const logs = [];
	const customLogger = {
		log: (...args) => logs.push(['log', ...args]),
		error: (...args) => logs.push(['error', ...args]),
		warn: (...args) => logs.push(['warn', ...args]),
		info: (...args) => logs.push(['info', ...args]),
		debug: (...args) => logs.push(['debug', ...args]),
	};

	const scanner = new SpamScanner({logger: customLogger, supportedLanguages: []});
	assert.strictEqual(scanner.config.logger, customLogger);
});

// Test: default config values
test('SpamScanner has correct default config values', () => {
	const scanner = new SpamScanner();

	assert.strictEqual(scanner.config.enableMacroDetection, true);
	assert.strictEqual(scanner.config.enablePerformanceMetrics, false);
	assert.strictEqual(scanner.config.timeout, 30_000);
	assert.strictEqual(scanner.config.enableMixedLanguageDetection, false);
	assert.strictEqual(scanner.config.enableAdvancedPatternRecognition, true);
	assert.strictEqual(scanner.config.debug, false);
});

// Test: getIDNDetector returns detector or null
test('getIDNDetector returns EnhancedIDNDetector or null', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});
	const detector = await scanner.getIDNDetector();

	// Detector may be null if module fails to load
	if (detector !== null) {
		assert.strictEqual(typeof detector.detectHomographAttack, 'function');
		assert.strictEqual(typeof detector.isIDNDomain, 'function');
	}
});
