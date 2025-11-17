import {test} from 'node:test';
import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

// Modern test suite for the updated SpamScanner
const scanner = new SpamScanner({
	enableMacroDetection: true,
	enableMalwareUrlCheck: true,
	enablePerformanceMetrics: true,
	enableAdvancedPatternRecognition: true,
});

test('should scan basic email', async () => {
	const result = await scanner.scan('This is a normal email message.');

	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.isSpam, 'boolean');
	assert.strictEqual(typeof result.message, 'string');
	assert.strictEqual(typeof result.results, 'object');
	assert.ok(Array.isArray(result.tokens));
	assert.ok(Array.isArray(result.links));
	assert.strictEqual(typeof result.mail, 'object');
});

test('should detect GTUBE test string', async () => {
	const gtubeEmail = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';
	const result = await scanner.scan(gtubeEmail);

	assert.ok(result.isSpam);
	assert.ok(result.message.includes('arbitrary') || result.message.includes('Spam'));
});

test('should extract URLs from email content', async () => {
	const emailWithUrls = 'Visit https://example.com and http://test.org for more info.';
	const result = await scanner.scan(emailWithUrls);

	assert.ok(Array.isArray(result.links));
	assert.ok(result.links.length > 0);
	assert.ok(result.links.some(url => url.includes('example.com')));
});

test('should handle malformed URLs gracefully', async () => {
	const emailWithBadUrls = 'Visit htp://bad-url and invalid://test for info';
	const result = await scanner.scan(emailWithBadUrls);

	assert.strictEqual(typeof result, 'object');
	assert.ok(!result.isSpam); // Malformed URLs shouldn't trigger spam detection
});

test('should tokenize text properly', async () => {
	const tokens = await scanner.getTokens('Hello world! This is a test message.');

	assert.ok(Array.isArray(tokens));
	assert.ok(tokens.length > 0);
});

test('should preprocess text', async () => {
	const processed = await scanner.preprocessText('Hello WORLD! Test message.');

	assert.strictEqual(typeof processed, 'string');
	assert.ok(processed.length > 0);
});

test('should parse locales', _t => {
	assert.strictEqual(scanner.parseLocale('en-US'), 'en');
	assert.strictEqual(scanner.parseLocale('fr-FR'), 'fr');
	assert.strictEqual(scanner.parseLocale(null), 'en');
});

test('should handle email attachments', async () => {
	const mail = {
		text: 'Please find attached.',
		html: '',
		subject: 'Attachment',
		attachments: [
			{
				filename: 'script.exe',
				content: Buffer.from('test'),
			},
		],
	};

	const result = await scanner.getExecutableResults(mail);
	assert.ok(Array.isArray(result));
	assert.ok(result.some(item => item.filename === 'script.exe'));
});

test('should detect macros in attachments', async () => {
	const macroEmail = String.raw`Sub AutoOpen()\nShell "cmd.exe"\nEnd Sub`;
	const result = await scanner.scan(macroEmail);

	// Should detect macro patterns
	assert.ok(Array.isArray(result.results.macros));
});

test('should handle empty input', async () => {
	const result = await scanner.scan('');

	assert.strictEqual(typeof result, 'object');
	assert.ok(!result.isSpam);
});

test('should handle null input', async () => {
	const result = await scanner.scan(null);

	assert.strictEqual(typeof result, 'object');
	assert.ok(!result.isSpam);
});

test('should initialize components', async () => {
	await scanner.initializeClassifier();
	await scanner.initializeReplacements();

	assert.ok(scanner.classifier);
	assert.ok(scanner.replacements);
});

test('should get classification', async () => {
	const classification = await scanner.getClassification(['test', 'tokens']);

	assert.strictEqual(typeof classification, 'object');
	assert.strictEqual(typeof classification.category, 'string');
	assert.strictEqual(typeof classification.probability, 'number');
});

test('should detect file paths', async () => {
	const mail = {
		text: String.raw`Check C:\\Windows\\System32\\file.exe`,
		html: '',
		subject: 'Test',
	};

	const result = await scanner.getFilePathResults(mail);
	assert.ok(Array.isArray(result));
});

test('should handle concurrent scans', async () => {
	const promises = [
		scanner.scan('Normal email'),
		scanner.scan('XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'),
		scanner.scan(String.raw`Sub AutoOpen()\nEnd Sub`),
	];

	const results = await Promise.all(promises);

	assert.strictEqual(results.length, 3);
	for (const result of results) {
		assert.strictEqual(typeof result, 'object');
		assert.strictEqual(typeof result.isSpam, 'boolean');
	}
});

test('should track metrics', async () => {
	const initialScans = scanner.metrics.totalScans;
	await scanner.scan('Test for metrics');

	assert.strictEqual(scanner.metrics.totalScans, initialScans + 1);
	assert.strictEqual(typeof scanner.metrics.lastScanTime, 'number');
});

test('should handle configuration', _t => {
	const customScanner = new SpamScanner({
		enableMacroDetection: false,
		timeout: 5000,
	});

	assert.ok(!customScanner.config.enableMacroDetection);
	assert.strictEqual(customScanner.config.timeout, 5000);
});

test('should optimize URL parsing', async () => {
	const url = 'https://example.com/path';
	const optimized = await scanner.optimizeUrlParsing(url);

	assert.strictEqual(typeof optimized, 'string');
	assert.ok(optimized.includes('example.com'));
});

test('should handle different input types', async () => {
	const stringResult = await scanner.scan('String input');
	const bufferResult = await scanner.scan(Buffer.from('Buffer input'));

	assert.strictEqual(typeof stringResult, 'object');
	assert.strictEqual(typeof bufferResult, 'object');
});

test('should detect patterns', async () => {
	const patternEmail = 'Call 123-456-7890 or email test@example.com';
	const result = await scanner.scan(patternEmail);

	assert.ok(Array.isArray(result.results.patterns));
});

test('should handle HTML content', async () => {
	const htmlEmail = '<html><body><h1>Test</h1><p>Content</p></body></html>';
	const result = await scanner.scan(htmlEmail);

	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.isSpam, 'boolean');
});

test('should export correctly', _t => {
	assert.strictEqual(typeof SpamScanner, 'function');
	assert.strictEqual(SpamScanner.name, 'SpamScanner');
});

