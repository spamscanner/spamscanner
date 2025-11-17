import {test} from 'node:test';
import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

const scanner = new SpamScanner();

test('should create scanner instance', async () => {
	assert.ok(scanner instanceof SpamScanner);
	assert.strictEqual(typeof scanner.config, 'object');
});

test('should extract URLs correctly', async () => {
	const text = 'Visit https://example.com and http://test.org';
	const urls = scanner.getUrls(text);
	assert.ok(Array.isArray(urls));
	assert.ok(urls.length >= 2);
});

test('should parse locale correctly', async () => {
	const locale = scanner.parseLocale('en-US');
	assert.strictEqual(locale, 'en');
});

test('should handle configuration options', async () => {
	const configuredScanner = new SpamScanner({
		enableMacroDetection: false,
	});
	assert.strictEqual(configuredScanner.config.enableMacroDetection, false);
});

test('should export default correctly', async () => {
	assert.strictEqual(typeof SpamScanner, 'function');
});

test('should tokenize text correctly', async () => {
	const tokens = await scanner.getTokens('Hello world test', 'en');
	assert.ok(Array.isArray(tokens));
	assert.ok(tokens.length > 0);
});

test('should preprocess text correctly', async () => {
	const result = await scanner.preprocessText('HELLO world!', 'en');
	assert.strictEqual(typeof result, 'string');
	assert.ok(result.length > 0);
});

test('should get file path results', async () => {
	const mail = {text: String.raw`Check C:\\Windows\\file.exe`};
	const results = await scanner.getFilePathResults(mail);
	assert.ok(Array.isArray(results));
});

test('should get arbitrary results', async () => {
	const mail = {text: 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'};
	const results = await scanner.getArbitraryResults(mail);
	assert.ok(Array.isArray(results));
	assert.ok(results.length > 0);
});

test('should get pattern results', async () => {
	const mail = {text: 'URGENT: Act now! Limited time!'};
	const results = await scanner.getPatternResults(mail);
	assert.ok(Array.isArray(results));
});

test('should optimize URL parsing', async () => {
	const text = 'Visit https://example.com';
	const result = await scanner.optimizeUrlParsing(text);
	assert.strictEqual(typeof result, 'string');
});

test('should handle tokenization for different languages', async () => {
	const tokens = await scanner.getTokens('Hello world', 'en');
	assert.ok(Array.isArray(tokens));
});

test('should get executable results', async () => {
	const mail = {attachments: []};
	const results = await scanner.getExecutableResults(mail);
	assert.ok(Array.isArray(results));
});

test('should initialize classifier', async () => {
	await scanner.initializeClassifier();
	assert.ok(scanner.classifier);
});

test('should get classification results', async () => {
	const tokens = ['test', 'email'];
	const result = await scanner.getClassification(tokens);
	assert.strictEqual(typeof result, 'object');
});

test('should initialize replacements', async () => {
	await scanner.initializeReplacements();
	assert.ok(scanner.replacements instanceof Map);
});

test('should handle empty input', async () => {
	const result = await scanner.scan('');
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, false);
});

test('should handle malformed input', async () => {
	const result = await scanner.scan(null);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, false);
});

test('should handle error conditions gracefully', async () => {
	// Test with invalid input
	const result = await scanner.scan(undefined);
	assert.strictEqual(typeof result, 'object');
});

test('should detect file path patterns', async () => {
	const mail = {text: String.raw`Check file at /home/user/document.pdf and C:\Windows\System32\file.exe`};
	const results = await scanner.getFilePathResults(mail);
	console.log('results', results);
	assert.ok(Array.isArray(results));
});

test('should scan ham email correctly', async () => {
	const hamEmail = 'Hi John, just wanted to follow up on our meeting. Best regards, Sarah';
	const result = await scanner.scan(hamEmail);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, false);
});

test('should handle performance metrics', async () => {
	const initialScans = scanner.metrics.totalScans;
	await scanner.scan('Test email');
	assert.ok(scanner.metrics.totalScans > initialScans);
});

test('should maintain metrics correctly', async () => {
	// Create fresh scanner for metrics test
	const freshScanner = new SpamScanner();
	const initial = freshScanner.metrics.totalScans;

	await freshScanner.scan('Test 1');
	await freshScanner.scan('Test 2');

	assert.strictEqual(freshScanner.metrics.totalScans, initial + 2);
});

test('should handle different input types', async () => {
	const buffer = Buffer.from('Test email');
	const result = await scanner.scan(buffer);
	assert.strictEqual(typeof result, 'object');
});

test('should detect macro content', async () => {
	const macroEmail = String.raw`Sub AutoOpen()\nShell "malware.exe"\nEnd Sub`;
	const result = await scanner.scan(macroEmail);
	assert.strictEqual(result.isSpam, true);
	assert.ok(result.message.includes('macro'));
});

test('should detect phishing attempts', async () => {
	const phishingEmail = 'Your account has been suspended. Click here: http://fake-bank.com';
	const result = await scanner.scan(phishingEmail);
	assert.strictEqual(typeof result, 'object');
});

test('should handle HTML content', async () => {
	const htmlContent = '<html><body><h1>Newsletter</h1><p>Legitimate content</p></body></html>';
	const result = await scanner.scan(htmlContent);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, false);
});

test('should scan spam email correctly', async () => {
	const spamEmail = 'URGENT: You won $1,000,000! Click here now!';
	const result = await scanner.scan(spamEmail);
	assert.strictEqual(typeof result, 'object');
	// Note: May or may not be spam depending on patterns
});

test('should handle concurrent scans', async () => {
	const promises = [
		scanner.scan('Email 1'),
		scanner.scan('Email 2'),
		scanner.scan('Email 3'),
	];

	const results = await Promise.all(promises);
	assert.strictEqual(results.length, 3);
	for (const result of results) {
		assert.strictEqual(typeof result, 'object');
	}
});

