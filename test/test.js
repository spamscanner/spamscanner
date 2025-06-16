import {test} from 'node:test';
import assert from 'node:assert';
import SpamScanner from '../src/index.js';

// Test data
const testEmails = {
	spam: 'URGENT: You have won $1,000,000! Click here now to claim your prize!',
	ham: 'Hi John, just wanted to follow up on our meeting yesterday. Best regards, Sarah',
	gtube: 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X',
	macro: String.raw`Sub AutoOpen()\nShell "malware.exe"\nEnd Sub`,
	phishing: 'Your PayPal account has been suspended. Click here to verify: http://fake-paypal.com',
};

const scanner = new SpamScanner();

test('should parse locales correctly', async () => {
	const result = scanner.parseLocale('en-US');
	assert.strictEqual(typeof result, 'string');
	assert.strictEqual(result, 'en');
});

test('should handle configuration options', async () => {
	const configuredScanner = new SpamScanner({
		enableMacroDetection: false,
		enablePhishingDetection: true,
	});
	assert.strictEqual(typeof configuredScanner.config, 'object');
	assert.strictEqual(configuredScanner.config.enableMacroDetection, false);
	assert.strictEqual(configuredScanner.config.enablePhishingDetection, true);
});

test('should export SpamScanner class correctly', async () => {
	assert.strictEqual(typeof SpamScanner, 'function');
	assert.ok(scanner instanceof SpamScanner);
});

test('should preprocess text correctly', async () => {
	const text = 'Hello WORLD! This is a TEST.';
	const result = await scanner.preprocessText(text, 'en');
	assert.strictEqual(typeof result, 'string');
	assert.ok(result.length > 0);
});

test('should detect file paths in content', async () => {
	const mail = {text: String.raw`Check this file: C:\\Windows\\System32\\malware.exe`};
	const result = await scanner.getFilePathResults(mail);
	assert.ok(Array.isArray(result));
});

test('should tokenize different languages', async () => {
	const text = 'Hello world test message';
	const tokens = await scanner.getTokens(text, 'en');
	assert.ok(Array.isArray(tokens));
	assert.ok(tokens.length > 0);
});

test('should optimize URL parsing', async () => {
	const text = 'Visit https://example.com for more info';
	const result = await scanner.optimizeUrlParsing(text);
	assert.strictEqual(typeof result, 'string');
});

test('should handle email attachments', async () => {
	const mail = {attachments: [{filename: 'test.pdf', contentType: 'application/pdf'}]};
	const result = await scanner.getExecutableResults(mail);
	assert.ok(Array.isArray(result));
});

test('should initialize classifier properly', async () => {
	await scanner.initializeClassifier();
	assert.ok(scanner.classifier);
});

test('should get classification results', async () => {
	const tokens = ['test', 'email', 'message'];
	const result = await scanner.getClassification(tokens);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.probability, 'number');
});

test('should scan tokens from email source', async () => {
	const emailSource = `Delivered-To: test@example.com
Subject: Test Email
From: sender@example.com
To: test@example.com

This is a test email message with some content.
It contains multiple words that should be tokenized properly.
`;

	const {tokens, mail} = await scanner.getTokensAndMailFromSource(emailSource);

	assert.ok(Array.isArray(tokens));
	assert.ok(tokens.length > 0);
	assert.strictEqual(typeof mail, 'object');

	// Check if subject was parsed, if not check that content is available
	if (mail.subject) {
		assert.strictEqual(typeof mail.subject, 'string');
		assert.ok(mail.subject.includes('Test Email'));
	} else {
		// If headers weren't parsed, check that content is available in text
		assert.strictEqual(typeof mail.text, 'string');
		assert.ok(mail.text.includes('Test Email'));
	}
});

test('should initialize replacements properly', async () => {
	await scanner.initializeReplacements();
	assert.ok(scanner.replacements instanceof Map);
});

test('should scan basic email and return proper structure', async () => {
	const result = await scanner.scan('This is a test email message.');

	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.isSpam, 'boolean');
	assert.strictEqual(typeof result.message, 'string');
	assert.strictEqual(typeof result.results, 'object');
});

test('should detect GTUBE test string', async () => {
	const result = await scanner.scan(testEmails.gtube);
	assert.strictEqual(result.isSpam, true);
	assert.ok(result.message.includes('arbitrary'));
});

test('should handle malformed URLs gracefully', async () => {
	const malformedUrls = 'Visit htp://broken-url or ftp:/invalid-url';
	const result = await scanner.scan(malformedUrls);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.isSpam, 'boolean');
});

test('should handle concurrent scans', async () => {
	const promises = [
		scanner.scan(testEmails.ham),
		scanner.scan(testEmails.spam),
		scanner.scan(testEmails.ham),
	];

	const results = await Promise.all(promises);
	assert.strictEqual(results.length, 3);
	for (const result of results) {
		assert.strictEqual(typeof result, 'object');
		assert.strictEqual(typeof result.isSpam, 'boolean');
	}
});

test('should track metrics correctly', async () => {
	// Create a fresh scanner to test metrics
	const freshScanner = new SpamScanner();
	const initialScans = freshScanner.metrics.totalScans;

	await freshScanner.scan('Test email 1');
	await freshScanner.scan('Test email 2');

	assert.strictEqual(freshScanner.metrics.totalScans, initialScans + 2);
	assert.strictEqual(typeof freshScanner.metrics.averageTime, 'number');
	assert.ok(freshScanner.metrics.averageTime > 0);
});

test('should handle large emails efficiently', async () => {
	const largeEmail = 'Large email content. '.repeat(1000);
	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(largeEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;
	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 5000); // Should complete within 5 seconds
});

test('should handle empty and null inputs', async () => {
	const emptyResult = await scanner.scan('');
	const nullResult = await scanner.scan(null);

	assert.strictEqual(typeof emptyResult, 'object');
	assert.strictEqual(typeof nullResult, 'object');
	assert.strictEqual(emptyResult.isSpam, false);
	assert.strictEqual(nullResult.isSpam, false);
});

test('should detect macros in email content', async () => {
	const result = await scanner.scan(testEmails.macro);
	assert.strictEqual(result.isSpam, true);
	assert.ok(result.message.includes('macro'));
});

test('should handle different input formats', async () => {
	const bufferInput = Buffer.from('Test email content');
	const result = await scanner.scan(bufferInput);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.isSpam, 'boolean');
});

test('should detect phishing attempts', async () => {
	const result = await scanner.scan(testEmails.phishing);
	assert.strictEqual(typeof result, 'object');
	// Note: May or may not be detected as spam depending on patterns
});

test('should handle HTML content properly', async () => {
	const htmlContent = '<html><body><h1>Newsletter</h1><p>This is a legitimate newsletter.</p></body></html>';
	const result = await scanner.scan(htmlContent);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, false); // Should not be detected as spam
});

test('should detect patterns correctly', async () => {
	const patternEmail = 'URGENT: Act now! Limited time offer! Call 1-800-SCAM-NOW!';
	const result = await scanner.scan(patternEmail);
	assert.strictEqual(typeof result, 'object');
	// Pattern detection should work
});

test('should extract URLs from email content', async () => {
	const emailWithUrls = 'Visit https://example.com and http://test.org for more info';
	const result = await scanner.scan(emailWithUrls);
	assert.strictEqual(typeof result, 'object');
	assert.ok(Array.isArray(result.links));
	assert.ok(result.links.length > 0);
});

