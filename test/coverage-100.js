import {test} from 'node:test';
import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

// Test to achieve 100% code coverage

test('should handle NSFW detection with actual image buffer', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// Create a minimal valid PNG image (1x1 pixel, red)
	const pngBuffer = Buffer.from([
		0x89,
		0x50,
		0x4E,
		0x47,
		0x0D,
		0x0A,
		0x1A,
		0x0A, // PNG signature
		0x00,
		0x00,
		0x00,
		0x0D,
		0x49,
		0x48,
		0x44,
		0x52, // IHDR chunk
		0x00,
		0x00,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x01, // 1x1 dimensions
		0x08,
		0x02,
		0x00,
		0x00,
		0x00,
		0x90,
		0x77,
		0x53,
		0xDE,
		0x00,
		0x00,
		0x00,
		0x0C,
		0x49,
		0x44,
		0x41, // IDAT chunk
		0x54,
		0x08,
		0xD7,
		0x63,
		0xF8,
		0xCF,
		0xC0,
		0x00,
		0x00,
		0x03,
		0x01,
		0x01,
		0x00,
		0x18,
		0xDD,
		0x8D,
		0xB4,
		0x00,
		0x00,
		0x00,
		0x00,
		0x49,
		0x45,
		0x4E, // IEND chunk
		0x44,
		0xAE,
		0x42,
		0x60,
		0x82,
	]);

	const emailWithImage = {
		text: 'Test email with image',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.png',
				content: pngBuffer,
			},
		],
	};

	const results = await scanner.getNSFWResults(emailWithImage);
	assert.ok(Array.isArray(results), 'Should return array of results');
	// Note: Results may be empty if image is classified as neutral
});

test('should handle NSFW detection with invalid image buffer', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	const emailWithInvalidImage = {
		text: 'Test email',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.png',
				content: Buffer.from('invalid image data'),
			},
		],
	};

	// Should not throw, should handle error gracefully
	const results = await scanner.getNSFWResults(emailWithInvalidImage);
	assert.ok(Array.isArray(results), 'Should return array even with invalid image');
});

test('should handle toxicity detection with various content', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.5});

	const toxicEmail = {
		text: 'You are an idiot and I hate you!',
		subject: 'Insult',
		html: '<p>You are an idiot and I hate you!</p>',
		attachments: [],
	};

	const results = await scanner.getToxicityResults(toxicEmail);
	assert.ok(Array.isArray(results), 'Should return array of results');
});

test('should handle toxicity detection with empty content', async () => {
	const scanner = new SpamScanner();

	const emptyEmail = {
		text: '',
		subject: '',
		html: '',
		attachments: [],
	};

	const results = await scanner.getToxicityResults(emptyEmail);
	assert.ok(Array.isArray(results), 'Should return empty array for empty content');
	assert.strictEqual(results.length, 0, 'Should have no results for empty content');
});

test('should handle toxicity detection with very short content', async () => {
	const scanner = new SpamScanner();

	const shortEmail = {
		text: 'Hi',
		subject: 'Hi',
		html: '',
		attachments: [],
	};

	const results = await scanner.getToxicityResults(shortEmail);
	assert.ok(Array.isArray(results), 'Should return array');
	assert.strictEqual(results.length, 0, 'Should have no toxicity in short greeting');
});

test('should handle NSFW detection with attachment without content', async () => {
	const scanner = new SpamScanner();

	const emailWithEmptyAttachment = {
		text: 'Test',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.txt',
				// No content field
			},
		],
	};

	const results = await scanner.getNSFWResults(emailWithEmptyAttachment);
	assert.ok(Array.isArray(results), 'Should return array');
	assert.strictEqual(results.length, 0, 'Should skip attachments without content');
});

test('should handle NSFW detection with non-buffer content', async () => {
	const scanner = new SpamScanner();

	const emailWithNonBuffer = {
		text: 'Test',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.txt',
				content: 'string content instead of buffer',
			},
		],
	};

	const results = await scanner.getNSFWResults(emailWithNonBuffer);
	assert.ok(Array.isArray(results), 'Should return array');
	assert.strictEqual(results.length, 0, 'Should skip non-buffer attachments');
});

test('should handle scan with all detection methods enabled', async () => {
	const scanner = new SpamScanner({
		enableToxicityDetection: true,
		enableNSFWDetection: true,
		toxicityThreshold: 0.7,
		nsfwThreshold: 0.6,
	});

	const email = 'This is a test email with normal content.';
	const result = await scanner.scan(email);

	assert.ok(result.results, 'Should have results object');
	assert.ok(Array.isArray(result.results.toxicity), 'Should have toxicity array');
	assert.ok(Array.isArray(result.results.nsfw), 'Should have nsfw array');
	assert.ok(result.results.idnHomographAttack, 'Should have IDN results');
});

test('should handle IDN detector edge cases', async () => {
	const scanner = new SpamScanner();
	const idnDetector = await scanner.getIDNDetector();

	// Test with domain containing null bytes
	const result1 = idnDetector.detectHomographAttack('test\u0000.com', {});
	assert.ok(result1, 'Should handle null bytes in domain');

	// Test with very long domain
	const longDomain = 'a'.repeat(300) + '.com';
	const result2 = idnDetector.detectHomographAttack(longDomain, {});
	assert.ok(result2, 'Should handle very long domains');

	// Test with mixed scripts
	const mixedScript = 'раypal.com'; // Cyrillic and Latin
	const result3 = idnDetector.detectHomographAttack(mixedScript, {});
	assert.ok(result3.riskScore > 0, 'Should detect mixed script domain');
});

test('should handle confusables normalization edge cases', async () => {
	const scanner = new SpamScanner();
	const idnDetector = await scanner.getIDNDetector();

	// Test with domain that has no confusables
	const normalDomain = 'example.com';
	const result1 = idnDetector.detectHomographAttack(normalDomain, {});
	assert.ok(result1, 'Should handle normal domains');

	// Test with punycode domain
	const punycodeDomain = 'xn--e1afmkfd.xn--p1ai';
	const result2 = idnDetector.detectHomographAttack(punycodeDomain, {});
	assert.ok(result2, 'Should handle punycode domains');
});

test('should handle tldts parsing edge cases', async () => {
	const scanner = new SpamScanner();

	// Test with invalid URL
	const result1 = scanner.parseUrlWithTldts('not a valid url');
	assert.ok(result1, 'Should handle invalid URLs gracefully');

	// Test with URL without protocol
	const result2 = scanner.parseUrlWithTldts('example.com');
	assert.ok(result2, 'Should handle URLs without protocol');

	// Test with localhost
	const result3 = scanner.parseUrlWithTldts('http://localhost:8080');
	assert.ok(result3, 'Should handle localhost');

	// Test with IP address
	const result4 = scanner.parseUrlWithTldts('http://127.0.0.1');
	assert.ok(result4, 'Should handle IP addresses');
	assert.strictEqual(result4.isIp, true, 'Should detect IP address');
});

test('should handle get-classifier edge cases', async () => {
	const scanner = new SpamScanner();

	// Initialize classifier
	await scanner.initializeClassifier();
	assert.ok(scanner.classifier, 'Classifier should be initialized');

	// Test classification with empty tokens
	const result1 = await scanner.getClassification([]);
	assert.ok(result1, 'Should handle empty tokens');

	// Test classification with single token
	const result2 = await scanner.getClassification(['test']);
	assert.ok(result2, 'Should handle single token');
});

test('should handle error in toxicity detection timeout', async () => {
	const scanner = new SpamScanner({
		toxicityThreshold: 0.7,
		timeout: 1, // Very short timeout to trigger timeout error
	});

	const longEmail = {
		text: 'This is a test email. '.repeat(100),
		subject: 'Test',
		html: '',
		attachments: [],
	};

	// Should handle timeout gracefully
	const results = await scanner.getToxicityResults(longEmail);
	assert.ok(Array.isArray(results), 'Should return array even on timeout');
});

test('should handle NSFW detection with JPEG image', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// Minimal valid JPEG (1x1 pixel)
	const jpegBuffer = Buffer.from([
		0xFF,
		0xD8,
		0xFF,
		0xE0,
		0x00,
		0x10,
		0x4A,
		0x46,
		0x49,
		0x46,
		0x00,
		0x01,
		0x01,
		0x00,
		0x00,
		0x01,
		0x00,
		0x01,
		0x00,
		0x00,
		0xFF,
		0xDB,
		0x00,
		0x43,
		0x00,
		0x08,
		0x06,
		0x06,
		0x07,
		0x06,
		0x05,
		0x08,
		0x07,
		0x07,
		0x07,
		0x09,
		0x09,
		0x08,
		0x0A,
		0x0C,
		0x14,
		0x0D,
		0x0C,
		0x0B,
		0x0B,
		0x0C,
		0x19,
		0x12,
		0x13,
		0x0F,
		0x14,
		0x1D,
		0x1A,
		0x1F,
		0x1E,
		0x1D,
		0x1A,
		0x1C,
		0x1C,
		0x20,
		0x24,
		0x2E,
		0x27,
		0x20,
		0x22,
		0x2C,
		0x23,
		0x1C,
		0x1C,
		0x28,
		0x37,
		0x29,
		0x2C,
		0x30,
		0x31,
		0x34,
		0x34,
		0x34,
		0x1F,
		0x27,
		0x39,
		0x3D,
		0x38,
		0x32,
		0x3C,
		0x2E,
		0x33,
		0x34,
		0x32,
		0xFF,
		0xC0,
		0x00,
		0x0B,
		0x08,
		0x00,
		0x01,
		0x00,
		0x01,
		0x01,
		0x01,
		0x11,
		0x00,
		0xFF,
		0xC4,
		0x00,
		0x14,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x03,
		0xFF,
		0xC4,
		0x00,
		0x14,
		0x10,
		0x01,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0xFF,
		0xDA,
		0x00,
		0x08,
		0x01,
		0x01,
		0x00,
		0x00,
		0x3F,
		0x00,
		0x37,
		0xFF,
		0xD9,
	]);

	const emailWithJpeg = {
		text: 'Test email with JPEG',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.jpg',
				content: jpegBuffer,
			},
		],
	};

	const results = await scanner.getNSFWResults(emailWithJpeg);
	assert.ok(Array.isArray(results), 'Should handle JPEG images');
});
