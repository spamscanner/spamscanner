/* eslint-disable no-await-in-loop */
import {test} from 'node:test';
import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

// Tests specifically designed to cover error paths and TensorFlow operations

test('should cover franc error path with extremely large text', async () => {
	const scanner = new SpamScanner();

	// Create text that might cause franc to have issues
	// Very large text with mixed content
	const largeText = 'a'.repeat(100_000) + '\n' + 'test '.repeat(10_000);

	const result = await scanner.detectLanguageHybrid(largeText);
	assert.ok(result, 'Should handle very large text');
	assert.strictEqual(typeof result, 'string', 'Should return language code');
});

test('should cover lande fallback when franc returns und', async () => {
	const scanner = new SpamScanner();

	// Text that franc might not recognize
	const ambiguousTexts = [
		'123456789',
		'!@#$%^&*()',
		'...........',
		'----------',
		'==========',
	];

	for (const text of ambiguousTexts) {
		const result = await scanner.detectLanguageHybrid(text);
		assert.strictEqual(result, 'en', 'Should fallback to en for ambiguous text');
	}
});

test('should cover both franc and lande failing with null bytes', async () => {
	const scanner = new SpamScanner();

	// Text with null bytes and control characters that might break parsers
	const problematicTexts = [
		'\u0000\u0000\u0000',
		'\uFFFD\uFFFD\uFFFD',
		String.fromCodePoint(0, 0, 0),
		'\u0000test\u0000',
	];

	for (const text of problematicTexts) {
		const result = await scanner.detectLanguageHybrid(text);
		assert.strictEqual(result, 'en', 'Should fallback to en for problematic text');
	}
});

test('should execute NSFW tensor operations with actual PNG image', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// Create a larger, more realistic PNG image (10x10 red square)
	const pngBuffer = Buffer.from([
		// PNG signature
		0x89,
		0x50,
		0x4E,
		0x47,
		0x0D,
		0x0A,
		0x1A,
		0x0A,
		// IHDR chunk
		0x00,
		0x00,
		0x00,
		0x0D,
		0x49,
		0x48,
		0x44,
		0x52,
		0x00,
		0x00,
		0x00,
		0x0A,
		0x00,
		0x00,
		0x00,
		0x0A, // 10x10 dimensions
		0x08,
		0x02,
		0x00,
		0x00,
		0x00,
		0x02,
		0x50,
		0x58,
		0xEA,
		// IDAT chunk (compressed image data)
		0x00,
		0x00,
		0x00,
		0x26,
		0x49,
		0x44,
		0x41,
		0x54,
		0x78,
		0x9C,
		0x63,
		0xFC,
		0xCF,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0xC0,
		0x00,
		0x00,
		0x0F,
		0x00,
		0x03,
		0x01,
		0x8C,
		0x4D,
		0x5C,
		0x2F,
		// IEND chunk
		0x00,
		0x00,
		0x00,
		0x00,
		0x49,
		0x45,
		0x4E,
		0x44,
		0xAE,
		0x42,
		0x60,
		0x82,
	]);

	const mail = {
		text: 'Email with image',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.png',
				content: pngBuffer,
			},
		],
	};

	// This should execute the full tensor operation path
	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should return results array');

	// Call again to test cached model path
	const results2 = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results2), 'Should work with cached model');
});

test('should execute NSFW tensor operations with JPEG image', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// Minimal valid JPEG (1x1 pixel, red)
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

	const mail = {
		text: 'Email with JPEG',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'photo.jpg',
				content: jpegBuffer,
			},
		],
	};

	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should process JPEG images');
});

test('should execute NSFW tensor operations with multiple images', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	const pngBuffer = Buffer.from([
		0x89,
		0x50,
		0x4E,
		0x47,
		0x0D,
		0x0A,
		0x1A,
		0x0A,
		0x00,
		0x00,
		0x00,
		0x0D,
		0x49,
		0x48,
		0x44,
		0x52,
		0x00,
		0x00,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x01,
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
		0x41,
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
		0x4E,
		0x44,
		0xAE,
		0x42,
		0x60,
		0x82,
	]);

	const mail = {
		text: 'Multiple images',
		subject: 'Test',
		html: '',
		attachments: [
			{filename: 'image1.png', content: pngBuffer},
			{filename: 'image2.png', content: pngBuffer},
			{filename: 'image3.png', content: pngBuffer},
		],
	};

	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should process multiple images');
});

test('should cover NSFW error path with corrupted image', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// Corrupted PNG header
	const corruptedBuffer = Buffer.from([
		0x89,
		0x50,
		0x4E,
		0x47,
		0x00,
		0x00,
		0x00,
		0x00, // Corrupted
		0x00,
		0x00,
		0x00,
		0x00,
	]);

	const mail = {
		text: 'Test',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'corrupted.png',
				content: corruptedBuffer,
			},
		],
	};

	// Should handle error gracefully (line 1544-1546)
	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should handle corrupted images');
});

test('should cover NSFW error path with invalid buffer', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	const mail = {
		text: 'Test',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.png',
				content: 'not a buffer', // String instead of buffer
			},
		],
	};

	// Should skip non-buffer attachments (line 1493-1495)
	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should skip non-buffer content');
	assert.strictEqual(results.length, 0, 'Should have no results for non-buffer');
});

test('should cover NSFW error path with non-image file', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	const mail = {
		text: 'Test',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'document.pdf',
				content: Buffer.from('PDF content here'),
			},
		],
	};

	// Should skip non-image files (line 1499-1501)
	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should skip non-image files');
});

test('should execute toxicity detection with actual content', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.7});

	const mail = {
		text: 'You are a terrible person and I hate you!',
		subject: 'Angry message',
		html: '<p>You are a terrible person and I hate you!</p>',
	};

	// This should execute the full toxicity detection path
	const results = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results), 'Should return results');

	// Call again to test cached model
	const results2 = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results2), 'Should work with cached model');
});

test('should cover toxicity detection with subject only', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.7});

	const mail = {
		text: '',
		subject: 'You are stupid!',
		html: '',
	};

	const results = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results), 'Should analyze subject');
});

test('should cover toxicity detection with HTML only', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.7});

	const mail = {
		text: '',
		subject: '',
		html: '<html><body><p>You are an idiot!</p></body></html>',
	};

	const results = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results), 'Should analyze HTML');
});

test('should cover toxicity detection with content at 5000 char limit', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.7});

	// Create text close to 5000 characters
	const longText = 'This is a test message. '.repeat(208);
	assert.ok(longText.length > 4000, 'Should be long text');

	const mail = {
		text: longText,
		subject: 'Long message',
		html: '',
	};

	const results = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results), 'Should handle long text');
});

test('should cover toxicity detection with content over 5000 chars', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.7});

	// Over 5000 characters (should be truncated)
	const veryLongText = 'This is a test message. '.repeat(250);
	assert.ok(veryLongText.length > 5000, 'Should be over 5000 chars');

	const mail = {
		text: veryLongText,
		subject: 'Very long message',
		html: '',
	};

	const results = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results), 'Should handle truncation');
});

test('should cover full scan with both toxicity and NSFW enabled', async () => {
	const scanner = new SpamScanner({
		enableToxicityDetection: true,
		enableNSFWDetection: true,
		toxicityThreshold: 0.7,
		nsfwThreshold: 0.6,
	});

	const pngBuffer = Buffer.from([
		0x89,
		0x50,
		0x4E,
		0x47,
		0x0D,
		0x0A,
		0x1A,
		0x0A,
		0x00,
		0x00,
		0x00,
		0x0D,
		0x49,
		0x48,
		0x44,
		0x52,
		0x00,
		0x00,
		0x00,
		0x01,
		0x00,
		0x00,
		0x00,
		0x01,
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
		0x41,
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
		0x4E,
		0x44,
		0xAE,
		0x42,
		0x60,
		0x82,
	]);

	const email = {
		text: 'You are terrible! Click here: https://example.com',
		subject: 'Spam message',
		html: '<p>You are terrible!</p>',
		attachments: [
			{
				filename: 'image.png',
				content: pngBuffer,
			},
		],
	};

	const result = await scanner.scan(email);
	assert.ok(result, 'Should return result');
	assert.ok(result.results, 'Should have results');
	assert.ok(Array.isArray(result.results.toxicity), 'Should have toxicity results');
	assert.ok(Array.isArray(result.results.nsfw), 'Should have NSFW results');
});

test('should cover language detection with short Latin text detected as non-English', async () => {
	const scanner = new SpamScanner();

	// Short Latin text that might be detected as another language
	const result = await scanner.detectLanguageHybrid('ok');
	assert.ok(result, 'Should return language code');
});

test('should cover language detection with exactly 50 chars', async () => {
	const scanner = new SpamScanner();

	// Exactly 50 characters (boundary between lande and franc)
	const text = '12345678901234567890123456789012345678901234567890';
	assert.strictEqual(text.length, 50, 'Should be exactly 50 chars');

	const result = await scanner.detectLanguageHybrid(text);
	assert.ok(result, 'Should handle 50 char boundary');
});

test('should cover language detection with 49 chars (uses lande)', async () => {
	const scanner = new SpamScanner();

	// 49 characters (uses lande)
	const text = '1234567890123456789012345678901234567890123456789';
	assert.strictEqual(text.length, 49, 'Should be 49 chars');

	const result = await scanner.detectLanguageHybrid(text);
	assert.ok(result, 'Should use lande for < 50 chars');
});

test('should cover language detection with 51 chars (uses franc)', async () => {
	const scanner = new SpamScanner();

	// 51 characters (uses franc)
	const text = 'Hello world this is a test message with enough text';
	assert.ok(text.length >= 50, 'Should be >= 50 chars');

	const result = await scanner.detectLanguageHybrid(text);
	assert.ok(result, 'Should use franc for >= 50 chars');
});
