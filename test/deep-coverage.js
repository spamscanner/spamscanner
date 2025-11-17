import {test} from 'node:test';
import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

// Deep coverage tests to reach 100%

test('should trigger franc error fallback to lande', async () => {
	const scanner = new SpamScanner();

	// Create text that might cause franc to error
	// Using very unusual characters or malformed text
	const weirdText = '\uFFFD\uFFFE\u0000\u0001\u0002';

	const result = await scanner.detectLanguageHybrid(weirdText);
	assert.ok(result, 'Should return a language code even with weird text');
	assert.strictEqual(typeof result, 'string', 'Should return string');
});

test('should handle lande fallback when franc fails', async () => {
	const scanner = new SpamScanner();

	// Text with only control characters
	const controlChars = '\u0000\u0001\u0002\u0003\u0004\u0005';

	const result = await scanner.detectLanguageHybrid(controlChars);
	assert.strictEqual(result, 'en', 'Should fallback to en for control chars');
});

test('should handle both franc and lande failing', async () => {
	const scanner = new SpamScanner();

	// Empty or null-like content
	const result = await scanner.detectLanguageHybrid('');
	assert.strictEqual(result, 'en', 'Should return en when both fail');
});

test('should cover NSFW model lazy loading path', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// Create a valid small PNG image
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
		text: 'Test',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.png',
				content: pngBuffer,
			},
		],
	};

	// First call loads the model
	const results1 = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results1), 'Should return array');

	// Second call uses cached model
	const results2 = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results2), 'Should return array on second call');
});

test('should cover toxicity model lazy loading path', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.9});

	const mail = {
		text: 'You are terrible',
		subject: 'Rude',
		html: '',
	};

	// First call loads the model
	const results1 = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results1), 'Should return array');

	// Second call uses cached model
	const results2 = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results2), 'Should return array on second call');
});

test('should handle NSFW detection with multiple image formats', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// PNG image
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
		text: 'Test',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'image1.png',
				content: pngBuffer,
			},
			{
				filename: 'image2.jpg',
				content: pngBuffer, // Using PNG data for simplicity
			},
		],
	};

	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should handle multiple images');
});

test('should handle toxicity detection with long content', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.7});

	// Create content just under the 5000 char limit
	const longText = 'This is a test message. '.repeat(200);

	const mail = {
		text: longText,
		subject: 'Long message',
		html: '',
	};

	const results = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results), 'Should handle long content');
});

test('should handle toxicity detection with HTML content', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.7});

	const mail = {
		text: '',
		subject: 'Test',
		html: '<html><body><p>You are stupid and I hate you!</p></body></html>',
	};

	const results = await scanner.getToxicityResults(mail);
	assert.ok(Array.isArray(results), 'Should detect toxicity in HTML');
});

test('should handle NSFW detection error gracefully', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// Corrupted image data
	const corruptedBuffer = Buffer.from([0x00, 0x01, 0x02, 0x03]);

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

	// Should not throw, should handle error gracefully
	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should handle corrupted images gracefully');
});

test('should handle scan with disabled detection methods', async () => {
	const scanner = new SpamScanner({
		enableToxicityDetection: false,
		enableNSFWDetection: false,
	});

	const email = 'This is a test email';
	const result = await scanner.scan(email);

	assert.ok(result, 'Should return result');
	assert.strictEqual(result.results.toxicity.length, 0, 'Toxicity should be empty');
	assert.strictEqual(result.results.nsfw.length, 0, 'NSFW should be empty');
});

test('should handle getUrls with edge cases', async () => {
	const scanner = new SpamScanner();

	// URLs with various formats
	const text = `
		Visit https://example.com
		Check http://test.org/path?query=value
		See ftp://files.example.com
		Go to www.site.com
		Email: test@example.com
	`;

	const urls = scanner.getUrls(text);
	assert.ok(Array.isArray(urls), 'Should return array');
	assert.ok(urls.length > 0, 'Should extract URLs');
});

test('should handle extractAllUrls with all sources', async () => {
	const scanner = new SpamScanner();

	const mail = {
		text: 'Visit https://text-url.com',
		html: '<a href="https://html-url.com">Link</a>',
		subject: 'Check https://subject-url.com',
		headers: {
			'x-custom': 'https://header-url.com',
		},
	};

	const urls = scanner.extractAllUrls(mail, 'test');
	assert.ok(Array.isArray(urls), 'Should return array');
	assert.ok(urls.length > 0, 'Should extract URLs from sources');
});

test('should handle IDN detector with various Unicode scripts', async () => {
	const scanner = new SpamScanner();
	const idnDetector = await scanner.getIDNDetector();

	// Test with various Unicode scripts
	const tests = [
		{domain: 'раypal.com', desc: 'Cyrillic mixed with Latin'},
		{domain: 'аррӏе.com', desc: 'Cyrillic lookalikes'},
		{domain: 'gοοgle.com', desc: 'Greek omicron'},
		{domain: 'microsοft.com', desc: 'Greek omicron in microsoft'},
		{domain: 'example。com', desc: 'Fullwidth period'},
	];

	for (const {domain, desc} of tests) {
		const result = idnDetector.detectHomographAttack(domain, {});
		assert.ok(result, `Should analyze ${desc}`);
		assert.ok(result.riskScore >= 0, `Should have risk score for ${desc}`);
	}
});

test('should handle IDN detector with punycode domains', async () => {
	const scanner = new SpamScanner();
	const idnDetector = await scanner.getIDNDetector();

	// Punycode encoded domains
	const domains = [
		'xn--e1afmkfd.xn--p1ai', // Russian
		'xn--80akhbyknj4f.xn--p1ai', // Russian
		'xn--vermgensberatung-pwb.com', // German
	];

	for (const domain of domains) {
		const result = idnDetector.detectHomographAttack(domain, {});
		assert.ok(result, `Should handle punycode: ${domain}`);
	}
});

test('should handle enhanced IDN detector edge cases', async () => {
	const scanner = new SpamScanner();
	const idnDetector = await scanner.getIDNDetector();

	// Test with empty domain
	const result1 = idnDetector.detectHomographAttack('', {});
	assert.ok(result1, 'Should handle empty domain');

	// Test with single character
	const result2 = idnDetector.detectHomographAttack('a', {});
	assert.ok(result2, 'Should handle single char domain');

	// Test with numbers only
	const result3 = idnDetector.detectHomographAttack('12345', {});
	assert.ok(result3, 'Should handle numeric domain');

	// Test with special characters
	const result4 = idnDetector.detectHomographAttack('test-domain.com', {});
	assert.ok(result4, 'Should handle hyphenated domain');
});

test('should handle tldts with complex TLDs', async () => {
	const scanner = new SpamScanner();

	const complexUrls = [
		'https://example.co.uk',
		'https://test.com.au',
		'https://site.gov.br',
		'https://domain.ac.jp',
		'https://web.org.nz',
	];

	for (const url of complexUrls) {
		const result = scanner.parseUrlWithTldts(url);
		assert.ok(result, `Should parse ${url}`);
		assert.ok(result.publicSuffix, `Should have public suffix for ${url}`);
	}
});

test('should handle scan with all features enabled and complex email', async () => {
	const scanner = new SpamScanner({
		enableToxicityDetection: true,
		enableNSFWDetection: true,
		toxicityThreshold: 0.7,
		nsfwThreshold: 0.6,
	});

	const complexEmail = `
From: test@example.com
To: user@test.com
Subject: Important message

Hello,

This is a test email with various content:
- URL: https://example.com
- Phone: 555-1234
- Email: contact@test.org
- Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

Please visit our website for more information.

Best regards,
Test User
	`;

	const result = await scanner.scan(complexEmail);
	assert.ok(result, 'Should return result');
	assert.ok(result.results, 'Should have results object');
	assert.ok(typeof result.isSpam === 'boolean', 'Should have isSpam flag');
});

test('should handle getClassification with various token sets', async () => {
	const scanner = new SpamScanner();
	await scanner.initializeClassifier();

	// Test with spam-like tokens
	const spamTokens = ['viagra', 'free', 'money', 'click', 'now', 'offer'];
	const result1 = await scanner.getClassification(spamTokens);
	assert.ok(result1, 'Should classify spam tokens');

	// Test with ham-like tokens
	const hamTokens = ['meeting', 'schedule', 'project', 'update', 'team'];
	const result2 = await scanner.getClassification(hamTokens);
	assert.ok(result2, 'Should classify ham tokens');

	// Test with mixed tokens
	const mixedTokens = ['hello', 'free', 'meeting', 'viagra'];
	const result3 = await scanner.getClassification(mixedTokens);
	assert.ok(result3, 'Should classify mixed tokens');
});
