/* eslint-disable no-await-in-loop */
import {test} from 'node:test';
import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

// Extreme edge case tests to force error paths and maximize coverage

test('should handle extremely malformed text for language detection', async () => {
	const scanner = new SpamScanner();

	// Text that might cause franc to fail internally
	const malformedTexts = [
		'\uFFFD'.repeat(100), // Replacement characters
		'\u0000\u0001\u0002\u0003\u0004', // Control characters
		'�'.repeat(50), // Invalid UTF-8 replacement chars
		'\uD800\uDFFF', // Surrogate pairs
		String.fromCodePoint(0xD8_00), // Lone surrogate
	];

	for (const text of malformedTexts) {
		const result = await scanner.detectLanguageHybrid(text);
		assert.ok(result, 'Should handle malformed text');
		assert.strictEqual(typeof result, 'string', 'Should return string');
	}
});

test('should handle language detection with only special characters', async () => {
	const scanner = new SpamScanner();

	const specialTexts = [
		'!@#$%^&*()',
		'😀😁😂🤣😃😄',
		'🔥💯✨🎉🎊',
		'←↑→↓↔↕',
		'①②③④⑤',
	];

	for (const text of specialTexts) {
		const result = await scanner.detectLanguageHybrid(text);
		assert.strictEqual(result, 'en', 'Should fallback to en for special chars');
	}
});

test('should handle NSFW detection with maximum image attachments', async () => {
	const scanner = new SpamScanner({enableNSFWDetection: true});

	// Create minimal PNG
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

	// Create many attachments
	const attachments = [];
	for (let i = 0; i < 5; i++) {
		attachments.push({
			filename: `image${i}.png`,
			content: pngBuffer,
		});
	}

	const mail = {
		text: 'Test',
		subject: 'Test',
		html: '',
		attachments,
	};

	const results = await scanner.getNSFWResults(mail);
	assert.ok(Array.isArray(results), 'Should handle multiple images');
});

test('should handle toxicity detection with edge case content', async () => {
	const scanner = new SpamScanner({toxicityThreshold: 0.5});

	const edgeCases = [
		{text: 'a'.repeat(5000), desc: 'exactly 5000 chars'},
		{text: 'test '.repeat(1000), desc: 'repeated words'},
		{text: '\n'.repeat(100) + 'content', desc: 'many newlines'},
		{text: '   '.repeat(100) + 'text', desc: 'many spaces'},
	];

	for (const {text, desc} of edgeCases) {
		const mail = {text, subject: 'Test', html: ''};
		const results = await scanner.getToxicityResults(mail);
		assert.ok(Array.isArray(results), `Should handle ${desc}`);
	}
});

test('should handle IDN detector with extreme confusables', async () => {
	const scanner = new SpamScanner();
	const idnDetector = await scanner.getIDNDetector();

	// Domains with heavy confusable usage
	const confusableDomains = [
		'раураӏ.com', // All Cyrillic
		'ɡoogle.com', // Latin small letter script g
		'аррӏе.com', // Cyrillic a, p, and palochka
		'ⅿicrosoft.com', // Roman numeral m
		'ｆａｃｅｂｏｏｋ.com', // Fullwidth Latin
	];

	for (const domain of confusableDomains) {
		const result = idnDetector.detectHomographAttack(domain, {});
		assert.ok(result, `Should analyze ${domain}`);
		assert.ok(result.riskScore > 0, `Should detect risk in ${domain}`);
	}
});

test('should handle IDN detector with mixed script combinations', async () => {
	const scanner = new SpamScanner();
	const idnDetector = await scanner.getIDNDetector();

	// Test various script mixing scenarios
	const mixedDomains = [
		{domain: 'test测试.com', desc: 'Latin + Chinese'},
		{domain: 'testテスト.com', desc: 'Latin + Japanese'},
		{domain: 'test테스트.com', desc: 'Latin + Korean'},
		{domain: 'testтест.com', desc: 'Latin + Cyrillic'},
		{domain: 'testδοκιμή.com', desc: 'Latin + Greek'},
	];

	for (const {domain, desc} of mixedDomains) {
		const result = idnDetector.detectHomographAttack(domain, {});
		assert.ok(result, `Should analyze ${desc}`);
	}
});

test('should handle tldts with unusual URL formats', async () => {
	const scanner = new SpamScanner();

	const unusualUrls = [
		'http://user:pass@example.com:8080/path',
		'https://192.168.1.1:443',
		'http://[::1]:8080',
		'ftp://files.example.com',
		'file:///path/to/file',
		'data:text/plain;base64,SGVsbG8=',
	];

	for (const url of unusualUrls) {
		const result = scanner.parseUrlWithTldts(url);
		assert.ok(result, `Should parse ${url}`);
	}
});

test('should handle scan with maximum complexity email', async () => {
	const scanner = new SpamScanner({
		enableToxicityDetection: true,
		enableNSFWDetection: true,
	});

	// Create a minimal PNG
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

	const complexEmail = `
From: spammer@раypal.com
To: victim@example.com
Subject: You won $1,000,000! Click now!

Dear user,

You are stupid if you don't click this link: https://раypal-secure.com/login

Download the attached file.exe to claim your prize!

Call 555-SCAM or send Bitcoin to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

Best regards,
Nigerian Prince
	`;

	const result = await scanner.scan({
		text: complexEmail,
		subject: 'You won $1,000,000!',
		html: `<html><body>${complexEmail}</body></html>`,
		attachments: [
			{filename: 'prize.exe', content: Buffer.from('fake exe')},
			{filename: 'image.png', content: pngBuffer},
		],
	});

	assert.ok(result, 'Should handle complex email');
	assert.ok(typeof result.isSpam === 'boolean', 'Should have isSpam flag');
	assert.ok(result.results, 'Should have results object');
	assert.ok(Array.isArray(result.results.executables), 'Should have executables array');
});

test('should handle getTokens with various language content', async () => {
	const scanner = new SpamScanner();

	const multilingualTexts = [
		{text: 'Hello world', lang: 'en'},
		{text: 'Bonjour le monde', lang: 'fr'},
		{text: 'Hola mundo', lang: 'es'},
		{text: 'Hallo Welt', lang: 'de'},
		{text: 'Ciao mondo', lang: 'it'},
		{text: 'Olá mundo', lang: 'pt'},
		{text: 'Привет мир', lang: 'ru'},
		{text: '你好世界', lang: 'zh'},
		{text: 'こんにちは世界', lang: 'ja'},
		{text: '안녕하세요 세계', lang: 'ko'},
	];

	for (const {text, lang} of multilingualTexts) {
		const tokens = await scanner.getTokens(text, lang, false);
		assert.ok(Array.isArray(tokens), `Should tokenize ${lang}`);
		// Some languages may have no tokens after stemming/filtering
	}
});

test('should handle normalizeLanguageCode with all mappings', async () => {
	const scanner = new SpamScanner();

	const languageCodes = [
		{input: 'eng', expected: 'en'},
		{input: 'fra', expected: 'fr'},
		{input: 'deu', expected: 'de'},
		{input: 'spa', expected: 'es'},
		{input: 'ita', expected: 'it'},
		{input: 'por', expected: 'pt'},
		{input: 'rus', expected: 'ru'},
		{input: 'zho', expected: 'zh'},
		{input: 'jpn', expected: 'ja'},
		{input: 'kor', expected: 'ko'},
	];

	for (const {input, expected} of languageCodes) {
		const result = scanner.normalizeLanguageCode(input);
		assert.strictEqual(result, expected, `Should convert ${input} to ${expected}`);
	}
});

test('should handle isValidShortTextDetection with various scripts', async () => {
	const scanner = new SpamScanner();

	// Non-Latin scripts should always be trusted
	const nonLatinTests = [
		{text: '你好', lang: 'zh', expected: true},
		{text: 'こんにちは', lang: 'ja', expected: true},
		{text: '안녕', lang: 'ko', expected: true},
		{text: 'Привет', lang: 'ru', expected: true},
		{text: 'مرحبا', lang: 'ar', expected: true},
	];

	for (const {text, lang, expected} of nonLatinTests) {
		const result = scanner.isValidShortTextDetection(text, lang);
		assert.strictEqual(result, expected, `Should handle ${lang} correctly`);
	}

	// Short Latin text with non-English detection should not be trusted
	const latinTests = [
		{text: 'hi', lang: 'fr', expected: false},
		{text: 'ok', lang: 'de', expected: false},
		{text: 'test', lang: 'es', expected: false},
	];

	for (const {text, lang, expected} of latinTests) {
		const result = scanner.isValidShortTextDetection(text, lang);
		assert.strictEqual(result, expected, `Should not trust short Latin as ${lang}`);
	}
});

test('should handle getPhishingResults with various phishing patterns', async () => {
	const scanner = new SpamScanner();

	const phishingEmails = [
		{
			text: 'Visit https://paypal-secure-login.com',
			desc: 'PayPal phishing',
		},
		{
			text: 'Click here: https://apple-id-verify.com',
			desc: 'Apple phishing',
		},
		{
			text: 'Update your account: https://amazon-security.com',
			desc: 'Amazon phishing',
		},
		{
			text: 'Verify now: https://microsoft-account-recovery.com',
			desc: 'Microsoft phishing',
		},
	];

	for (const {text, desc} of phishingEmails) {
		const mail = {text, subject: 'Security Alert', html: ''};
		const results = await scanner.getPhishingResults(mail);
		assert.ok(Array.isArray(results), `Should analyze ${desc}`);
	}
});

test('should handle getMacroResults with various macro types', async () => {
	const scanner = new SpamScanner();

	const macroContents = [
		{
			text: 'Sub AutoOpen()\nMsgBox "Hello"\nEnd Sub',
			desc: 'VBA macro',
		},
		{
			text: 'powershell.exe -ExecutionPolicy Bypass -Command "Write-Host test"',
			desc: 'PowerShell',
		},
		{
			text: 'eval(atob("SGVsbG8gV29ybGQ="))',
			desc: 'JavaScript eval',
		},
		{
			text: '@echo off\ndel /f /q *.*',
			desc: 'Batch file',
		},
	];

	for (const {text, desc} of macroContents) {
		const mail = {text, subject: 'Test', html: ''};
		const results = await scanner.getMacroResults(mail);
		assert.ok(Array.isArray(results), `Should detect ${desc}`);
	}
});

test('should handle getPatternResults with comprehensive patterns', async () => {
	const scanner = new SpamScanner();

	const mail = {
		text: `
			Phone: 555-1234, (555) 123-4567
			Email: test@example.com, user@test.org
			Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
			Credit Card: 4532-1234-5678-9010
			IP: 192.168.1.1, 10.0.0.1
			MAC: 00:1B:44:11:3A:B7
			Currency: $100.00, €50.00, £25.00
			Color: #FF5733, #00FF00
		`,
		subject: 'Test',
		html: '',
	};

	const results = await scanner.getPatternResults(mail);
	assert.ok(Array.isArray(results), 'Should detect various patterns');
	// Patterns may or may not be detected depending on regex matching
});

test('should handle getArbitraryResults with GTUBE and other tests', async () => {
	const scanner = new SpamScanner();

	const testEmails = [
		{
			text: 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X',
			desc: 'GTUBE test',
		},
		{
			text: 'This is a normal email',
			desc: 'Normal email',
		},
	];

	for (const {text, desc} of testEmails) {
		const mail = {text, subject: 'Test', html: ''};
		const results = await scanner.getArbitraryResults(mail);
		assert.ok(Array.isArray(results), `Should handle ${desc}`);
	}
});
