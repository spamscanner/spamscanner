import {test} from 'node:test';
import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

// Tests to cover remaining edge cases for 100% coverage

test('should handle normalizeLanguageCode with null input', async () => {
	const scanner = new SpamScanner();

	const result1 = scanner.normalizeLanguageCode(null);
	assert.strictEqual(result1, 'en', 'Should return en for null');

	const result2 = scanner.normalizeLanguageCode(undefined);
	assert.strictEqual(result2, 'en', 'Should return en for undefined');

	const result3 = scanner.normalizeLanguageCode('');
	assert.strictEqual(result3, 'en', 'Should return en for empty string');

	const result4 = scanner.normalizeLanguageCode(123);
	assert.strictEqual(result4, 'en', 'Should return en for non-string');
});

test('should handle normalizeLanguageCode with 2-letter codes', async () => {
	const scanner = new SpamScanner();

	const result1 = scanner.normalizeLanguageCode('en');
	assert.strictEqual(result1, 'en', 'Should return lowercase en');

	const result2 = scanner.normalizeLanguageCode('FR');
	assert.strictEqual(result2, 'fr', 'Should return lowercase fr');

	const result3 = scanner.normalizeLanguageCode('De');
	assert.strictEqual(result3, 'de', 'Should return lowercase de');
});

test('should handle normalizeLanguageCode with 3-letter codes', async () => {
	const scanner = new SpamScanner();

	const result1 = scanner.normalizeLanguageCode('eng');
	assert.strictEqual(result1, 'en', 'Should convert eng to en');

	const result2 = scanner.normalizeLanguageCode('fra');
	assert.strictEqual(result2, 'fr', 'Should convert fra to fr');

	const result3 = scanner.normalizeLanguageCode('deu');
	assert.strictEqual(result3, 'de', 'Should convert deu to de');
});

test('should handle get-classifier with no classifier loaded', async () => {
	const scanner = new SpamScanner();

	// Don't initialize classifier, test fallback
	const tokens = ['test', 'email', 'message'];
	const result = await scanner.getClassification(tokens);

	assert.ok(result, 'Should return result even without classifier');
	assert.strictEqual(typeof result.category, 'string', 'Should have category');
});

test('should handle replacements initialization', async () => {
	const scanner = new SpamScanner();

	await scanner.initializeReplacements();
	assert.ok(scanner.replacements, 'Replacements should be initialized');
});

test('should handle isValidShortTextDetection edge cases', async () => {
	const scanner = new SpamScanner();

	// Test with non-Latin script (should always trust)
	const result1 = scanner.isValidShortTextDetection('你好', 'zh');
	assert.strictEqual(result1, true, 'Should trust non-Latin detection');

	// Test with very short Latin text and non-English detection
	const result2 = scanner.isValidShortTextDetection('hi', 'fr');
	assert.strictEqual(result2, false, 'Should not trust short Latin text as non-English');

	// Test with longer Latin text
	const result3 = scanner.isValidShortTextDetection('hello world', 'es');
	assert.strictEqual(result3, true, 'Should trust longer Latin text detection');
});

test('should handle detectLanguageHybrid with edge cases', async () => {
	const scanner = new SpamScanner();

	// Test with empty string
	const result1 = await scanner.detectLanguageHybrid('');
	assert.strictEqual(result1, 'en', 'Should return en for empty string');

	// Test with very short string
	const result2 = await scanner.detectLanguageHybrid('a');
	assert.strictEqual(result2, 'en', 'Should return en for very short string');

	// Test with only numbers and special chars
	const result3 = await scanner.detectLanguageHybrid('123 !@# 456');
	assert.strictEqual(result3, 'en', 'Should return en for non-linguistic content');

	// Test with whitespace only
	const result4 = await scanner.detectLanguageHybrid('   ');
	assert.strictEqual(result4, 'en', 'Should return en for whitespace');
});

test('should handle parseLocale with various inputs', async () => {
	const scanner = new SpamScanner();

	const result1 = await scanner.parseLocale('en-US');
	assert.strictEqual(result1, 'en', 'Should parse en-US to en');

	const result2 = await scanner.parseLocale('fr_FR');
	assert.ok(result2, 'Should return a locale code');

	const result3 = await scanner.parseLocale('invalid');
	assert.ok(result3, 'Should handle invalid locale');
});

test('should handle getTokensAndMailFromSource with string input', async () => {
	const scanner = new SpamScanner();

	const result = await scanner.getTokensAndMailFromSource('Test email message');
	assert.ok(result.tokens, 'Should have tokens');
	assert.ok(result.mail, 'Should have mail object');
	assert.ok(Array.isArray(result.tokens), 'Tokens should be array');
});

test('should handle getTokensAndMailFromSource with buffer input', async () => {
	const scanner = new SpamScanner();

	const buffer = Buffer.from('Test email message');
	const result = await scanner.getTokensAndMailFromSource(buffer);
	assert.ok(result.tokens, 'Should have tokens');
	assert.ok(result.mail, 'Should have mail object');
});

test('should handle getTokensAndMailFromSource with stream input', async () => {
	const scanner = new SpamScanner();
	const {Readable} = await import('node:stream');

	const stream = Readable.from(['Test email message']);
	const result = await scanner.getTokensAndMailFromSource(stream);
	assert.ok(result.tokens, 'Should have tokens');
	assert.ok(result.mail, 'Should have mail object');
});

test('should handle optimizeUrlParsing edge cases', async () => {
	const scanner = new SpamScanner();

	// URL without protocol
	const result1 = await scanner.optimizeUrlParsing('example.com');
	assert.ok(result1, 'Should handle URL without protocol');

	// URL with unusual protocol
	const result2 = await scanner.optimizeUrlParsing('ftp://example.com');
	assert.ok(result2, 'Should handle FTP URL');
});

test('should handle extractAllUrls with various formats', async () => {
	const scanner = new SpamScanner();

	const mail = {
		text: 'Visit https://example.com and http://test.org',
		html: '<a href="https://link.com">Link</a>',
		subject: 'Check out example.net',
	};

	const urls = scanner.extractAllUrls(mail, 'test');
	assert.ok(Array.isArray(urls), 'Should return array');
	assert.ok(urls.length > 0, 'Should extract URLs');
});

test('should handle getUrls with various URL formats', async () => {
	const scanner = new SpamScanner();

	const text = 'Visit https://example.com, http://test.org, and www.site.com';
	const urls = scanner.getUrls(text);

	assert.ok(Array.isArray(urls), 'Should return array');
	assert.ok(urls.length > 0, 'Should extract multiple URLs');
});

test('should handle getTokens with HTML content', async () => {
	const scanner = new SpamScanner();

	const html = '<html><body><p>Test email with <b>HTML</b> content</p></body></html>';
	const tokens = await scanner.getTokens(html, 'en', true);

	assert.ok(Array.isArray(tokens), 'Should return tokens array');
	assert.ok(tokens.length > 0, 'Should have tokens');
});

test('should handle getTokens with non-English content', async () => {
	const scanner = new SpamScanner();

	const frenchText = 'Bonjour, comment allez-vous?';
	const tokens = await scanner.getTokens(frenchText, 'fr', false);

	assert.ok(Array.isArray(tokens), 'Should return tokens array');
	assert.ok(tokens.length > 0, 'Should have tokens');
});

test('should handle getPhishingResults with suspicious URLs', async () => {
	const scanner = new SpamScanner();

	const mail = {
		text: 'Click here: http://paypal-secure-login.suspicious.com',
		html: '',
		subject: 'Verify your account',
	};

	const results = await scanner.getPhishingResults(mail);
	assert.ok(Array.isArray(results), 'Should return array');
});

test('should handle getExecutableResults with various extensions', async () => {
	const scanner = new SpamScanner();

	const mail = {
		text: 'Download file.exe and script.bat',
		html: '',
		attachments: [
			{filename: 'test.exe'},
			{filename: 'script.bat'},
			{filename: 'safe.txt'},
		],
	};

	const results = await scanner.getExecutableResults(mail);
	assert.ok(Array.isArray(results), 'Should return array');
	assert.ok(results.length > 0, 'Should detect executables');
});

test('should handle getMacroResults with macro content', async () => {
	const scanner = new SpamScanner();

	const mail = {
		text: 'Sub AutoOpen()\nMsgBox "Hello"\nEnd Sub',
		html: '',
	};

	const results = await scanner.getMacroResults(mail);
	assert.ok(Array.isArray(results), 'Should return array');
});

test('should handle getArbitraryResults with GTUBE', async () => {
	const scanner = new SpamScanner();

	const mail = {
		text: 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X',
		html: '',
	};

	const results = await scanner.getArbitraryResults(mail);
	assert.ok(Array.isArray(results), 'Should return array');
	assert.ok(results.length > 0, 'Should detect GTUBE');
});

test('should handle getPatternResults with various patterns', async () => {
	const scanner = new SpamScanner();

	const mail = {
		text: 'Call 555-1234 or email test@example.com. Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
		html: '',
	};

	const results = await scanner.getPatternResults(mail);
	assert.ok(Array.isArray(results), 'Should return array');
});
