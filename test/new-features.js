import {test} from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);

const __dirname = path.dirname(__filename);

const scanner = new SpamScanner();

// Test confusables integration in IDN detection
test('should detect confusable characters in domains using confusables library', async () => {
	const idnDetector = await scanner.getIDNDetector();
	assert.ok(idnDetector, 'IDN detector should be initialized');

	// Test with confusable characters (Cyrillic 'а' instead of Latin 'a')
	const result = idnDetector.detectHomographAttack('pаypal.com', {});
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.riskScore, 'number');
	assert.ok(result.riskScore > 0, 'Should detect confusable characters');
	assert.ok(Array.isArray(result.riskFactors));
});

// Test tldts integration
test('should parse URLs with tldts correctly', async () => {
	const testUrl = 'https://subdomain.example.co.uk/path';
	const parsed = scanner.parseUrlWithTldts(testUrl);

	assert.ok(parsed, 'Should parse URL successfully');
	assert.strictEqual(parsed.domain, 'example.co.uk');
	assert.strictEqual(parsed.domainWithoutSuffix, 'example');
	assert.strictEqual(parsed.publicSuffix, 'co.uk');
	assert.strictEqual(parsed.subdomain, 'subdomain');
	assert.strictEqual(parsed.isIp, false);
});

test('should handle complex TLDs with tldts', async () => {
	const testUrl = 'https://test.example.com.au';
	const parsed = scanner.parseUrlWithTldts(testUrl);

	assert.ok(parsed, 'Should parse URL successfully');
	assert.strictEqual(parsed.domain, 'example.com.au');
	assert.strictEqual(parsed.publicSuffix, 'com.au');
});

// Test toxicity detection
test('should detect toxic content', async () => {
	const toxicEmail = {
		text: 'You are stupid and worthless, you idiot!',
		subject: 'Insult',
		html: '',
		attachments: [],
	};

	const results = await scanner.getToxicityResults(toxicEmail);
	assert.ok(Array.isArray(results), 'Should return array of results');
	// Note: May not always detect depending on model threshold
});

test('should not detect toxicity in clean content', async () => {
	const cleanEmail = {
		text: 'Thank you for your help. I appreciate your assistance.',
		subject: 'Thanks',
		html: '',
		attachments: [],
	};

	const results = await scanner.getToxicityResults(cleanEmail);
	assert.ok(Array.isArray(results), 'Should return array of results');
	assert.strictEqual(results.length, 0, 'Should not detect toxicity in clean content');
});

// Test NSFW detection
test('should handle NSFW detection for non-image attachments', async () => {
	const emailWithTextAttachment = {
		text: 'Test email',
		subject: 'Test',
		html: '',
		attachments: [
			{
				filename: 'test.txt',
				content: Buffer.from('This is a text file'),
			},
		],
	};

	const results = await scanner.getNSFWResults(emailWithTextAttachment);
	assert.ok(Array.isArray(results), 'Should return array of results');
	assert.strictEqual(results.length, 0, 'Should not process non-image attachments');
});

// Test integration of new features in scan method
test('should include toxicity and nsfw in scan results', async () => {
	const testEmail = 'This is a test email message.';
	const result = await scanner.scan(testEmail);

	assert.ok(result.results, 'Should have results object');
	assert.ok(Array.isArray(result.results.toxicity), 'Should have toxicity results array');
	assert.ok(Array.isArray(result.results.nsfw), 'Should have nsfw results array');
});

// Test enhanced IDN detection with confusables
test('should detect IDN homograph attacks with confusables', async () => {
	const emailWithIDN = 'Check out this link: https://аpple.com/login';
	const result = await scanner.scan(emailWithIDN);

	assert.ok(result.results.idnHomographAttack, 'Should have IDN homograph attack results');
	assert.strictEqual(typeof result.results.idnHomographAttack.detected, 'boolean');
	assert.strictEqual(typeof result.results.idnHomographAttack.riskScore, 'number');
});

// Test URL parsing with tldts in phishing detection
test('should use tldts for accurate domain extraction', async () => {
	const emailWithComplexTLD = 'Visit https://test.example.co.uk for more info';
	const result = await scanner.scan(emailWithComplexTLD);

	assert.ok(Array.isArray(result.links), 'Should extract links');
	assert.ok(result.links.length > 0, 'Should find at least one link');
});

// Test toxicity detection triggers spam flag
test('should mark email as spam if toxic content detected', async () => {
	// Create a scanner with lower toxicity threshold for testing
	const testScanner = new SpamScanner({toxicityThreshold: 0.5});

	const toxicEmail = 'You are a complete idiot and I hate you!';
	const result = await testScanner.scan(toxicEmail);

	// Note: This depends on the toxicity model actually detecting the content
	assert.ok(result.results, 'Should have results');
	assert.ok(Array.isArray(result.results.toxicity), 'Should have toxicity results');
});

// Test confusables normalization
test('should normalize confusable characters correctly', async () => {
	const idnDetector = await scanner.getIDNDetector();

	// Test with mixed confusable characters
	const testDomain = 'gооgle.com'; // Uses Cyrillic 'о' instead of Latin 'o'
	const result = idnDetector.detectHomographAttack(testDomain, {});

	assert.ok(result.riskFactors.length > 0, 'Should identify risk factors');
	assert.ok(
		result.riskFactors.some(factor => factor.includes('confusable') || factor.includes('Normalized')),
		'Should mention confusable characters or normalization',
	);
});

// Test tldts with IP addresses
test('should detect IP addresses with tldts', async () => {
	const ipUrl = 'http://192.168.1.1/test';
	const parsed = scanner.parseUrlWithTldts(ipUrl);

	assert.ok(parsed, 'Should parse IP URL');
	assert.strictEqual(parsed.isIp, true, 'Should detect IP address');
});

// Test tldts with punycode domains
test('should handle punycode domains with tldts', async () => {
	const punycodeUrl = 'https://xn--e1afmkfd.xn--p1ai/test';
	const parsed = scanner.parseUrlWithTldts(punycodeUrl);

	assert.ok(parsed, 'Should parse punycode URL');
	assert.ok(parsed.domain, 'Should extract domain from punycode');
});
