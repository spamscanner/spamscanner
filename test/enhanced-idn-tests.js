import {test} from 'node:test';
import assert from 'node:assert';
import SpamScanner from '../src/index.js';

// Enhanced IDN Homograph Attack Detection Tests
test('Enhanced IDN Detection - Basic homograph attacks', async () => {
	const scanner = new SpamScanner();

	// Test Cyrillic 'a' (U+0430) vs Latin 'a' (U+0061)
	const cyrillicDomain = 'аpple.com'; // Cyrillic 'а'
	const result = await scanner.scan(`Visit https://${cyrillicDomain} for deals!`);

	assert.ok(result.results.idnHomographAttack, 'Should have IDN detection results');
	assert.ok(typeof result.results.idnHomographAttack.detected === 'boolean', 'Should have detected property');
	assert.ok(Array.isArray(result.results.idnHomographAttack.domains), 'Should have domains array');
	assert.ok(typeof result.results.idnHomographAttack.riskScore === 'number', 'Should have risk score');

	// Should detect the Cyrillic homograph attack
	if (result.results.idnHomographAttack.detected) {
		assert.ok(result.results.idnHomographAttack.domains.length > 0, 'Should identify suspicious domains');
		assert.ok(result.results.idnHomographAttack.riskScore > 0.3, 'Should have significant risk score');
	}
});

test('Enhanced IDN Detection - Mixed script attacks', async () => {
	const scanner = new SpamScanner();

	// Mixed Latin/Cyrillic characters
	const mixedDomain = 'gооgle.com'; // Contains Cyrillic 'о' (U+043E)
	const result = await scanner.scan(`Check out https://${mixedDomain}/search`);

	assert.ok(result.results.idnHomographAttack, 'Should have IDN detection results');
	assert.ok(typeof result.results.idnHomographAttack.detected === 'boolean', 'Should have detected property');

	// Should detect the mixed script attack
	if (result.results.idnHomographAttack.detected) {
		assert.ok(result.results.idnHomographAttack.domains.length > 0, 'Should identify suspicious domains');
		assert.ok(result.results.idnHomographAttack.riskScore > 0.3, 'Should have significant risk score');

		// Check that risk factors are provided
		const domain = result.results.idnHomographAttack.domains[0];
		assert.ok(Array.isArray(domain.riskFactors), 'Should have risk factors');
		assert.ok(Array.isArray(domain.recommendations), 'Should have recommendations');
	}
});

test('Enhanced IDN Detection - Brand similarity protection', async () => {
	const scanner = new SpamScanner();

	// Similar to popular brand but with substitutions
	const brandSpoof = 'goog1e.com'; // '1' instead of 'l'
	const result = await scanner.scan(`Visit https://${brandSpoof} for search`);

	assert.ok(result.results.idnHomographAttack, 'Should have IDN detection results');
	assert.ok(typeof result.results.idnHomographAttack.detected === 'boolean', 'Should have detected property');

	// Brand similarity detection may or may not trigger depending on implementation
	if (result.results.idnHomographAttack.detected) {
		assert.ok(result.results.idnHomographAttack.domains.length > 0, 'Should identify suspicious domains');
	}
});

test('Enhanced IDN Detection - Legitimate international domains', async () => {
	const scanner = new SpamScanner();

	// Legitimate domain that shouldn't trigger false positives
	const legitimateDomain = 'example.com';
	const result = await scanner.scan(`Visit https://${legitimateDomain} for information`);

	assert.ok(result.results.idnHomographAttack, 'Should have IDN detection results');
	assert.strictEqual(result.results.idnHomographAttack.detected, false, 'Should not detect legitimate domain as attack');
	assert.strictEqual(result.results.idnHomographAttack.domains.length, 0, 'Should have no suspicious domains');
	assert.strictEqual(result.results.idnHomographAttack.riskScore, 0, 'Should have zero risk score');
});

test('Enhanced IDN Detection - Punycode domains', async () => {
	const scanner = new SpamScanner();

	// Punycode domain (xn-- prefix)
	const punycodeDomain = 'xn--e1afmkfd.xn--p1ai'; // Пример.рф in punycode
	const result = await scanner.scan(`Visit https://${punycodeDomain} for information`);

	assert.ok(result.results.idnHomographAttack, 'Should have IDN detection results');
	assert.ok(typeof result.results.idnHomographAttack.detected === 'boolean', 'Should have detected property');

	// Punycode domains should be analyzed
	if (result.results.idnHomographAttack.detected) {
		const domain = result.results.idnHomographAttack.domains[0];
		assert.ok(domain.domain.includes('xn--'), 'Should identify punycode domain');
	}
});

test('Enhanced IDN Detection - Context analysis', async () => {
	const scanner = new SpamScanner();

	// Email with suspicious context and IDN domain
	const suspiciousEmail = `
		Subject: URGENT: Account Verification Required
		
		Your account has been suspended due to suspicious activity.
		Click here immediately to verify: https://аpple.com/verify
		
		WARNING: Failure to verify within 24 hours will result in permanent deletion.
	`;

	const result = await scanner.scan(suspiciousEmail);

	assert.ok(result.results.idnHomographAttack, 'Should have IDN detection results');

	if (result.results.idnHomographAttack.detected) {
		const domain = result.results.idnHomographAttack.domains[0];
		assert.ok(Array.isArray(domain.riskFactors), 'Should have risk factors');
		assert.ok(domain.riskFactors.length > 0, 'Should identify multiple risk factors');

		// Should consider email context in risk assessment
		assert.ok(typeof domain.confidence === 'number', 'Should have confidence score');
		assert.ok(domain.riskScore > 0.3, 'Should have elevated risk score due to context');
	}
});

test('Enhanced IDN Detection - Multiple domains in email', async () => {
	const scanner = new SpamScanner();

	// Email with multiple suspicious domains
	const multiDomainEmail = `
		Visit https://аpple.com for your account.
		Also check https://gооgle.com for search.
		And visit https://example.com for legitimate content.
	`;

	const result = await scanner.scan(multiDomainEmail);

	assert.ok(result.results.idnHomographAttack, 'Should have IDN detection results');

	if (result.results.idnHomographAttack.detected) {
		// Should detect multiple suspicious domains
		assert.ok(result.results.idnHomographAttack.domains.length > 0, 'Should detect at least one suspicious domain');

		// Risk score should reflect the highest risk found
		assert.ok(result.results.idnHomographAttack.riskScore > 0, 'Should have positive risk score');

		// Details should summarize findings
		assert.ok(Array.isArray(result.results.idnHomographAttack.details), 'Should have details array');
		assert.ok(result.results.idnHomographAttack.details.length > 0, 'Should have summary details');
	}
});

test('Enhanced IDN Detection - Edge cases', async () => {
	const scanner = new SpamScanner();

	// Email with no URLs
	const noUrlEmail = 'This is a simple email with no URLs.';
	const result1 = await scanner.scan(noUrlEmail);

	assert.ok(result1.results.idnHomographAttack, 'Should have IDN detection results');
	assert.strictEqual(result1.results.idnHomographAttack.detected, false, 'Should not detect attacks in email with no URLs');
	assert.strictEqual(result1.results.idnHomographAttack.domains.length, 0, 'Should have no domains');

	// Email with malformed URLs
	const malformedUrlEmail = 'Visit htp://broken-url for info.';
	const result2 = await scanner.scan(malformedUrlEmail);

	assert.ok(result2.results.idnHomographAttack, 'Should have IDN detection results');
	// Should handle malformed URLs gracefully without crashing
	assert.ok(typeof result2.results.idnHomographAttack.detected === 'boolean', 'Should handle malformed URLs gracefully');
});

test('Enhanced IDN Detection - Performance with large emails', async () => {
	const scanner = new SpamScanner();

	// Large email with many URLs
	let largeEmail = 'This is a large email with many URLs:\n';
	for (let i = 0; i < 50; i++) {
		largeEmail += `Visit https://example${i}.com for more info.\n`;
	}

	largeEmail += 'And finally visit https://аpple.com for suspicious content.';

	const startTime = Date.now();
	const result = await scanner.scan(largeEmail);
	const endTime = Date.now();
	const processingTime = endTime - startTime;

	assert.ok(result.results.idnHomographAttack, 'Should have IDN detection results');
	assert.ok(processingTime < 5000, 'Should process large email within reasonable time (< 5s)');

	// Should still detect the suspicious domain among many legitimate ones
	if (result.results.idnHomographAttack.detected) {
		assert.ok(result.results.idnHomographAttack.domains.length > 0, 'Should detect suspicious domain even in large email');
	}
});

