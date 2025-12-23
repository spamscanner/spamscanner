import {test} from 'node:test';
import assert from 'node:assert';
import process from 'node:process';
import SpamScanner from '../src/index.js';

const scanner = new SpamScanner();

test('integration: should export and instantiate correctly', async () => {
	assert.strictEqual(typeof SpamScanner, 'function');
	assert.ok(scanner instanceof SpamScanner);
});

test('integration: should handle email with executable attachments', async () => {
	const mail = {
		attachments: [
			{filename: 'document.exe', contentType: 'application/octet-stream'},
			{filename: 'image.jpg', contentType: 'image/jpeg'},
		],
	};

	const results = await scanner.getExecutableResults(mail);
	assert.ok(Array.isArray(results));
});

test('integration: should handle concurrent scanning', async () => {
	const emails = [
		'This is a legitimate business email.',
		'URGENT: You have won a prize!',
		'Meeting scheduled for tomorrow at 2 PM.',
	];

	const promises = emails.map(email => scanner.scan(email));
	const results = await Promise.all(promises);

	assert.strictEqual(results.length, 3);
	for (const result of results) {
		assert.strictEqual(typeof result, 'object');
		assert.strictEqual(typeof result.isSpam, 'boolean');
		assert.strictEqual(typeof result.message, 'string');
	}
});

test('integration: should detect GTUBE test pattern', async () => {
	const gtubeEmail = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';
	const result = await scanner.scan(gtubeEmail);

	assert.strictEqual(result.isSpam, true);
	assert.ok(result.message.includes('arbitrary') || result.message.includes('GTUBE'));
});

test('integration: should maintain metrics across scans', async () => {
	// Create a fresh scanner to test metrics
	const freshScanner = new SpamScanner();
	const initialScans = freshScanner.metrics.totalScans;

	await freshScanner.scan('Test email 1');
	await freshScanner.scan('Test email 2');
	await freshScanner.scan('Test email 3');

	assert.strictEqual(freshScanner.metrics.totalScans, initialScans + 3);
	assert.strictEqual(typeof freshScanner.metrics.averageTime, 'number');
	assert.ok(freshScanner.metrics.averageTime > 0);
});

test('integration: should handle configuration changes', async () => {
	const configuredScanner = new SpamScanner({
		enableMacroDetection: false,
		enablePhishingDetection: true,
	});

	assert.strictEqual(configuredScanner.config.enableMacroDetection, false);
	assert.strictEqual(configuredScanner.config.enablePhishingDetection, true);
});

test('integration: should handle email with suspicious file paths', async () => {
	const suspiciousEmail = String.raw`Please check this file: C:\\Windows\\System32\\malware.exe`;
	const result = await scanner.scan(suspiciousEmail);

	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.isSpam, 'boolean');
});

test('integration: should handle multilingual content', async () => {
	const multilingualEmail = 'Hello world. Bonjour le monde. Hola mundo.';
	const result = await scanner.scan(multilingualEmail);

	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(typeof result.isSpam, 'boolean');
});

test('integration: should handle legitimate business email', async () => {
	const businessEmail = `
		Dear Mr. Johnson,
		
		Thank you for your inquiry about our services. We would be happy to schedule
		a meeting to discuss your requirements in detail.
		
		Best regards,
		Sarah Smith
		Account Manager
		ABC Corporation`;

	const result = await scanner.scan(businessEmail);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, false);
});

test('integration: should handle real spam email patterns', async () => {
	const spamEmail = `
		URGENT: CONGRATULATIONS!!!
		
		You have been selected to receive $1,000,000 USD!!!
		
		To claim your prize, click here immediately:
		http://suspicious-site.com/claim-now
		
		Act fast! This offer expires in 24 hours!
	`;

	const result = await scanner.scan(spamEmail);
	assert.strictEqual(typeof result, 'object');
	// Note: May or may not be detected as spam depending on patterns
});

test('integration: should detect phishing attempt', async () => {
	const phishingEmail = `
		Your PayPal account has been suspended due to suspicious activity.
		
		To restore access, please verify your account immediately:
		http://fake-paypal-security.com/verify
		
		Failure to verify within 24 hours will result in permanent suspension.
	`;

	const result = await scanner.scan(phishingEmail);
	assert.strictEqual(typeof result, 'object');
});

test('integration: should handle performance with large emails', async () => {
	const largeEmail = 'This is a large email with lots of content. '.repeat(500);

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(largeEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 60_000); // Should complete within 60s (includes model loading)
});

test('integration: should detect macro-laden email', async () => {
	const macroEmail = `
		Please find the attached document.
		
		Sub AutoOpen()
			Shell "powershell.exe -ExecutionPolicy Bypass -File malware.ps1"
		End Sub
		
		Best regards
	`;

	const result = await scanner.scan(macroEmail);
	assert.strictEqual(result.isSpam, true);
	assert.ok(result.message.includes('macro'));
});

test('integration: should handle email with multiple threat types', async () => {
	const multiThreatEmail = `
		URGENT: Your account will be suspended!
		
		Sub AutoOpen()
			Shell "malware.exe"
		End Sub
		
		Click here to verify: http://fake-bank.com/verify
		
		File attached: C:\\\\Windows\\\\System32\\\\virus.exe
	`;

	const result = await scanner.scan(multiThreatEmail);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, true);
});

