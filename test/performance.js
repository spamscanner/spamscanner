/* eslint-disable no-await-in-loop */
import {test} from 'node:test';
import assert from 'node:assert';
import process from 'node:process';
import {Buffer} from 'node:buffer';
import SpamScanner from '../src/index.js';

const scanner = new SpamScanner();

test('error handling: should handle invalid configuration gracefully', async () => {
	const invalidScanner = new SpamScanner({
		invalidOption: 'invalid',
	});

	assert.ok(invalidScanner instanceof SpamScanner);
	assert.strictEqual(typeof invalidScanner.config, 'object');
});

test('performance: should handle small emails quickly', async () => {
	const smallEmail = 'Short email.';

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(smallEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 12_000); // Should complete within 12000ms (includes TensorFlow loading)
});

test('performance: should handle medium emails efficiently', async () => {
	const mediumEmail = 'This is a medium-sized email with some content. '.repeat(20);

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(mediumEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 10_000); // Should complete within 10000ms (includes TensorFlow loading)
});

test('performance: should handle large emails within timeout', async () => {
	const largeEmail = 'This is a large email with lots of content. '.repeat(100);

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(largeEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 10_000); // Should complete within 10000ms
});

test('performance: should handle concurrent scans efficiently', async () => {
	const emails = Array.from({length: 3}, (_, i) => `Email ${i + 1}`);

	const startTime = process.hrtime.bigint();
	const results = await Promise.all(emails.map(email => scanner.scan(email)));
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(results.length, 3);
	assert.ok(duration < 12_000); // Should complete within 12000ms (includes TensorFlow loading)
});

test('stress: should handle many URLs without crashing', async () => {
	const urls = Array.from({length: 50}, (_, i) => `https://example${i}.com`);
	const emailWithManyUrls = `Check these URLs: ${urls.join(' ')}`;

	const result = await scanner.scan(emailWithManyUrls);
	assert.strictEqual(typeof result, 'object');
});

test('stress: should handle many tokens without memory issues', async () => {
	const manyWords = Array.from({length: 1000}, (_, i) => `word${i}`).join(' ');

	const result = await scanner.scan(manyWords);
	assert.strictEqual(typeof result, 'object');
});

test('stress: should handle repeated patterns gracefully', async () => {
	const repeatedPattern = 'URGENT! '.repeat(100);

	const result = await scanner.scan(repeatedPattern);
	assert.strictEqual(typeof result, 'object');
});

test('edge case: should handle empty strings', async () => {
	const result = await scanner.scan('');
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, false);
});

test('edge case: should handle whitespace-only content', async () => {
	const result = await scanner.scan(String.raw`   \n\t   `);
	assert.strictEqual(typeof result, 'object');
	assert.strictEqual(result.isSpam, false);
});

test('edge case: should handle special characters', async () => {
	const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
	const result = await scanner.scan(specialChars);
	assert.strictEqual(typeof result, 'object');
});

test('edge case: should handle unicode content', async () => {
	const unicodeContent = '你好世界 🌍 Здравствуй мир 🚀 مرحبا بالعالم';
	const result = await scanner.scan(unicodeContent);
	assert.strictEqual(typeof result, 'object');
});

test('edge case: should handle very long single words', async () => {
	const longWord = 'a'.repeat(10_000);
	const result = await scanner.scan(longWord);
	assert.strictEqual(typeof result, 'object');
});

test('edge case: should handle emails with binary content', async () => {
	const binaryContent = Buffer.from([0x00, 0x01, 0x02, 0x03, 0xFF]).toString('binary');
	const result = await scanner.scan(binaryContent);
	assert.strictEqual(typeof result, 'object');
});

test('edge case: should handle extremely nested HTML', async () => {
	const nestedHtml = '<div>'.repeat(100) + 'Content' + '</div>'.repeat(100);
	const result = await scanner.scan(nestedHtml);
	assert.strictEqual(typeof result, 'object');
});

test('performance metrics: should track processing times', async () => {
	const initialScans = scanner.metrics.totalScans;
	await scanner.scan('Test email for metrics');

	assert.ok(scanner.metrics.totalScans > initialScans);
	assert.strictEqual(typeof scanner.metrics.averageTime, 'number');
});

test('timeout: should respect timeout settings', async () => {
	const timeoutScanner = new SpamScanner({
		timeout: 1000, // 1 second timeout
	});

	const result = await timeoutScanner.scan('Test email');
	assert.strictEqual(typeof result, 'object');
});

test('configuration: should handle different language settings', async () => {
	const multiLangScanner = new SpamScanner({
		defaultLanguage: 'es',
	});

	const result = await multiLangScanner.scan('Hola mundo');
	assert.strictEqual(typeof result, 'object');
});

test('edge case: should handle malformed email headers', async () => {
	const malformedEmail = String.raw`From: invalid-email\nSubject: \nTo: \n\nBody content`;
	const result = await scanner.scan(malformedEmail);
	assert.strictEqual(typeof result, 'object');
});

test('performance: should maintain consistent performance', async () => {
	const testEmails = Array.from({length: 5}, (_, i) => `Test email ${i + 1}`);
	const times = [];

	for (const email of testEmails) {
		const startTime = process.hrtime.bigint();
		await scanner.scan(email);
		const endTime = process.hrtime.bigint();
		times.push(Number(endTime - startTime) / 1_000_000);
	}

	const average = times.reduce((a, b) => a + b, 0) / times.length;
	const maxDeviation = Math.max(...times) - Math.min(...times);

	assert.ok(average < 10_000); // Average should be under 10 seconds (more realistic)
	assert.ok(maxDeviation < average * 3); // No scan should take more than 3x average (more lenient)
});

test('robustness: should handle scanner reuse', async () => {
	// Use the same scanner instance multiple times
	for (let i = 0; i < 5; i++) {
		const result = await scanner.scan(`Reuse test ${i + 1}`);
		assert.strictEqual(typeof result, 'object');
	}
});

test('memory: should not leak memory with repeated scans', async () => {
	const initialMemory = process.memoryUsage().heapUsed;

	// Perform many scans
	for (let i = 0; i < 20; i++) {
		await scanner.scan(`Memory test ${i + 1}`);
	}

	// Force garbage collection if available
	if (globalThis.gc) {
		globalThis.gc();
	}

	const finalMemory = process.memoryUsage().heapUsed;
	const memoryIncrease = (finalMemory - initialMemory) / 1024 / 1024; // MB

	assert.ok(memoryIncrease < 200); // Should not increase by more than 200MB
});

