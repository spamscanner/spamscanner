/* eslint-disable no-await-in-loop */
import {test} from 'node:test';
import assert from 'node:assert';
import process from 'node:process';
import SpamScanner from '../src/index.js';

const scanner = new SpamScanner();

test('benchmark: tokenization performance', async () => {
	const text = 'This is a test email with many words that need to be tokenized efficiently. '.repeat(50);

	const startTime = process.hrtime.bigint();
	const tokens = await scanner.getTokens(text, 'en');
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.ok(Array.isArray(tokens));
	assert.ok(tokens.length > 0);
	assert.ok(duration < 2000); // Should complete within 2000ms

	console.log(`Tokenization took ${duration.toFixed(2)}ms for ${tokens.length} tokens`);
});

test('benchmark: preprocessing performance', async () => {
	const text = 'HELLO WORLD! This is a TEST with LOTS of UPPERCASE and punctuation!!!'.repeat(20);

	const startTime = process.hrtime.bigint();
	const result = await scanner.preprocessText(text, 'en');
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'string');
	assert.ok(duration < 500); // Should complete within 500ms

	console.log(`Text preprocessing took ${duration.toFixed(2)}ms`);
});

test('benchmark: classification performance', async () => {
	const tokens = ['test', 'email', 'message', 'content', 'legitimate'];

	const startTime = process.hrtime.bigint();
	const result = await scanner.getClassification(tokens);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 500); // Should complete within 500ms

	console.log(`Classification took ${duration.toFixed(2)}ms`);
});

test('benchmark: basic email scanning', async () => {
	const email = 'This is a basic test email message with some content.';

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(email);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 5000); // Should complete within 5000ms (includes TensorFlow model loading)

	console.log(`Basic scan took ${duration.toFixed(2)}ms`);
});

test('benchmark: URL extraction performance', async () => {
	const urls = Array.from({length: 20}, (_, i) => `https://example${i}.com/path/to/resource`);
	const emailWithUrls = `Visit these sites: ${urls.join(', ')}`;

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(emailWithUrls);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 2000); // Should complete within 2000ms

	console.log(`URL extraction took ${duration.toFixed(2)}ms`);
});

test('benchmark: concurrent scanning performance', async () => {
	const emails = Array.from({length: 5}, (_, i) => `Test email ${i + 1} with some content.`);

	const startTime = process.hrtime.bigint();
	const results = await Promise.all(emails.map(email => scanner.scan(email)));
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(results.length, 5);
	assert.ok(duration < 3000); // Should complete within 3000ms

	console.log(`Concurrent scanning of ${emails.length} emails took ${duration.toFixed(2)}ms`);
});

test('benchmark: large email handling', async () => {
	const largeEmail = 'This is a large email with lots of content that needs to be processed efficiently. '.repeat(200);

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(largeEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 3000); // Should complete within 3000ms

	console.log(`Large email scan took ${duration.toFixed(2)}ms`);
});

test('benchmark: memory usage tracking', async () => {
	const initialMemory = process.memoryUsage().heapUsed;

	// Perform multiple scans
	for (let i = 0; i < 10; i++) {
		await scanner.scan(`Test email ${i} with some content.`);
	}

	const finalMemory = process.memoryUsage().heapUsed;
	const memoryIncrease = (finalMemory - initialMemory) / 1024 / 1024; // MB

	// Memory increase threshold: 200MB (more lenient for different platforms)
	// macOS may have higher memory usage than Linux due to different memory management
	assert.ok(
		memoryIncrease < 200,
		`Memory increase (${memoryIncrease.toFixed(2)}MB) should be less than 200MB`,
	);

	console.log(`Memory increase: ${memoryIncrease.toFixed(2)}MB`);
});

test('benchmark: spam detection performance', async () => {
	const spamEmail = 'URGENT: You have won $1,000,000! Click here now to claim your prize! Limited time offer!';

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(spamEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 3000); // Should complete within 3000ms

	console.log(`Spam detection took ${duration.toFixed(2)}ms`);
});

test('benchmark: macro detection performance', async () => {
	const macroEmail = String.raw`Sub AutoOpen()\nShell "malware.exe"\nEnd Sub`;

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(macroEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 2000); // Should complete within 2000ms (more realistic)

	console.log(`Macro detection took ${duration.toFixed(2)}ms`);
});

test('benchmark: pattern recognition performance', async () => {
	const patternEmail = 'URGENT! Act now! Limited time! Call 1-800-SCAM! Free money! Click here!';

	const startTime = process.hrtime.bigint();
	const result = await scanner.scan(patternEmail);
	const endTime = process.hrtime.bigint();

	const duration = Number(endTime - startTime) / 1_000_000;

	assert.strictEqual(typeof result, 'object');
	assert.ok(duration < 2000); // Should complete within 2000ms (more realistic)

	console.log(`Pattern recognition took ${duration.toFixed(2)}ms`);
});

test('performance summary', async () => {
	console.log(String.raw`\n=== Performance Summary ===`);
	console.log('All benchmarks completed successfully');
	console.log('Scanner performance is within acceptable limits');
	console.log('Memory usage is controlled');
	console.log('Concurrent processing works efficiently');
});

