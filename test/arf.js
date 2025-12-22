import assert from 'node:assert';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import {ArfParser, VALID_FEEDBACK_TYPES} from '../src/arf.js';

// Sample ARF message for testing
const sampleArfMessage = `From: abuse@example.com
To: abuse@isp.example.net
Date: Thu, 1 Jan 2024 00:00:00 +0000
Subject: Abuse Report
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

This is a spam report.

--boundary123
Content-Type: message/feedback-report

Feedback-Type: abuse
User-Agent: SpamScanner/1.0
Version: 1
Source-IP: 192.168.1.100
Original-Mail-From: <spammer@example.com>
Original-Rcpt-To: <victim@example.net>
Arrival-Date: Wed, 31 Dec 2023 23:59:59 +0000
Reporting-MTA: dns; mail.example.com

--boundary123
Content-Type: message/rfc822

From: spammer@example.com
To: victim@example.net
Subject: Buy our stuff!
Date: Wed, 31 Dec 2023 23:00:00 +0000

This is spam content.

--boundary123--
`;

// Non-ARF message for testing
const nonArfMessage = `From: test@example.com
To: recipient@example.net
Subject: Regular email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Content-Type: text/plain

This is a regular email, not an ARF report.
`;

// ARF message with multiple recipients
const arfMultipleRecipients = `From: abuse@example.com
To: abuse@isp.example.net
Date: Thu, 1 Jan 2024 00:00:00 +0000
Subject: Abuse Report
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="boundary456"

--boundary456
Content-Type: text/plain

Spam report for multiple recipients.

--boundary456
Content-Type: message/feedback-report

Feedback-Type: fraud
User-Agent: TestAgent/2.0
Version: 1
Source-IP: 10.0.0.1
Original-Mail-From: <scammer@bad.example>
Original-Rcpt-To: <user1@example.com>
Original-Rcpt-To: <user2@example.com>
Original-Rcpt-To: <user3@example.com>
Incidents: 5

--boundary456
Content-Type: message/rfc822

From: scammer@bad.example
To: user1@example.com
Subject: You won!

Congratulations!

--boundary456--
`;

describe('ArfParser', () => {
	describe('VALID_FEEDBACK_TYPES', () => {
		it('should contain all standard feedback types', () => {
			assert.ok(VALID_FEEDBACK_TYPES.has('abuse'));
			assert.ok(VALID_FEEDBACK_TYPES.has('fraud'));
			assert.ok(VALID_FEEDBACK_TYPES.has('virus'));
			assert.ok(VALID_FEEDBACK_TYPES.has('other'));
			assert.ok(VALID_FEEDBACK_TYPES.has('not-spam'));
			assert.ok(VALID_FEEDBACK_TYPES.has('auth-failure'));
			assert.ok(VALID_FEEDBACK_TYPES.has('dmarc'));
		});
	});

	describe('parse', () => {
		it('should parse a valid ARF message', async () => {
			const result = await ArfParser.parse(sampleArfMessage);

			assert.strictEqual(result.isArf, true);
			assert.strictEqual(result.feedbackType, 'abuse');
			assert.strictEqual(result.userAgent, 'SpamScanner/1.0');
			assert.strictEqual(result.version, '1');
			assert.strictEqual(result.sourceIp, '192.168.1.100');
			assert.strictEqual(result.originalMailFrom, 'spammer@example.com');
			assert.deepStrictEqual(result.originalRcptTo, ['victim@example.net']);
			assert.ok(result.humanReadable.includes('spam report'));
			assert.ok(result.originalMessage.includes('Buy our stuff'));
		});

		it('should parse ARF message from Buffer', async () => {
			const buffer = Buffer.from(sampleArfMessage);
			const result = await ArfParser.parse(buffer);

			assert.strictEqual(result.isArf, true);
			assert.strictEqual(result.feedbackType, 'abuse');
		});

		it('should throw for non-ARF messages', async () => {
			await assert.rejects(
				async () => ArfParser.parse(nonArfMessage),
				/Not a valid ARF message/,
			);
		});

		it('should parse multiple recipients', async () => {
			const result = await ArfParser.parse(arfMultipleRecipients);

			assert.strictEqual(result.feedbackType, 'fraud');
			assert.deepStrictEqual(result.originalRcptTo, [
				'user1@example.com',
				'user2@example.com',
				'user3@example.com',
			]);
			assert.strictEqual(result.incidents, 5);
		});

		it('should parse reporting MTA', async () => {
			const result = await ArfParser.parse(sampleArfMessage);

			assert.ok(result.reportingMta);
			assert.strictEqual(result.reportingMta.type, 'dns');
			assert.strictEqual(result.reportingMta.name, 'mail.example.com');
		});

		it('should parse arrival date', async () => {
			const result = await ArfParser.parse(sampleArfMessage);

			assert.ok(result.arrivalDate instanceof Date);
		});
	});

	describe('tryParse', () => {
		it('should return parsed result for valid ARF', async () => {
			const result = await ArfParser.tryParse(sampleArfMessage);

			assert.ok(result);
			assert.strictEqual(result.isArf, true);
			assert.strictEqual(result.feedbackType, 'abuse');
		});

		it('should return null for non-ARF messages', async () => {
			const result = await ArfParser.tryParse(nonArfMessage);

			assert.strictEqual(result, null);
		});

		it('should return null for invalid input', async () => {
			const result = await ArfParser.tryParse('not an email at all');

			assert.strictEqual(result, null);
		});
	});

	describe('create', () => {
		it('should create a valid ARF message', async () => {
			const originalMessage = `From: spammer@example.com
To: victim@example.net
Subject: Spam
Date: Thu, 1 Jan 2024 00:00:00 +0000

Spam content here.`;

			const arfMessage = ArfParser.create({
				feedbackType: 'abuse',
				userAgent: 'TestAgent/1.0',
				from: 'abuse@reporter.example',
				to: 'abuse@isp.example',
				originalMessage,
				humanReadable: 'This is a spam report.',
				sourceIp: '192.168.1.1',
				originalMailFrom: 'spammer@example.com',
				originalRcptTo: ['victim@example.net'],
				arrivalDate: new Date('2024-01-01T00:00:00Z'),
				reportingMta: 'mail.reporter.example',
			});

			// Verify the created message can be parsed
			const parsed = await ArfParser.parse(arfMessage);

			assert.strictEqual(parsed.isArf, true);
			assert.strictEqual(parsed.feedbackType, 'abuse');
			assert.strictEqual(parsed.userAgent, 'TestAgent/1.0');
			assert.strictEqual(parsed.sourceIp, '192.168.1.1');
			assert.strictEqual(parsed.originalMailFrom, 'spammer@example.com');
		});

		it('should throw for missing required fields', () => {
			assert.throws(
				() => ArfParser.create({feedbackType: 'abuse'}),
				/Missing required fields/,
			);
		});

		it('should create ARF with minimal options', async () => {
			const arfMessage = ArfParser.create({
				feedbackType: 'abuse',
				userAgent: 'MinimalAgent/1.0',
				from: 'reporter@example.com',
				to: 'abuse@isp.example',
				originalMessage: 'From: test@test.com\r\nSubject: Test\r\n\r\nTest body',
			});

			const parsed = await ArfParser.parse(arfMessage);

			assert.strictEqual(parsed.isArf, true);
			assert.strictEqual(parsed.feedbackType, 'abuse');
		});
	});

	describe('feedback types', () => {
		it('should handle virus feedback type', async () => {
			const virusArfMessage = sampleArfMessage.replace('Feedback-Type: abuse', 'Feedback-Type: virus');
			const result = await ArfParser.parse(virusArfMessage);

			assert.strictEqual(result.feedbackType, 'virus');
		});

		it('should handle not-spam feedback type', async () => {
			const notSpamArfMessage = sampleArfMessage.replace('Feedback-Type: abuse', 'Feedback-Type: not-spam');
			const result = await ArfParser.parse(notSpamArfMessage);

			assert.strictEqual(result.feedbackType, 'not-spam');
		});

		it('should handle auth-failure feedback type', async () => {
			const authFailureArfMessage = sampleArfMessage.replace('Feedback-Type: abuse', 'Feedback-Type: auth-failure');
			const result = await ArfParser.parse(authFailureArfMessage);

			assert.strictEqual(result.feedbackType, 'auth-failure');
		});

		it('should normalize unknown feedback types to other', async () => {
			const unknownArfMessage = sampleArfMessage.replace('Feedback-Type: abuse', 'Feedback-Type: custom-type');
			const result = await ArfParser.parse(unknownArfMessage);

			assert.strictEqual(result.feedbackType, 'other');
			assert.strictEqual(result.feedbackTypeOriginal, 'custom-type');
		});
	});
});
