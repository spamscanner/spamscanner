import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import {simpleParser} from 'mailparser';
import ArfParser, {
	VALID_FEEDBACK_TYPES, create, isArfMessage, parse, parseReportFields, tryParse,
} from '../src/arf.js';

const original = 'From: spammer@example.biz\r\nTo: victim@example.org\r\nSubject: Buy now\r\n\r\nSpam body mentioning --boundary text\r\n';

function report({fields, encoding, originalType = 'message/rfc822', originalBody = original, contentType} = {}) {
	const body = fields ?? 'Feedback-Type: abuse\r\nUser-Agent: TestFBL/1.0\r\nVersion: 1\r\n';
	return [
		'From: fbl@example.net',
		'To: abuse@example.com',
		'Subject: Feedback report',
		'MIME-Version: 1.0',
		`Content-Type: ${contentType ?? 'multipart/report; report-type=feedback-report; boundary="b1"'}`,
		'',
		'--b1',
		'Content-Type: text/plain',
		'',
		'This is an email abuse report.',
		'--b1',
		'Content-Type: message/feedback-report',
		...(encoding ? [`Content-Transfer-Encoding: ${encoding}`] : []),
		'',
		encoding === 'base64' ? Buffer.from(body).toString('base64') : body,
		'--b1',
		`Content-Type: ${originalType}`,
		'',
		originalBody,
		'--b1--',
		'',
	].join('\r\n');
}

describe('ARF reports', () => {
	it('parses every field of a report, with folded lines and repeated fields', async () => {
		const result = await parse(report({
			fields: [
				'Feedback-Type: Abuse',
				'User-Agent: TestFBL/1.0',
				'User-Agent: Second/2.0',
				'Version: 1',
				'Arrival-Date: Mon, 05 Oct 2026 09:30:00 +0000',
				'Source-IP: [192.0.2.1]',
				'Original-Mail-From: <spammer@example.biz>',
				'Original-Rcpt-To: <a@example.org>',
				'Original-Rcpt-To: b@example.org',
				'Original-Envelope-Id: abc123',
				'Reporting-MTA: dns; mx.example.net',
				'Authentication-Results: mx.example.net;',
				' spf=fail smtp.mailfrom=example.biz',
				'Reported-Domain: example.biz',
				'Reported-Uri: http://example.biz/buy',
				'Incidents: 3',
				'',
			].join('\r\n'),
		}));
		assert.equal(result.isArf, true);
		assert.equal(result.feedbackType, 'abuse');
		assert.equal(result.userAgent, 'TestFBL/1.0');
		assert.equal(result.arrivalDate.toISOString(), '2026-10-05T09:30:00.000Z');
		assert.equal(result.sourceIp, '192.0.2.1');
		assert.equal(result.originalMailFrom, 'spammer@example.biz');
		assert.deepEqual(result.originalRcptTo, ['a@example.org', 'b@example.org']);
		assert.equal(result.originalEnvelopeId, 'abc123');
		assert.deepEqual(result.reportingMta, {type: 'dns', name: 'mx.example.net'});
		assert.deepEqual(result.authenticationResults, ['mx.example.net; spf=fail smtp.mailfrom=example.biz']);
		assert.deepEqual(result.reportedDomain, ['example.biz']);
		assert.deepEqual(result.reportedUri, ['http://example.biz/buy']);
		assert.equal(result.incidents, 3);
		assert.equal(result.humanReadable, 'This is an email abuse report.');
		assert.match(result.originalMessage, /--boundary text/);
		assert.equal(result.originalHeaders.subject, 'Buy now');
	});

	it('reads base64 reports, header-only originals and minimal reports', async () => {
		const minimal = await parse(report({encoding: 'base64', originalType: 'text/rfc822-headers', originalBody: 'From: x@example.biz\r\nSubject: Hi'}));
		assert.equal(minimal.feedbackType, 'abuse');
		assert.equal(minimal.originalHeaders.subject, 'Hi');
		assert.equal(minimal.sourceIp, null);
		assert.equal(minimal.arrivalDate, null);
		assert.equal(minimal.reportingMta, null);
		assert.equal(minimal.originalMailFrom, null);
		assert.deepEqual(minimal.originalRcptTo, []);
		assert.equal(minimal.incidents, 1);
		assert.equal((await parse(Buffer.from(report()))).feedbackType, 'abuse');
	});

	it('decodes base64 and quoted-printable parts and copes with odd parts', async () => {
		const qp = report({originalBody: 'Content-Transfer-Encoding: quoted-printable\r\n\r\nFrom: x@example.biz\r\nSubject: Caf=C3=A9 sp=\r\necial =ZZ\r\n\r\nbody'}).replace('Content-Type: message/rfc822\r\n\r\nContent-Transfer-Encoding', 'Content-Type: message/rfc822\r\nContent-Transfer-Encoding');
		const decoded = await parse(qp);
		assert.equal(decoded.originalHeaders.subject, 'Café special =ZZ');
		const b64 = report({originalBody: Buffer.from('From: x@example.biz\r\nSubject: Grüße\r\n\r\nbody').toString('base64')}).replace('Content-Type: message/rfc822\r\n', 'Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n');
		assert.equal((await parse(b64)).originalHeaders.subject, 'Grüße');
		const odd = report().replace('--b1\r\nContent-Type: text/plain\r\n\r\nThis is an email abuse report.', '--b1\r\nno blank line here\r\n--b1\r\n\r\nUntyped human part');
		const result = await parse(odd);
		assert.equal(result.humanReadable, 'Untyped human part');
		const empty = report().replace('This is an email abuse report.', '   ');
		assert.equal((await parse(empty)).humanReadable, null);
		const noOriginal = report().replace(/--b1\r\nContent-Type: message\/rfc822[\s\S]*?(?=--b1--)/, '');
		const missing = await parse(noOriginal);
		assert.equal(missing.originalMessage, null);
		assert.equal(missing.originalHeaders, null);
		const noHuman = report().replace('--b1\r\nContent-Type: text/plain\r\n\r\nThis is an email abuse report.\r\n', '');
		assert.equal((await parse(noHuman)).humanReadable, null);
	});

	it('maps unknown feedback types to other and tolerates odd values', async () => {
		const result = await parse(report({
			fields: 'Feedback-Type: weird\r\nUser-Agent: X\r\nIncidents: many\r\nSource-IP: not-an-ip\r\nReporting-MTA: mx.example.net\r\nReceived-Date: garbage\r\nOriginal-Mail-From: <>\r\nOriginal-Rcpt-To: plain@example.org\r\nOriginal-Rcpt-To: nobody\r\nOriginal-Rcpt-To:  \r\nnot a field line\r\n',
		}));
		assert.equal(result.feedbackType, 'other');
		assert.equal(result.feedbackTypeOriginal, 'weird');
		assert.equal(result.incidents, 1);
		assert.equal(result.sourceIp, null);
		assert.deepEqual(result.reportingMta, {type: 'unknown', name: 'mx.example.net'});
		assert.equal(result.arrivalDate, null);
		assert.equal(result.originalMailFrom, null);
		assert.deepEqual(result.originalRcptTo, ['plain@example.org', 'nobody']);
		assert.ok(VALID_FEEDBACK_TYPES.has('not-spam'));
	});

	it('rejects messages that are not reports', async () => {
		await assert.rejects(parse(original), /Not an ARF report/);
		await assert.rejects(parse(report({contentType: 'multipart/report; report-type=delivery-status; boundary="b1"'})), /Not an ARF report/);
		await assert.rejects(parse(report({fields: 'User-Agent: X\r\n'})), /missing the Feedback-Type/);
		await assert.rejects(parse(report({fields: 'Feedback-Type: abuse\r\n'})), /missing the User-Agent/);
		const noReport = report().replace('message/feedback-report', 'text/plain');
		await assert.rejects(parse(noReport), /missing the message\/feedback-report part/);
		assert.equal(await tryParse(original), null);
		assert.equal((await tryParse(report())).feedbackType, 'abuse');
	});

	it('recognises reports from parsed messages and plain header values', async () => {
		assert.equal(isArfMessage(await simpleParser(report())), true);
		assert.equal(isArfMessage({headers: new Map([['content-type', 'multipart/report; report-type="feedback-report"']])}), true);
		assert.equal(isArfMessage({headers: new Map([['content-type', 'multipart/report']])}), false);
		assert.equal(isArfMessage({headers: new Map([['content-type', {value: 'multipart/report'}]])}), false);
		assert.equal(isArfMessage({headers: new Map()}), false);
		assert.equal(isArfMessage({headers: {}}), false);
		assert.equal(isArfMessage(null), false);
	});

	it('parses report fields directly', () => {
		assert.deepEqual(parseReportFields('Feedback-Type: abuse\nOriginal-Rcpt-To: a\nOriginal-Rcpt-To: b\nVersion: 1\nVersion: 2'), {feedback_type: 'abuse', original_rcpt_to: ['a', 'b'], version: '1'});
	});

	it('writes reports that it can read back', async () => {
		const raw = create({
			feedbackType: 'abuse', userAgent: 'SpamScanner/7', from: 'abuse@example.com', to: 'fbl@example.net', originalMessage: original, sourceIp: '192.0.2.1', originalMailFrom: 'spammer@example.biz', originalRcptTo: ['a@example.org'], arrivalDate: new Date('2026-10-05T09:30:00Z'), reportingMta: 'mx.example.com',
		});
		const result = await parse(raw);
		assert.equal(result.sourceIp, '192.0.2.1');
		assert.deepEqual(result.originalRcptTo, ['a@example.org']);
		assert.equal(result.reportingMta.name, 'mx.example.com');
		assert.equal(result.originalHeaders.subject, 'Buy now');
		const plain = await parse(create({
			feedbackType: 'not-spam', userAgent: 'x', from: 'a@example.com', to: 'b@example.net', originalMessage: Buffer.from(original),
		}));
		assert.equal(plain.feedbackType, 'not-spam');
	});

	it('refuses to write incomplete reports or values with line breaks', () => {
		assert.throws(() => create({feedbackType: 'abuse'}), /needs feedbackType/);
		assert.throws(() => create(), /needs feedbackType/);
		assert.throws(() => create({
			feedbackType: 'abuse', userAgent: 'x\r\nFeedback-Type: not-spam', from: 'a', to: 'b', originalMessage: 'm',
		}), /userAgent must not contain line breaks/);
	});

	it('keeps the object interface of earlier versions', () => {
		assert.equal(ArfParser.parse, parse);
		assert.equal(ArfParser.create, create);
	});
});
