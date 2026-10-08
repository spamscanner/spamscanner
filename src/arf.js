import {Buffer} from 'node:buffer';
import {randomBytes} from 'node:crypto';
import {isIP} from 'node:net';
import {simpleParser} from 'mailparser';

/**
 * Feedback types from RFC 5965, RFC 6591 (auth-failure) and RFC 7489 (dmarc).
 */
export const VALID_FEEDBACK_TYPES = new Set(['abuse', 'fraud', 'virus', 'other', 'not-spam', 'auth-failure', 'dmarc']);

// Fields that may appear more than once (RFC 5965 section 3.2).
const MULTIPLE = new Set(['original_rcpt_to', 'authentication_results', 'reported_domain', 'reported_uri']);

const PARSER_OPTIONS = {
	skipHtmlToText: true, skipTextToHtml: true, skipImageLinks: true, skipTextLinks: true,
};

/**
 * Parse the fields of a message/feedback-report part. Folded lines are
 * unfolded. Fields that may repeat are arrays; for other fields the first
 * occurrence wins.
 * @param {string} content
 * @returns {Record<string, string|string[]>}
 */
export function parseReportFields(content) {
	const fields = {};
	const unfolded = String(content).replaceAll(/\r?\n[ \t]+/g, ' ');
	for (const line of unfolded.split(/\r?\n/)) {
		const match = /^([\w-]+):\s*(.*)$/.exec(line);
		if (!match) {
			continue;
		}

		const name = match[1].toLowerCase().replaceAll('-', '_');
		const value = match[2].trim();
		if (MULTIPLE.has(name)) {
			(fields[name] ||= []).push(value);
		} else if (!(name in fields)) {
			fields[name] = value;
		}
	}

	return fields;
}

function extractEmail(value) {
	if (!value) {
		return null;
	}

	const angle = /<([^>]*)>/.exec(value);
	if (angle) {
		return angle[1].trim() || null;
	}

	const plain = /[^\s@<>]+@[^\s@<>]+/.exec(value);
	return plain ? plain[0] : value.trim();
}

function parseIp(value) {
	if (!value) {
		return null;
	}

	const candidate = value.trim().replaceAll(/^\[|]$/g, '');
	return isIP(candidate) ? candidate : null;
}

function parseDate(value) {
	if (!value) {
		return null;
	}

	const date = new Date(value);
	return Number.isNaN(date.getTime()) ? null : date;
}

function parseReportingMta(value) {
	if (!value) {
		return null;
	}

	const match = /^([\w-]+);\s*(.+)$/.exec(value.trim());
	return match ? {type: match[1].toLowerCase(), name: match[2].trim()} : {type: 'unknown', name: value.trim()};
}

function decodeQuotedPrintable(text) {
	const bytes = [];
	const soft = text.replaceAll(/=\r?\n/g, '');
	for (let i = 0; i < soft.length; i++) {
		if (soft[i] === '=' && /^[\da-f]{2}$/i.test(soft.slice(i + 1, i + 3))) {
			bytes.push(Number.parseInt(soft.slice(i + 1, i + 3), 16));
			i += 2;
		} else {
			bytes.push(soft.codePointAt(i) % 256);
		}
	}

	return Buffer.from(bytes);
}

/**
 * Find a top-level MIME part by content type in a raw multipart message,
 * splitting only at boundary lines. mailparser merges inline message/rfc822
 * parts into the text, so the original message of a report is read here.
 * @param {string} raw
 * @param {string} boundary
 * @param {string[]} types
 * @returns {{type: string, content: Buffer}|null}
 */
export function findPart(raw, boundary, types) {
	const escaped = boundary.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
	const parts = raw.split(new RegExp(String.raw`\r?\n--${escaped}(?:--)?[ \t]*(?=\r?\n|$)`));
	for (const part of parts.slice(1)) {
		// A part is a header block (possibly empty), a blank line and a body.
		const match = /^\r?\n((?:[^\r\n]+\r?\n)*)\r?\n([\s\S]*)$/.exec(part);
		if (!match) {
			continue;
		}

		const headers = match[1].replaceAll(/\r?\n[ \t]+/g, ' ');
		const type = (/^content-type:\s*([^;\s]+)/im.exec(headers)?.[1] || 'text/plain').toLowerCase();
		if (!types.includes(type)) {
			continue;
		}

		const encoding = (/^content-transfer-encoding:\s*(\S+)/im.exec(headers)?.[1] || '').toLowerCase();
		let content;
		if (encoding === 'base64') {
			content = Buffer.from(match[2], 'base64');
		} else if (encoding === 'quoted-printable') {
			content = decodeQuotedPrintable(match[2]);
		} else {
			content = Buffer.from(match[2], 'latin1');
		}

		return {type, content};
	}

	return null;
}

/**
 * Whether a message parsed by mailparser is an ARF report
 * (multipart/report; report-type=feedback-report).
 * @param {object} parsed
 * @returns {boolean}
 */
export function isArfMessage(parsed) {
	const header = typeof parsed?.headers?.get === 'function' ? parsed.headers.get('content-type') : null;
	if (!header) {
		return false;
	}

	const value = typeof header === 'string' ? header : header.value;
	const type = typeof header === 'string' ? (/report-type\s*=\s*"?([\w-]+)/i.exec(header)?.[1] || '') : (header.params?.['report-type'] || '');
	return /^multipart\/report\b/i.test(String(value)) && type.toLowerCase() === 'feedback-report';
}

/**
 * Parse an ARF (RFC 5965) abuse report.
 * @param {Buffer|string} source - the raw report message
 * @returns {Promise<object>} feedbackType, userAgent, version, arrivalDate,
 *   sourceIp, originalMailFrom, originalRcptTo, reportingMta,
 *   originalEnvelopeId, authenticationResults, reportedDomain, reportedUri,
 *   incidents, humanReadable, originalMessage, originalHeaders (always an
 *   object of lowercase header name to value) and rawFeedbackReport
 * @throws {Error} when the message is not a valid ARF report
 */
export async function parse(source) {
	const parsed = await simpleParser(source, PARSER_OPTIONS);
	if (!isArfMessage(parsed)) {
		throw new Error('Not an ARF report: expected multipart/report with report-type=feedback-report');
	}

	const report = parsed.attachments.find(part => String(part.contentType).toLowerCase() === 'message/feedback-report');
	if (!report) {
		throw new Error('Invalid ARF report: missing the message/feedback-report part');
	}

	const raw = report.content.toString('utf8');
	const fields = parseReportFields(raw);
	if (!fields.feedback_type) {
		throw new Error('Invalid ARF report: missing the Feedback-Type field');
	}

	if (!fields.user_agent) {
		throw new Error('Invalid ARF report: missing the User-Agent field');
	}

	let feedbackType = fields.feedback_type.toLowerCase();
	let feedbackTypeOriginal = null;
	if (!VALID_FEEDBACK_TYPES.has(feedbackType)) {
		feedbackTypeOriginal = feedbackType;
		feedbackType = 'other';
	}

	const incidents = Number.parseInt(fields.incidents, 10);
	const result = {
		isArf: true,
		feedbackType,
		feedbackTypeOriginal,
		userAgent: fields.user_agent,
		version: fields.version || '1',
		arrivalDate: parseDate(fields.arrival_date || fields.received_date),
		sourceIp: parseIp(fields.source_ip),
		originalMailFrom: extractEmail(fields.original_mail_from),
		originalRcptTo: fields.original_rcpt_to ? fields.original_rcpt_to.map(value => extractEmail(value)).filter(Boolean) : [],
		reportingMta: parseReportingMta(fields.reporting_mta),
		originalEnvelopeId: fields.original_envelope_id || null,
		authenticationResults: fields.authentication_results || [],
		reportedDomain: fields.reported_domain || [],
		reportedUri: fields.reported_uri || [],
		incidents: Number.isFinite(incidents) && incidents > 0 ? incidents : 1,
		humanReadable: null,
		originalMessage: null,
		originalHeaders: null,
		rawFeedbackReport: raw,
	};

	const text = (Buffer.isBuffer(source) ? source : Buffer.from(String(source))).toString('latin1');
	const {boundary} = parsed.headers.get('content-type').params;
	const human = findPart(text, boundary, ['text/plain']);
	result.humanReadable = human ? human.content.toString('utf8').trim() || null : null;
	const original = findPart(text, boundary, ['message/rfc822', 'text/rfc822-headers', 'message/rfc822-headers']);
	if (original) {
		const content = original.content.toString('utf8');
		result.originalMessage = content;
		const inner = await simpleParser(original.type === 'message/rfc822' ? content : `${content.replace(/\s+$/, '')}\r\n\r\n`, PARSER_OPTIONS);
		result.originalHeaders = Object.fromEntries([...inner.headers].map(([key, value]) => [key, value]));
	}

	return result;
}

/**
 * Parse an ARF report, or return null when the message is not one.
 * @param {Buffer|string} source
 * @returns {Promise<object|null>}
 */
export async function tryParse(source) {
	try {
		return await parse(source);
	} catch {
		return null;
	}
}

function clean(value, name) {
	const text = String(value);
	if (/[\r\n]/.test(text)) {
		throw new TypeError(`${name} must not contain line breaks`);
	}

	return text;
}

/**
 * Write an ARF report.
 * @param {object} options
 * @param {string} options.feedbackType - abuse, fraud, virus, other, not-spam, ...
 * @param {string} options.userAgent
 * @param {string} options.from
 * @param {string} options.to
 * @param {string|Buffer} options.originalMessage
 * @param {string} [options.humanReadable]
 * @param {string} [options.subject]
 * @param {string} [options.sourceIp]
 * @param {string} [options.originalMailFrom]
 * @param {string[]} [options.originalRcptTo]
 * @param {Date} [options.arrivalDate]
 * @param {string} [options.reportingMta]
 * @returns {string}
 */
export function create(options = {}) {
	const {
		feedbackType, userAgent, from, to, originalMessage, humanReadable = 'This is an abuse report for a message received from your network.', subject = 'Abuse report', sourceIp, originalMailFrom, originalRcptTo = [], arrivalDate, reportingMta,
	} = options;
	if (!feedbackType || !userAgent || !from || !to || !originalMessage) {
		throw new TypeError('An ARF report needs feedbackType, userAgent, from, to and originalMessage');
	}

	const boundary = `arf-${randomBytes(12).toString('hex')}`;
	const report = [
		`Feedback-Type: ${clean(feedbackType, 'feedbackType')}`,
		`User-Agent: ${clean(userAgent, 'userAgent')}`,
		'Version: 1',
	];
	if (sourceIp) {
		report.push(`Source-IP: ${clean(sourceIp, 'sourceIp')}`);
	}

	if (originalMailFrom) {
		report.push(`Original-Mail-From: <${clean(originalMailFrom, 'originalMailFrom')}>`);
	}

	for (const rcpt of originalRcptTo) {
		report.push(`Original-Rcpt-To: <${clean(rcpt, 'originalRcptTo')}>`);
	}

	if (arrivalDate) {
		report.push(`Arrival-Date: ${arrivalDate.toUTCString()}`);
	}

	if (reportingMta) {
		report.push(`Reporting-MTA: dns; ${clean(reportingMta, 'reportingMta')}`);
	}

	return [
		`From: ${clean(from, 'from')}`,
		`To: ${clean(to, 'to')}`,
		`Date: ${new Date().toUTCString()}`,
		`Subject: ${clean(subject, 'subject')}`,
		'MIME-Version: 1.0',
		`Content-Type: multipart/report; report-type=feedback-report; boundary="${boundary}"`,
		'',
		`--${boundary}`,
		'Content-Type: text/plain; charset=utf-8',
		'Content-Transfer-Encoding: 8bit',
		'',
		humanReadable,
		'',
		`--${boundary}`,
		'Content-Type: message/feedback-report',
		'',
		...report,
		'',
		`--${boundary}`,
		'Content-Type: message/rfc822',
		'Content-Disposition: inline',
		'',
		String(originalMessage).replace(/\r?\n$/, ''),
		`--${boundary}--`,
		'',
	].join('\r\n');
}

/**
 * The ARF parser as an object, as in earlier versions.
 */
export const ArfParser = {
	isArfMessage, parse, tryParse, create,
};

export default ArfParser;
