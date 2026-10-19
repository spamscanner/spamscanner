import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import {simpleParser} from 'mailparser';
import {rewriteMessage, taggedSubject} from '../src/headers.js';
import {cpuTime} from './helpers/cpu-time.js';

const ENCODED_WORD = /=\?UTF-8\?B\?([A-Za-z\d+/]*={0,2})\?=/g;
const base64 = text => Buffer.from(text, 'utf8').toString('base64');

// The Subject field of a rewritten message, its lines, and the subject a mail
// client reads from it
async function tagged(message, subjectTag) {
	const out = rewriteMessage(message, [], {subjectTag}).toString('latin1');
	const head = out.slice(0, out.indexOf('\r\n\r\n'));
	const field = head.match(/^Subject:.*(?:\r\n[ \t].*)*/m)?.[0] ?? null;
	return {
		out, field, lines: field?.split('\r\n') ?? [], subject: (await simpleParser(out)).subject,
	};
}

describe('rewriteMessage', () => {
	it('keeps an mbox "From " line first, as procmail passes a message', () => {
		const out = rewriteMessage('From a@example.org Sat Oct 17 10:00:00 2026\nFrom: a@example.org\nSubject: Hi\n\nbody\n', [['X-Spam-Flag', 'NO']], {subjectTag: '[SPAM]'}).toString();
		assert.equal(out, 'From a@example.org Sat Oct 17 10:00:00 2026\nX-Spam-Flag: NO\nFrom: a@example.org\nSubject: [SPAM] Hi\n\nbody\n');
	});

	it('adds headers at the top of a message with no headers, before its body', () => {
		assert.equal(rewriteMessage('\r\nbody\r\n', [['X-Spam-Flag', 'YES']], {subjectTag: '[SPAM]'}).toString(), 'X-Spam-Flag: YES\r\nSubject: [SPAM]\r\n\r\nbody\r\n');
		assert.equal(rewriteMessage('\nbody\n', [], {subjectTag: '[SPAM]'}).toString(), 'Subject: [SPAM]\n\nbody\n');
		// (and, adding none, leaves it as it is)
		assert.equal(rewriteMessage('\r\nbody').toString(), '\r\nbody');
	});
});

describe('subject tags (RFC 2047)', () => {
	const message = (subject = 'Subject: Hello\r\n') => `From: a@example.org\r\nTo: b@example.org\r\n${subject}\r\nbody\r\n`;

	it('splits a long tag into encoded words of at most 75 characters, between whole characters', async () => {
		for (const tag of [`[${'垃圾'.repeat(40)}]`, '🚫'.repeat(30), `[${'é'.repeat(100)} spam]`]) {
			const {field, lines, subject} = await tagged(message(), tag);
			const words = [...field.matchAll(ENCODED_WORD)];
			assert.ok(words.length > 1, tag);
			for (const [word, data] of words) {
				assert.ok(word.length <= 75, word);
				// (each word whole UTF-8: decoded and encoded again, the same bytes)
				const bytes = Buffer.from(data, 'base64');
				assert.deepEqual(Buffer.from(bytes.toString('utf8'), 'utf8'), bytes, word);
			}

			assert.equal(words.map(([, data]) => Buffer.from(data, 'base64').toString('utf8')).join(''), tag);
			for (const line of lines) {
				assert.ok(line.length <= 76, line);
			}

			assert.equal(subject, `${tag} Hello`);
		}
	});

	it('encodes a tag of ASCII that holds "=?", or a word too long to fold', async () => {
		const {field, subject} = await tagged(message(), '[=?SPAM?=]');
		assert.equal(field, `Subject: =?UTF-8?B?${base64('[=?SPAM?=]')}?= Hello`);
		assert.equal(subject, '[=?SPAM?=] Hello');
		const long = `[${'X'.repeat(2000)}]`;
		const folded = await tagged(message(), long);
		for (const line of folded.lines) {
			assert.ok(line.length <= 76, line);
		}

		assert.equal(folded.subject, `${long} Hello`);
		// (a plain tag is written as it is)
		assert.equal((await tagged(message(), '[SPAM] [bulk]')).field, 'Subject: [SPAM] [bulk] Hello');
	});

	it('leaves a space between an encoded tag and an encoded subject', async () => {
		const {field, subject} = await tagged(message(`Subject: =?UTF-8?B?${base64('Hello')}?=\r\n`), '[垃圾]');
		assert.equal(subject, '[垃圾] Hello');
		assert.equal(field, `Subject: =?UTF-8?B?${base64('[垃圾] ')}?= =?UTF-8?B?${base64('Hello')}?=`);
		// (and tags it once)
		const again = rewriteMessage(rewriteMessage(message(`Subject: =?UTF-8?B?${base64('Hello')}?=\r\n`), [], {subjectTag: '[垃圾]'}), [], {subjectTag: '[垃圾]'}).toString('latin1');
		assert.equal((await simpleParser(again)).subject, '[垃圾] Hello');
	});

	it('reads only an encoded word as one, before deciding on the space after a tag', async () => {
		// (a subject that starts with "=?" but no encoded word keeps the space
		//  after the tag shown)
		const {subject} = await tagged(message('Subject: =?not an encoded word\r\n'), '[垃圾]');
		assert.equal(subject, '[垃圾] =?not an encoded word');
		// (and one that starts with an encoded word, as a decoder reads it,
		//  whatever follows it, keeps the space inside the encoded tag)
		for (const [current, decoded] of [['=?UTF-8?B?0J/RgNC40LLQtdGC?=,', 'Привет,'], ['=?UTF-8?B?QQ==?==?UTF-8?B?Qg==?=', 'AB'], ['=?x?q?a b?=', 'a b']]) {
			const {subject} = await tagged(message(`Subject: ${current}\r\n`), '[垃圾]');
			assert.equal(subject, `[垃圾] ${decoded}`, current);
		}
	});

	it('folds a plain tag before an encoded subject within 76 characters', async () => {
		const word = `=?UTF-8?B?${base64('é'.repeat(22))}?=`;
		const value = taggedSubject('[SPAM]', word);
		assert.equal(value, `[SPAM]\r\n ${word}`);
		for (const line of `Subject: ${value}`.split('\r\n')) {
			assert.ok(line.length <= 76, `${line.length}`);
		}

		const {subject} = await tagged(message(`Subject: ${word}\r\n`), '[SPAM]');
		assert.equal(subject, `[SPAM] ${'é'.repeat(22)}`);
	});

	it('looks for encoded words in a long subject in linear time', () => {
		const time = subject => {
			const started = cpuTime();
			taggedSubject('[SPAM]', subject);
			return cpuTime() - started;
		};

		for (const make of [n => '=?'.repeat(n), n => '=?a'.repeat(n), n => `=?${'a'.repeat(n)}`, n => '=?a?b?'.repeat(n)]) {
			const fastest = subject => Math.min(time(subject), time(subject), time(subject));
			const small = fastest(make(20_000));
			const large = fastest(make(80_000));
			assert.ok(large < 8 * Math.max(small, 5), `${Math.round(small)}ms, then ${Math.round(large)}ms`);
		}
	});

	it('adds nothing for a tag empty after cleanup, and no space after a tag on an empty subject', async () => {
		for (const tag of ['   ', '\r\n\t', '\u0000']) {
			assert.equal((await tagged(message(''), tag)).field, null, JSON.stringify(tag));
			assert.equal((await tagged(message(), tag)).field, 'Subject: Hello', JSON.stringify(tag));
		}

		assert.equal((await tagged(message('Subject:\r\n'), '[SPAM]')).field, 'Subject: [SPAM]');
		assert.equal((await tagged(message(''), '[垃圾]')).field, `Subject: =?UTF-8?B?${base64('[垃圾]')}?=`);
	});

	it('keeps every line of a long tagged subject within 998 octets', async () => {
		const long = 'word'.repeat(247);
		for (const tag of ['[SPAM]', '[垃圾]']) {
			const {lines, subject} = await tagged(message(`Subject: ${long}\r\n`), tag);
			assert.equal(lines.length, 2, tag);
			for (const line of lines) {
				assert.ok(Buffer.byteLength(line, 'latin1') <= 998, `${line.length}`);
			}

			assert.equal(subject, `${tag} ${long}`);
		}

		// (a folded tag over a folded subject, tagged once)
		const tag = `[${'垃圾'.repeat(40)}]`;
		const once = rewriteMessage(message('Subject: Hello\r\n there\r\n'), [], {subjectTag: tag});
		assert.deepEqual(rewriteMessage(once, [], {subjectTag: tag}), once);
		assert.equal((await simpleParser(once)).subject, `${tag} Hello there`);
	});
});
