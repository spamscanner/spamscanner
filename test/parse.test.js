import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import SpamScanner, {unwrapLink} from '../src/index.js';
import {expandAttachments, isAttachedMessage, parseMessage} from '../src/parse.js';

const offline = {phishing: {cloudflare: false}};
const names = result => result.tests.map(test => test.name);

// A message of `count` MIME parts.
const parts = count => {
	let raw = 'From: a@example.com\r\nTo: b@example.org\r\nSubject: many parts\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n';
	for (let i = 0; i < count; i++) {
		raw += `--b\r\nContent-Type: application/pdf; name="r${i}.pdf"\r\nContent-Disposition: attachment; filename="r${i}.pdf"\r\n\r\n%PDF-1.4\r\n`;
	}

	return `${raw}--b--\r\n`;
};

describe('what a message is read in part for', () => {
	it('says the parser\'s limit a message it parses is past, as scan() does', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const many = await scanner.parse(parts(1001));
		assert.match(many.error, /child nodes/);
		assert.ok(many.mail.attachments.length > 900);
		assert.equal((await scanner.parse(parts(999))).error, null);
		assert.equal((await scanner.parse('Subject: hi\r\n\r\nbody')).error, null);
		// (and reads a link's address as the scanner does, for integrators)
		assert.equal(unwrapLink('https://www.example.org/x').hostname, 'www.example.org');
	});

	it('lists the attached messages it does not open, past its limits, without scoring them', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		// (each with a boundary of its own)
		const attach = (inner, name) => [
			`Content-Type: multipart/mixed; boundary=${name}`,
			'',
			`--${name}`,
			'Content-Type: text/plain',
			'',
			'See attached.',
			`--${name}`,
			`Content-Type: message/rfc822; name="${name}"`,
			`Content-Disposition: attachment; filename="${name}"`,
			'',
			inner,
			`--${name}--`,
			'',
		].join('\r\n');
		// (four attached in one another: the innermost, with a program, not
		//  opened)
		let nested = 'From: a@example.org\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\nContent-Type: application/octet-stream; name="run.exe"\r\nContent-Disposition: attachment; filename="run.exe"\r\n\r\nMZ\r\n--inner--\r\n';
		for (let depth = 4; depth > 0; depth--) {
			nested = `From: a@example.org\r\nSubject: level ${depth}\r\n${attach(nested, `m${depth}.eml`)}`;
		}

		const deep = await scanner.scan(nested);
		assert.deepEqual(deep.results.unopenedAttachments, [{filename: 'm1.eml/m2.eml/m3.eml/m4.eml', reason: 'nested more than 3 deep'}]);
		assert.ok(!names(deep).includes('MIME_TOO_COMPLEX'));
		assert.equal(deep.results.parseError, null);
		// (three deep, every one opened)
		let shallow = 'From: a@example.org\r\nSubject: inner\r\n\r\nhi\r\n';
		for (let depth = 3; depth > 0; depth--) {
			shallow = `From: a@example.org\r\nSubject: level ${depth}\r\n${attach(shallow, `m${depth}.eml`)}`;
		}

		assert.deepEqual((await scanner.scan(shallow)).results.unopenedAttachments, []);
		// (more attachments in attached messages than are read: once)
		let files = '';
		for (let i = 0; i < 101; i++) {
			files += `--c\r\nContent-Type: text/plain; name="f${i}.txt"\r\nContent-Disposition: attachment; filename="f${i}.txt"\r\n\r\n${i}\r\n`;
		}

		const wide = await scanner.scan(`From: a@example.org\r\nSubject: wide\r\n${attach(`From: b@example.org\r\nContent-Type: multipart/mixed; boundary=c\r\n\r\n${files}--c--\r\n`, 'files.eml')}`);
		assert.deepEqual(wide.results.unopenedAttachments, [{filename: 'files.eml', reason: 'more than 100 attachments in attached messages'}]);
		// (and those past the size attached messages are read within)
		const unopened = [];
		await expandAttachments([{filename: 'big.eml', contentType: 'message/rfc822', content: Buffer.alloc(26 * 1024 * 1024, 'a')}], [], parseMessage, unopened);
		assert.deepEqual(unopened, [{filename: 'big.eml', reason: 'past 25 MB of attached messages'}]);
		// (and past the attached messages opened in all, at every level)
		const many = Array.from({length: 101}, (_, i) => ({filename: `m${i}.eml`, contentType: 'message/rfc822', content: Buffer.from('From: a@example.org\r\nSubject: hi\r\n\r\nhi\r\n')}));
		const past = [];
		await expandAttachments(many, [], parseMessage, past);
		assert.deepEqual(past, [{filename: 'm100.eml', reason: 'more than 100 attached messages'}]);
	});

	it('opens an attached message/global (RFC 6532) as it opens message/rfc822', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const inner = 'From: a@example.org\r\nSubject: inner\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\nContent-Type: application/octet-stream; name="run.exe"\r\nContent-Disposition: attachment; filename="run.exe"\r\n\r\nMZ\r\n--inner--\r\n';
		const encoded = Buffer.from(inner).toString('base64');
		for (const [type, encoding, body] of [
			['message/global', '', inner],
			['message/global', 'Content-Transfer-Encoding: base64\r\n', encoded],
			['application/octet-stream; name="fw.u8msg"', 'Content-Transfer-Encoding: base64\r\n', encoded],
		]) {
			const result = await scanner.scan(`From: b@example.org\r\nSubject: fw\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=o\r\n\r\n--o\r\nContent-Type: text/plain\r\n\r\nsee\r\n--o\r\nContent-Type: ${type}\r\n${encoding}\r\n${body}\r\n--o--\r\n`);
			assert.ok(result.results.executables.some(item => item.filename.endsWith('run.exe')), type);
		}

		assert.ok(isAttachedMessage({contentType: 'Message/Global'}));
		assert.ok(isAttachedMessage({filename: 'FW.EML'}));
		assert.ok(!isAttachedMessage({contentType: 'text/plain', filename: 'notes.txt'}));
		assert.ok(!isAttachedMessage({}));
	});
});
