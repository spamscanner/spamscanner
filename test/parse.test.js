import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import SpamScanner, {unwrapLink} from '../src/index.js';
import {
	expandAttachments, isAttachedMessage, isDeliveryReport, namedTextParts, parseMessage, parseWithin,
} from '../src/parse.js';
import {message, SPAM} from './helpers/index.js';

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
		// (and with nothing to tell, as with none given)
		const opened = await expandAttachments(many.slice(0, 1), [], parseMessage, null);
		assert.equal(opened.length, 1);
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

describe('parts and names mail programs show as attachments', () => {
	it('takes the AMP version of a message\'s text for no attachment, unless it is one', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const amp = '<!doctype html><html amp4email><head><script async src="https://cdn.ampproject.org/v0.js"></script></head><body><form method="post" action-xhr="https://shop.example/vote"><input name="choice"></form></body></html>';
		const found = async headers => (await scanner.scan(`From: news@shop.example\r\nTo: b@example.org\r\nSubject: This week\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nThis week at the shop.\r\n--b\r\n${headers}\r\n\r\n${amp}\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>This week at the shop.</p>\r\n--b--\r\n`)).results.attachments.map(item => [item.type, item.active]);
		assert.deepEqual(await found('Content-Type: text/x-amp-html'), []);
		// (a file to open: named, marked as an attachment, or of another type)
		for (const headers of ['Content-Type: text/x-amp-html; name="page.html"', 'Content-Type: text/x-amp-html\r\nContent-Disposition: attachment', 'Content-Type: text/x-amp-html\r\nContent-Disposition: attachment; filename="page.html"', 'Content-Type: application/octet-stream']) {
			assert.deepEqual(await found(headers), [['html_attachment', true]], headers);
		}
	});

	it('inspects text parts named as files, and the other names attachments give, by name', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const head = 'From: a@example.org\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n';
		const scan = async (...parts) => scanner.scan(`${head}${parts.map(part => `--m\r\n${part}\r\n`).join('')}--m--\r\n`);
		const page = await scan('Content-Type: text/html; name="invoice.html"\r\n\r\n<p>sign in</p>');
		assert.deepEqual(page.results.attachments.map(item => [item.type, item.filename]), [['html_attachment', 'invoice.html']]);
		// (as mailparser reads it, the body)
		assert.match(page.mail.html, /sign in/);
		assert.equal(page.mail.attachments.length, 0);
		assert.ok(names(await scan('Content-Type: text/plain; name="run.vbs"\r\n\r\nx')).includes('EXECUTABLE_ATTACHMENT'));
		assert.ok(names(await scan('Content-Type: text/plain\r\nContent-Disposition: inline; filename="run.js"\r\n\r\nx')).includes('EXECUTABLE_ATTACHMENT'));
		// (a name in the Content-Type other than the file name, encoded too)
		const renamed = await scan('Content-Type: application/octet-stream; name="=?utf-8?B?cnVuLmV4ZQ==?="\r\nContent-Disposition: attachment; filename="report.pdf"\r\n\r\nxx');
		assert.deepEqual(renamed.results.attachments.map(item => [item.type, item.filename]), [['executable', 'run.exe']]);
		// (and in an attached message, named after it)
		const inner = 'From: b@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=i\r\n\r\n--i\r\nContent-Type: text/plain\r\n\r\nhi\r\n--i\r\nContent-Type: text/plain; name="run.vbs"\r\n\r\nx\r\n--i--\r\n';
		const forwarded = await scan(`Content-Type: message/rfc822\r\nContent-Disposition: attachment; filename="fw.eml"\r\n\r\n${inner}`);
		assert.deepEqual(forwarded.results.attachments.map(item => [item.type, item.filename]), [['executable', 'fw.eml/run.vbs']]);
		// (and nothing for ordinary mail: plain text and HTML without names, or
		//  named as text, or a name the same as the file name)
		const ordinary = await scan('Content-Type: text/plain; name="notes.txt"\r\n\r\nx', 'Content-Type: application/pdf; name="Report.PDF"\r\nContent-Disposition: attachment; filename="report.pdf"\r\n\r\nxx');
		assert.deepEqual(ordinary.results.attachments, []);
	});

	it('reads the other name an attachment gives in its Content-Type, named after its message', async () => {
		const headers = name => new Map([['content-type', {value: 'application/octet-stream', params: name === undefined ? {} : {name}}]]);
		const named = [];
		await expandAttachments([
			{filename: 'a.pdf', headers: headers('a.exe')},
			{filename: 'b.pdf', headers: headers('B.PDF ')},
			{filename: 'c.pdf', headers: headers(' ')},
			{filename: 'd.pdf', headers: headers()},
			{filename: 'e.pdf', headers: new Map()},
			{filename: 'f.pdf'},
			{headers: headers('g.url')},
		], [], undefined, {named});
		assert.deepEqual(named.map(part => part.filename), ['a.exe', 'g.url']);
		const inner = 'From: b@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=i\r\n\r\n--i\r\nContent-Type: text/plain\r\n\r\nhi\r\n--i\r\nContent-Type: application/octet-stream; name="run.exe"\r\nContent-Disposition: attachment; filename="report.pdf"\r\n\r\nxx\r\n--i--\r\n';
		const nested = [];
		await expandAttachments([{filename: 'fw.eml', contentType: 'message/rfc822', content: Buffer.from(inner)}], [], undefined, {named: nested});
		assert.deepEqual(nested.map(part => part.filename), ['fw.eml/run.exe']);
		// (nor for a name only as Windows saves it: dots and spaces at its end)
		const same = [];
		await expandAttachments([{filename: 'a.exe', headers: headers('A.EXE. ')}], [], undefined, {named: same});
		assert.deepEqual(same, []);
		// (one of each kind of finding, of every attached message: more of a
		//  kind add nothing to the score)
		const many = `From: b@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=i\r\n\r\n${Array.from({length: 60}, (_, i) => `--i\r\nContent-Type: text/html; name="p${i}.html"\r\n\r\nx\r\n`).join('')}--i--\r\n`;
		const capped = [];
		await expandAttachments(Array.from({length: 3}, (_, i) => ({filename: `fw${i}.eml`, contentType: 'message/rfc822', content: Buffer.from(many)})), [], undefined, {named: capped});
		assert.deepEqual(capped.map(part => part.filename), ['fw0.eml/p0.html']);
		// (names that are harmless, or many of one kind, never hide another:
		//  neither in a message nor in what it carries)
		const pages = Array.from({length: 120}, (_, i) => `--i\r\nContent-Type: text/html; name="p${i}.html"\r\n\r\nx\r\n`).join('');
		const program = `From: b@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=i\r\n\r\n${pages}--i\r\nContent-Type: text/plain; name="invoice.exe"\r\n\r\nx\r\n--i--\r\n`;
		assert.deepEqual(namedTextParts(await parseMessage(program)).map(part => part.filename), ['p0.html', 'invoice.exe']);
		const notes = Array.from({length: 120}, (_, i) => `--i\r\nContent-Type: text/plain; name="note${i}.txt"\r\n\r\nx\r\n`).join('');
		const late = `From: b@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=i\r\n\r\n${notes}--i\r\nContent-Type: text/html; name="invoice.html"\r\n\r\n<form>x</form>\r\n--i--\r\n`;
		assert.deepEqual(namedTextParts(await parseMessage(late)).map(part => part.filename), ['invoice.html']);
		const harmless = [];
		await expandAttachments([
			...Array.from({length: 120}, (_, i) => ({filename: `n${i}.txt`, headers: headers(`note${i}.txt`)})),
			{filename: 'report.pdf', headers: headers('run.exe')},
		], [], undefined, {named: harmless});
		assert.deepEqual(harmless.map(part => part.filename), ['run.exe']);
		// (and files uuencoded or yEncoded into its text, not ordinary words)
		const encoded = await parseMessage('From: a@example.org\r\nContent-Type: text/plain\r\n\r\nwe begin 644 tests\r\nbegin 644 invoice.exe\r\nM35H`\r\n`\r\nend\r\n=ybegin line=128 size=4 name=notes.url\r\nxx\r\n=yend size=4\r\n');
		assert.deepEqual(namedTextParts(encoded).map(part => part.filename), ['invoice.exe', 'notes.url']);
		// (in linear time, also across line separators, which end a line for "^"
		//  and "$" but not for the characters of a line)
		const separated = `=ybegin${String.fromCodePoint(0x20_28)}`.repeat(60_000);
		const started = performance.now();
		assert.deepEqual(namedTextParts(await parseMessage(`From: a@example.org\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n${Buffer.from(separated).toString('base64')}\r\n`)), []);
		assert.ok(performance.now() - started < 2000);
		// (the first 1000 of them: one past them is not read)
		const lines = `${'begin 644 notes.txt\r\n'.repeat(1000)}begin 644 invoice.exe\r\n`;
		assert.deepEqual(namedTextParts(await parseMessage(`From: a@example.org\r\nContent-Type: text/plain\r\n\r\n${lines}`)), []);
		// (none for a message parsed otherwise)
		assert.deepEqual(namedTextParts({}), []);
	});

	it('inspects every name a part gives itself twice, whichever the parser reads', async () => {
		const message = fields => `From: a@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\n${fields}\r\n\r\nx\r\n--b--\r\n`;
		const found = async fields => {
			const mail = await parseMessage(message(fields));
			return {named: namedTextParts(mail).map(part => part.filename), read: mail.attachments[0].filename};
		};

		// (a parameter given twice, in either order; the parser reads one, by
		//  its version, and the other is inspected by name)
		for (const fields of [
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="run.vbs"; filename="notes.txt"',
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="notes.txt"; filename="run.vbs"',
			// (a field given twice)
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="run.vbs"\r\nContent-Disposition: attachment; filename="notes.txt"',
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="notes.txt"\r\nContent-Disposition: attachment; filename="run.vbs"',
			// (the name of its Content-Type, an encoded word, and one after a
			//  quoted semicolon)
			'Content-Type: application/octet-stream; name="notes.txt"; name="run.vbs"\r\nContent-Disposition: attachment',
			'Content-Type: application/octet-stream; name="run.vbs"; name="notes.txt"\r\nContent-Disposition: attachment',
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="=?UTF-8?B?cnVuLnZicw==?="; filename="notes.txt"',
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a;b.txt"; filename="run.vbs"',
			// (after a quoted quotation mark, an empty name, and a field without one)
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="a\\";b.txt"; filename="run.vbs"',
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=""; filename="run.vbs"',
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment\r\nContent-Disposition: attachment; filename="run.vbs"',
		]) {
			const {named, read} = await found(fields);
			assert.ok(read === 'run.vbs' || named.includes('run.vbs'), fields);
		}

		// (and scored as a program, whichever name the parser read)
		const scanner = new SpamScanner({classifier: false});
		for (const order of ['filename="run.vbs"; filename="notes.txt"', 'filename="notes.txt"; filename="run.vbs"']) {
			const result = await scanner.scan(message(`Content-Type: application/octet-stream\r\nContent-Disposition: attachment; ${order}`), offline);
			assert.ok(result.results.executables.some(item => item.type === 'executable' && item.filename === 'run.vbs'), order);
		}

		// (none for a part that names itself once: not the pieces of a name
		//  written in several, nor a name written both plainly and encoded)
		for (const fields of [
			'Content-Type: application/octet-stream; name="report.json"\r\nContent-Disposition: attachment; filename="report.json"',
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*0="report.js"; filename*1="on"',
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="report.json"; filename*=UTF-8\'\'report.json',
			// (twice the same)
			'Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="report.json"; filename="report.json"',
		]) {
			assert.deepEqual(await found(fields), {named: [], read: 'report.json'}, fields);
		}

		// (a part another parser made is read as far as it is one: none
		//  without its header or what reads it, none of a value that cannot
		//  be read, and a name without a type is a file's)
		const {Writable} = await import('node:stream');
		const {simpleParse} = await import('../src/parse.js');
		const twice = {get: field => (field === 'content-disposition' ? ['attachment; filename="notes.txt"; filename="run.vbs"'] : [])};
		const reads = {parseHeaderValue: value => ({params: {filename: /filename="([^"]*)"\s*$/.exec(value)[1]}}), decodeWords: value => value};
		const parser = input => new Promise(resolve => {
			const fake = new Writable({
				write(chunk, encoding, callback) {
					callback();
				},
			});
			let made = 0;
			fake.createNode = () => (++made === 1 ? undefined : {isAttachment: true});
			input.pipe(fake);
			fake.createNode({headers: twice, libmime: reads, filename: 'notes.txt'});
			fake.createNode(undefined);
			fake.createNode({headers: twice});
			fake.createNode({
				headers: twice, libmime: {
					parseHeaderValue() {
						throw new Error('unreadable');
					},
				},
			});
			resolve({text: ''});
		});
		assert.deepEqual(namedTextParts(await simpleParse('From: a@example.org\r\n\r\nhi\r\n', {parser})), [{filename: 'run.vbs', contentType: 'application/octet-stream', content: null}]);

		// (a field or a parameter given many times is read in part, in linear time)
		const started = performance.now();
		await found(`Content-Type: application/octet-stream\r\nContent-Disposition: attachment${'; filename="a.txt"'.repeat(20_000)}`);
		assert.ok(performance.now() - started < 2000);
	});
});

describe('parseWithin', () => {
	it('reads the sender of a header too large for its many short lines', async () => {
		const pads = ['a:\r\n'.repeat(20_000), 'Received: x\r\n'.repeat(20_000)];
		const message = pad => `${pad}From: bad@spammer.example\r\nSubject: win\r\n\r\nverify your bank password now\r\n`;

		// (mailsplit 5.4.25 and later, which mailparser 3.10 and later use,
		//  count each header line as at least 64 characters and fail on these;
		//  earlier versions count bytes and read them whole: the sender is read
		//  either way)
		const scanner = new SpamScanner({...offline, classifier: false, denylist: ['spammer.example']});
		for (const pad of pads) {
			const result = await scanner.scan(message(pad));
			if (result.results.parseError !== null) {
				assert.match(result.results.parseError, /header size/);
			}

			assert.ok(names(result).includes('DENYLISTED'));
			assert.equal(result.mail.subject, 'win');
		}

		// (and with a parser that counts lines so, whatever version is installed)
		const tooLarge = Object.assign(new Error('Max header size for a MIME node exceeded'), {code: 'EMAXLEN'});
		const countsLines = async input => {
			const text = input.toString('latin1');
			const header = text.slice(0, text.search(/\r?\n\r?\n/));
			if (header.split('\n').reduce((cost, line) => cost + Math.max(64, line.length + 1), 0) > 1024 * 1024) {
				throw tooLarge;
			}

			return parseMessage(input);
		};

		for (const pad of pads) {
			const {mail, error} = await parseWithin(Buffer.from(message(pad)), countsLines);
			assert.equal(error, tooLarge.message);
			assert.equal(mail.from.value[0].address, 'bad@spammer.example');
			assert.equal(mail.subject, 'win');
		}
	});

	it('reads less of a message under 1 MB whose header is too large when cutting the header down does not shorten it', async () => {
		const raw = Buffer.from(`From: a@example.org\r\nSubject: s\r\n\r\n${'body line\r\n'.repeat(100)}`);
		const tooLarge = Object.assign(new Error('Max header size for a MIME node exceeded'), {code: 'EMAXLEN'});
		const sizes = [];
		const {mail, error} = await parseWithin(raw, async input => {
			sizes.push(input.length);
			if (input.length > 200) {
				throw tooLarge;
			}

			return parseMessage(input);
		});
		assert.equal(error, tooLarge.message);
		assert.equal(mail.from.value[0].address, 'a@example.org');
		assert.ok(sizes.every((size, i) => i === 0 || size < sizes[i - 1]));
	});
});

describe('delivery status notifications', () => {
	// A mail server's report that `returned` (a message, or only its header)
	// was not delivered, in each server's own words.
	const NOTICES = {
		postfix: ['Undelivered Mail Returned to Sender', 'This is the mail system at host mx.far.example.\r\n\r\nI\'m sorry to have to inform you that your message could not\r\nbe delivered to one or more recipients. It\'s attached below.\r\n\r\nFor further assistance, please send mail to postmaster.\r\n\r\nIf you do so, please include this problem report. You can\r\ndelete your own text from the attached returned message.\r\n\r\n                   The mail system\r\n\r\n<dana@far.example>: host mail.far.example[198.51.100.7] said: 550 5.1.1\r\n    <dana@far.example>: Recipient address rejected: User unknown in virtual\r\n    mailbox table (in reply to RCPT TO command)\r\n'],
		exim: ['Mail delivery failed: returning message to sender', 'This message was created automatically by mail delivery software.\r\n\r\nA message that you sent could not be delivered to one or more of its\r\nrecipients. This is a permanent error. The following address(es) failed:\r\n\r\n  dana@far.example\r\n    host mail.far.example [198.51.100.7]\r\n    SMTP error from remote mail server after RCPT TO:<dana@far.example>:\r\n    550 5.1.1 User unknown\r\n'],
		sendmail: ['Returned mail: see transcript for details', 'The original message was received at Tue, 17 Nov 2026 10:00:01 GMT\r\nfrom mail.customer.example [192.0.2.10]\r\n\r\n   ----- The following addresses had permanent fatal errors -----\r\n<dana@far.example>\r\n    (reason: 550 5.1.1 User unknown)\r\n\r\n   ----- Transcript of session follows -----\r\n... while talking to mail.far.example.:\r\n>>> DATA\r\n<<< 550 5.1.1 User unknown\r\n550 5.1.1 <dana@far.example>... User unknown\r\n'],
	};
	const report = (server, returned, type = 'message/rfc822') => {
		const [subject, notice] = NOTICES[server];
		return `Return-Path: <>\r\nFrom: Mail Delivery System <MAILER-DAEMON@mx.far.example>\r\nTo: sam@customer.example\r\nSubject: ${subject}\r\nDate: ${new Date().toUTCString()}\r\nMessage-ID: <b1@mx.far.example>\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n${notice}\r\n--b\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.far.example\r\n\r\nFinal-Recipient: rfc822; dana@far.example\r\nAction: failed\r\nStatus: 5.1.1\r\nDiagnostic-Code: smtp; 550 5.1.1 User unknown\r\n\r\n--b\r\nContent-Type: ${type}\r\n\r\n${returned}\r\n--b--\r\n`;
	};

	const ordinary = message({from: 'Sam <sam@customer.example>', subject: 'Notes from Tuesday', text: 'Hi Dana,\n\nAttached are the notes from Tuesday\'s planning meeting. Could you look over section two before Friday and tell me whether the timeline still works for your team?\n\nThanks,\nSam\n'});
	const [, spamSubject, spamText] = SPAM.find(([language]) => language === 'en') ?? SPAM[0];
	const spam = message({from: 'Offers <win@promo-deals.example>', subject: spamSubject, text: spamText});

	it('tells a delivery status notification by its type', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const is = async raw => isDeliveryReport((await scanner.parse(raw)).mail);
		assert.equal(await is(report('postfix', ordinary)), true);
		assert.equal(await is(report('postfix', ordinary).replace('multipart/report; report-type=delivery-status', 'Multipart/Report; Report-Type="Delivery-Status"')), true);
		for (const type of ['multipart/report; report-type=disposition-notification', 'multipart/report; report-type=feedback-report', 'multipart/report', 'multipart/mixed']) {
			assert.equal(await is(report('postfix', ordinary).replace('multipart/report; report-type=delivery-status', type)), false, type);
		}

		assert.equal(await is(ordinary), false);
		assert.equal(isDeliveryReport({}), false);
		assert.equal(isDeliveryReport(), false);
	});

	it('reads the message a bounce returns, not the mail server\'s words about it', async () => {
		const scanner = new SpamScanner(offline);
		assert.ok((await scanner.scan(spam)).isSpam);
		for (const server of Object.keys(NOTICES)) {
			// (the bounce of an ordinary message is no spam)
			const bounce = await scanner.scan(report(server, ordinary));
			assert.equal(bounce.isSpam, false, `${server}: ${names(bounce).join(' ')}`);
			assert.ok(bounce.results.classification.probability < 0.5, server);
			// (the bounce of spam, sent in the recipient's name, is)
			const backscatter = await scanner.scan(report(server, spam));
			assert.equal(backscatter.isSpam, true, server);
			assert.equal(backscatter.results.classification.probability, (await scanner.scan(spam)).results.classification.probability, server);
			// (and with only the header returned, or nothing, the classifier
			//  has no say)
			for (const partial of [report(server, 'From: Sam <sam@customer.example>\r\nSubject: Notes from Tuesday\r\n', 'text/rfc822-headers'), report(server, '').replace(/--b\r\nContent-Type: message\/rfc822[\s\S]*$/, '--b--\r\n')]) {
				const result = await scanner.scan(partial);
				assert.equal(result.results.classification.category, 'unsure', server);
				assert.equal(result.isSpam, false, server);
			}
		}
	});

	it('still checks everything else in a bounce, and reads any other message as it is', async () => {
		const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(0x3A), Buffer.from([0x40, 0, 0, 0]), Buffer.from('PE\0\0')]);
		const scanner = new SpamScanner(offline);
		// (a program in the message returned)
		const carried = await scanner.scan(report('postfix', message({subject: 'Notes', text: 'See the attachment.', attachments: [{filename: 'notes.exe', content: exe}]})));
		assert.ok(names(carried).includes('EXECUTABLE_ATTACHMENT'));
		// (a message that only says it is a bounce is read whole: the same
		//  words in a message of another type, and as one forwarded)
		const [subject, notice] = NOTICES.postfix;
		const plain = await scanner.scan(message({from: 'MAILER-DAEMON@mx.far.example', subject, text: `${notice}\n${spamText}`}));
		assert.ok(plain.results.classification.probability > 0.9);
		const forwarded = await scanner.scan(report('postfix', ordinary).replace('multipart/report; report-type=delivery-status;', 'multipart/mixed;').replace(notice, spamText));
		assert.ok(forwarded.results.classification.probability > 0.9);
		// (and so is a notification whose own text links somewhere, which a
		//  mail server's does not: its type is no way around the classifier)
		const linked = report('postfix', ordinary).replace(notice, `${spamText}\r\nhttps://promo-deals.example/claim\r\n`);
		assert.ok((await scanner.scan(linked)).results.classification.probability > 0.9);
	});
});
