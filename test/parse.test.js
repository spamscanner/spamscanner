import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import SpamScanner, {unwrapLink} from '../src/index.js';
import {
	expandAttachments, isAttachedMessage, namedTextParts, parseMessage, parseWithin,
} from '../src/parse.js';

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
