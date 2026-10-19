import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {generateKeyPairSync} from 'node:crypto';
import {describe, it} from 'node:test';
import {dkimSign} from 'mailauth/lib/dkim/sign.js';
import {simpleParser} from 'mailparser';
import {authenticate} from '../src/auth.js';
import SpamScanner from '../src/index.js';
import {
	boundedForAuth, parseMessage, parseWithin, unfoldHeaders,
} from '../src/parse.js';
import {cpuTime} from './helpers/cpu-time.js';

const offline = {phishing: {cloudflare: false}};
const names = result => result.tests.map(test => test.name);

describe('address fields', () => {
	// A header field of `unit` again and again, `size` characters, folded.
	const field = (name, unit, size) => `${name}: ${unit.repeat(Math.ceil(size / unit.length)).replaceAll(/.{76}/g, '$&\r\n ')}\r\n`;
	const unresolved = async () => {
		throw Object.assign(new Error('not found'), {code: 'ENOTFOUND'});
	};

	const attach = (inner, count) => {
		const encoded = Buffer.from(inner).toString('base64').replaceAll(/.{76}/g, '$&\r\n');
		let raw = 'From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n';
		for (let i = 0; i < count; i++) {
			raw += `--b\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="m${i}.eml"\r\n\r\n${encoded}\r\n`;
		}

		return `${raw}--b--\r\n`;
	};

	it('reads address fields of a megabyte and more, of groups and of lists, in linear time', async () => {
		// (each took seconds, a minute in mailauth: addressparser reads a field
		//  again for each group nested in it, and its addresses in time that
		//  grows with the square of their number)
		const scanner = new SpamScanner({...offline, classifier: false, authentication: {resolver: unresolved}});
		for (const unit of [':', 'g:', '"g":', 'a@b,', 'a,']) {
			for (const size of [1_000_000, 4_000_000]) {
				const started = cpuTime();
				const result = await scanner.scan(`${field('From', unit, size)}Subject: x\r\n\r\nhello\r\n`, {session: {remoteAddress: '192.0.2.1'}});
				const spent = cpuTime() - started;
				assert.ok(spent < 3000, `${unit} ${size}: ${spent} ms`);
				assert.equal(result.mail.from.truncated, true);
				assert.equal(result.results.authentication.dmarc.status.result, 'fail');
			}
		}

		// (in a part's header, and in attached messages, 4 MB of them)
		const started = cpuTime();
		const part = await scanner.scan(`From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n${field('From', ':', 900_000)}Content-Type: text/plain\r\n\r\nhi\r\n--b--\r\n`);
		const attached = await scanner.scan(attach(`${field('From', 'g:', 900_000)}Subject: x\r\n\r\nhello\r\n`, 5));
		const spent = cpuTime() - started;
		assert.ok(spent < 3000, `${spent} ms`);
		assert.equal(part.mail.text, 'hi');
		assert.equal(attached.mail.from.value[0].address, 'a@example.com');
		assert.equal(attached.mail.from.truncated, undefined);
	});

	it('reads long lists of recipients as far as the limits allow, whole addresses only, and the sender whole', async () => {
		const recipients = Array.from({length: 1000}, (_, i) => `"User ${i}" <user${i}@example.com>`);
		const raw = `From: Alice <alice@example.com>\r\nTo: ${recipients.join(',\r\n ')}\r\nCc: ${recipients.slice(0, 300).join(', ')}\r\nSubject: all hands\r\n\r\nhello\r\n`;
		assert.ok(raw.length > 40_000);
		const {mail} = await parseWithin(Buffer.from(raw));
		assert.deepEqual(mail.from.value, [{address: 'alice@example.com', name: 'Alice'}]);
		assert.equal(mail.from.truncated, undefined);
		// (16 KB of the To field: each address whole, in order)
		assert.ok(mail.to.value.length > 400 && mail.to.value.length < 1000, String(mail.to.value.length));
		assert.deepEqual(mail.to.value, recipients.slice(0, mail.to.value.length).map((_, i) => ({address: `user${i}@example.com`, name: `User ${i}`})));
		assert.equal(mail.to.truncated, true);
		assert.equal(mail.cc.value.length, 300);
		assert.equal(mail.cc.truncated, undefined);
		// (and the sender is read before or after the lists)
		const after = await parseMessage(`To: ${recipients.join(', ')}\r\nCc: ${recipients.join(', ')}\r\nFrom: Alice <alice@example.com>\r\n\r\nhello\r\n`);
		assert.equal(after.from.value[0].address, 'alice@example.com');
		assert.equal(after.from.truncated, undefined);
		// (parsers of others read every address, as they always did)
		assert.equal((await simpleParser(raw)).to.value.length, 1000);
	});

	it('never reads part of an address as another address, and reads a message\'s address fields up to 64 KB', async () => {
		const filler = Array.from({length: 2000}, (_, i) => `f${i}@filler.example`).join(', ');
		const cut = (16 * 1024) - 'From: '.length - 'ceo@bank.example'.length;
		// (cut by length, a separator count, a group count, a quote, a comment
		//  and a group: no part read is part of the last address)
		for (const from of [
			`${filler.slice(0, cut - 20)}, x@y.example, ceo@bank.example.attacker.example`,
			`a@x.example, ${'b,'.repeat(2000)}ceo@bank.example`,
			`a@x.example, "q:${'q,'.repeat(10)}"${':'.repeat(5)} ; ${'g:'.repeat(20)}ceo@bank.example`,
			`a@x.example, "q\\"${'q,'.repeat(9000)} ceo@bank.example" <evil@attacker.example>`,
			`a@x.example, (${'c,'.repeat(9000)} ceo@bank.example) evil@attacker.example`,
			`a@x.example, team: ${'m@x.example, '.repeat(1500)}ceo@bank.example;`,
		]) {
			const mail = await parseMessage(`From: ${from}\r\n\r\nx\r\n`);
			const addresses = mail.from.value.flatMap(entry => entry.group ?? [entry]).map(entry => entry.address);
			assert.equal(mail.from.truncated, true);
			assert.ok(!addresses.some(address => /bank|attacker/.test(address)), addresses.at(-1));
			assert.ok(addresses.length > 0);
		}

		// (a group ended in time is kept whole)
		const group = await parseMessage(`From: team: a@x.example, b@x.example; ${'c,'.repeat(2000)}\r\n\r\nx\r\n`);
		assert.deepEqual(group.from.value[0].group.map(entry => entry.address), ['a@x.example', 'b@x.example']);
		// (64 KB in all: what comes after is empty, and a List-* field cut too)
		const lists = await parseMessage(`From: a@x.example\r\n${field('To', 'b@x.example, ', 15_000).repeat(5)}List-Unsubscribe: <mailto:u@x.example>, ${'<a@b>,'.repeat(3000)}\r\nCc: c@x.example\r\nFrom: d@x.example\r\n\r\nx\r\n`);
		assert.deepEqual(lists.from.value, []);
		assert.equal(lists.from.truncated, true);
		assert.equal(lists.to.length, 5);
		assert.deepEqual(lists.cc.value, []);
		assert.equal(lists.headers.get('list'), undefined);
		const list = await parseMessage(`List-Unsubscribe: <mailto:u@x.example>, ${'<a@b>,'.repeat(3000)}\r\n\r\nx\r\n`);
		assert.deepEqual(list.headers.get('list'), {unsubscribe: {mail: 'a@b'}});
	});

	it('gives no credit for the sender of a From field too long to read whole', async () => {
		const passed = {
			spf: {status: {result: 'pass'}, domain: 'sender.example'}, dkim: {results: [{signingDomain: 'sender.example', status: {result: 'pass', aligned: 'sender.example'}}]}, dmarc: {status: {result: 'pass'}, domain: 'sender.example'}, arc: {status: {result: 'pass'}},
		};
		const scanner = new SpamScanner({...offline, classifier: false, allowlist: ['sender.example']});
		const whole = await scanner.scan('From: a@sender.example\r\nSubject: hi\r\n\r\nhello\r\n', {authenticationResults: passed});
		assert.ok(names(whole).includes('ALLOWLISTED'));
		const cut = await scanner.scan(`From: a@sender.example, ${'b,'.repeat(3000)}c@other.example\r\nSubject: hi\r\n\r\nhello\r\n`, {authenticationResults: passed});
		assert.equal(cut.mail.from.value[0].address, 'a@sender.example');
		assert.ok(!names(cut).includes('ALLOWLISTED'));
		// (nor of one cut down in a header too large: over 512 KB, or with more
		//  From fields than are kept)
		for (const header of [
			`From: a@sender.example, ${'b,'.repeat(3000)}c@other.example\r\n${'X-Filler: x\r\n'.repeat(90_000)}`,
			`From: c@other.example\r\n${'From: a@sender.example\r\n'.repeat(101)}${'Received: from x\r\n'.repeat(60_000)}`,
		]) {
			const large = await scanner.scan(`${header}Subject: hi\r\n\r\nhello\r\n`, {authenticationResults: passed});
			assert.match(large.results.parseError, /header size/);
			assert.equal(large.mail.from.value[0].address, 'a@sender.example');
			assert.equal(large.mail.from.truncated, true);
			assert.ok(!names(large).includes('ALLOWLISTED'));
		}

		const fine = await scanner.scan(`From: a@sender.example\r\n${'X-Filler: x\r\n'.repeat(90_000)}Subject: hi\r\n\r\nhello\r\n`, {authenticationResults: passed});
		assert.equal(fine.mail.from.truncated, undefined);
		assert.ok(names(fine).includes('ALLOWLISTED'));
	});

	it('gives mailauth the header it reads, cut down when it would take it too long', async () => {
		const plain = Buffer.from('From: a@x.example\r\nSubject: hi\r\n\r\nbody');
		assert.equal(boundedForAuth(plain).raw, plain);
		assert.equal(boundedForAuth(Buffer.from('From: a@x.example')).fromCut, false);
		assert.equal(boundedForAuth(Buffer.from('\r\n\r\nbody')).fromCut, false);
		// (where mailauth finds the header's end and its fields)
		const bare = boundedForAuth(Buffer.from(`From: a@x.example, ${'b,'.repeat(2500)}\n\tc@x.example\nSubject: hi\n\nbody\n`));
		assert.equal(bare.raw.toString(), `From: a@x.example, ${'b,'.repeat(1998)}b\r\nSubject: hi\r\n\r\nbody\n`);
		assert.equal(bare.fromCut, true);
		const returnPath = boundedForAuth(Buffer.from(`Return-Path: <a@x.example>, ${'b,'.repeat(2500)}\r\nFrom: a@x.example\r\n\r\nbody`));
		assert.equal(returnPath.fromCut, false);
		assert.ok(returnPath.raw.length < 5000);
		// (folded lines unfolded, the fields kept, at most 8 DKIM signatures)
		const folded = `X-Filler: x${'\r\n x'.repeat(40_000)}\r\n${'DKIM-Signature: v=1; h=from:to\r\n'.repeat(12)}Subject: hi\r\n folded\r\nFrom: a@x.example\r\n\r\nbody`;
		const reduced = boundedForAuth(Buffer.from(folded));
		assert.equal(reduced.raw.toString(), `${'DKIM-Signature: v=1; h=from:to\r\n'.repeat(8)}Subject: hi folded\r\nFrom: a@x.example\r\n\r\nbody`);
		assert.equal(reduced.fromCut, false);
		const fromLeftOut = boundedForAuth(Buffer.from(`From: c@other.example\r\n${'From: a@x.example\r\n'.repeat(100)}DKIM-Signature: h=${'x:'.repeat(20_000)}\r\n${'X: y\r\n'.repeat(1000)}\r\nbody`));
		assert.equal(fromLeftOut.fromCut, true);
		assert.ok(fromLeftOut.raw.length < 12_000);
		// (a DMARC pass for what mailauth did not read is a failure)
		const started = cpuTime();
		const result = await authenticate(`From: a@x.example, ${'b,'.repeat(2500)}evil@attacker.example\r\n${folded}`, {ip: '192.0.2.1', resolver: unresolved});
		assert.ok(cpuTime() - started < 2000);
		assert.deepEqual(result.dmarc.status, {result: 'fail', comment: 'From field too long to read whole'});
		assert.equal(result.headers, '');
	});

	it('leaves signed To and Cc fields whole for authentication, however long, so a signature over them holds', async () => {
		const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
		const key = publicKey.export({type: 'spki', format: 'der'}).toString('base64');
		const resolver = async (name, type) => {
			if (type === 'TXT' && name === 's1._domainkey.example.com') {
				return [[`v=DKIM1; k=rsa; p=${key}`]];
			}

			if (type === 'TXT' && name === '_dmarc.example.com') {
				return [['v=DMARC1; p=reject']];
			}

			throw Object.assign(new Error('not found'), {code: 'ENOTFOUND'});
		};

		for (const canonicalization of ['relaxed/relaxed', 'simple/simple']) {
			// (2500 recipients: over 80 KB, past every bound of address fields)
			const to = Array.from({length: 2500}, (_, i) => `user${i}@recipients.example`).join(',\r\n ');
			const message = `From: alice@example.com\r\nTo: ${to}\r\nCc: ${to}\r\nSubject: hi\r\nDate: Mon, 19 Oct 2026 10:00:00 +0000\r\nMessage-ID: <x@example.com>\r\n\r\nhello\r\n`;

			const {signatures} = await dkimSign(message, {
				signTime: new Date(), canonicalization, signatureData: [{
					signingDomain: 'example.com', selector: 's1', privateKey: privateKey.export({type: 'pkcs8', format: 'pem'}), headerList: ['from', 'to', 'cc', 'subject', 'date', 'message-id'],
				}],
			});
			const signed = Buffer.from(signatures + message);
			assert.equal(boundedForAuth(signed).raw, signed, canonicalization);

			const result = await authenticate(signed, {
				ip: '198.51.100.9', sender: 'alice@example.com', helo: 'mail.example.com', resolver,
			});
			assert.equal(result.dkim.results[0].status.result, 'pass', canonicalization);
			assert.equal(result.dmarc.status.result, 'pass', canonicalization);
		}
	});
});

describe('header fields', () => {
	it('reads fields folded on many lines quickly, in every part and attached message inline, as they read folded', async () => {
		// (mailparser before 3.9.30 took seconds on a field of a megabyte
		//  folded on thousands of lines, in the message's header or a part's)
		const fold = (name, count) => `${name}: ${Array.from({length: count}, (_, i) => `w${i}`).join('\r\n \t')}\r\n`;
		const subject = Array.from({length: 300}, (_, i) => `w${i}`).join(' ');
		assert.equal(unfoldHeaders(Buffer.from(`${fold('Subject', 256)}\r\n${fold('X', 300)}`)).toString(), `${fold('Subject', 256)}\r\n${fold('X', 300)}`);
		const unfolded = unfoldHeaders(Buffer.from(`${fold('Subject', 300)}\r\nhi\r\n`)).toString();
		assert.equal(unfolded, `Subject: ${subject}\r\n\r\nhi\r\n`);
		assert.equal(unfoldHeaders(Buffer.from(fold('Subject', 300))).toString(), `Subject: ${subject}\r\n`);
		assert.equal((await parseMessage(`${fold('Subject', 300)}\r\nhi\r\n`)).subject, (await simpleParser(`${fold('Subject', 300)}\r\nhi\r\n`)).subject);
		// (in parts, after a quoted boundary, in a part's header ended by the
		//  next part, in an attached message inline and in its parts; not in
		//  bodies, an attached message encoded nor after the last part)
		const mixed = [
			' lead\r\nContent-Type: multipart/mixed; boundary="a\\"b"; name="x; boundary=c"\r\nContent-Type: text/plain\r\n\r\n',
			'--c\n',
			fold('X-Body', 300),
			'\r\n',
			'--a"b\r\n',
			fold('X-Ended', 300),
			'--a"b\r\nContent-Type: message/rfc822\r\nContent-Disposition: inline\r\nContent-Transfer-Encoding: 7bit (plain)\r\n\r\n',
			fold('Subject', 300),
			'Content-Type: multipart/alternative; boundary=in\r\n\r\n',
			'--in\r\n',
			fold('Subject', 300),
			'\r\nhi\r\n--in--',
			'\r\n',
			fold('X-Epilogue', 300),
			'--a"b\r\nContent-Type: message/rfc822\r\nContent-Disposition: inline; junk\r\nContent-Transfer-Encoding: base64\r\n\r\n',
			fold('X-Encoded', 300),
			'--a"b-\r\n',
			fold('X-Body', 300),
			'--a"b---\r\n',
			fold('X-Body', 300),
			'--a"b--\r\n',
			fold('X-After', 300),
			'--a"b\r\n',
			fold('X-After', 300),
			'--a"b',
		].join('');
		const read = unfoldHeaders(Buffer.from(mixed)).toString();
		assert.deepEqual(['X-Body', 'X-Ended', 'Subject', 'X-Epilogue', 'X-Encoded', 'X-After'].map(name => read.split(`${name}: w0 w1`).length - 1), [0, 1, 2, 0, 0, 0]);
		assert.deepEqual(['X-Body', 'X-Epilogue', 'X-Encoded', 'X-After'].map(name => read.split(`${name}: w0\r\n \tw1`).length - 1), [3, 1, 1, 2]);
		// (as quickly with every version)
		const started = cpuTime();
		const part = await parseMessage(`From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n${fold('Subject', 100_000)}\r\nhi\r\n--b--\r\n`);
		const whole = await parseMessage(`${fold('Subject', 100_000)}\r\nhi\r\n`);
		assert.ok(cpuTime() - started < 3000, `${cpuTime() - started} ms`);
		assert.equal(part.text, 'hi');
		assert.equal(whole.subject.split(' ').length, 100_000);
	});

	it('reads the last value of a field read once given more than once, with every mailparser', async () => {
		const mail = await parseMessage('From: a@example.com\r\nFrom: b@example.com\r\nSubject: one\r\nSubject:\r\nImportance: high\r\nX-Priority: 5\r\nPrecedence:\r\nPrecedence:\r\n\r\nhi\r\n');
		assert.deepEqual([mail.from.value[0].address, mail.subject, mail.headers.get('priority'), mail.headers.has('precedence')], ['b@example.com', 'one', 'low', false]);
	});
});
