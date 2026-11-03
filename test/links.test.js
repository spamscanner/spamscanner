import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import SpamScanner from '../src/index.js';
import {decodeEntities} from '../src/html.js';
import {carriedLinkHosts} from '../src/links.js';
import {serializeResult} from '../src/server.js';
import {message} from './helpers/index.js';

const hostsOf = (mail, options) => carriedLinkHosts(mail, options).hosts;
const card = (filename, contentType, text) => ({filename, contentType, content: Buffer.from(text)});

describe('carriedLinkHosts', () => {
	it('reads links a browser follows that extractLinks leaves out', () => {
		const html = [
			// (an anchor never closed)
			'<a href="https://open.example.com/x">click',
			// (an attribute behind a quote in a comment)
			'<!-- " --><img src="https://comment.example.com/a.png">',
			// (a ping, a refresh, a srcset, a style and an @import)
			'<a ping="https://ping.example.com/1 https://ping2.example.com/2" href="#">',
			'<meta http-equiv="refresh" content="0;url=https://refresh.example.com/">',
			'<img srcset="https://set.example.com/a.png 2x">',
			'<div style="background:url(\'https://style.example.com/b.png\')">',
			'<style>@import "https://import.example.com/c.css";</style>',
			// (scheme-relative, with character references, and with a tab in it)
			'<a href="//relative.example.com/">x</a>',
			'<a href="https&colon;//entity.example.com/">x</a>',
			'<a href="https://tab.ex\tample.com/">x</a>',
		].join('\n');
		const hosts = hostsOf({html});
		for (const host of ['open.example.com', 'comment.example.com', 'ping.example.com', 'ping2.example.com', 'refresh.example.com', 'set.example.com', 'style.example.com', 'import.example.com', 'relative.example.com', 'entity.example.com', 'tab.example.com']) {
			assert.ok(hosts.includes(host), host);
		}
	});

	it('reads documents held in others: an iframe\'s srcdoc and a data: URL\'s HTML', () => {
		const inner = '<a href="https://data.example.com/">x</a>';
		const html = [
			'<iframe srcdoc="&lt;a href=&quot;https://srcdoc.example.com/&quot;&gt;x&lt;/a&gt;"></iframe>',
			`<iframe src="data:text/html;base64,${Buffer.from(inner).toString('base64')}"></iframe>`,
			`<object data="data:image/svg+xml,${encodeURIComponent('<svg><a href="https://svg.example.com/">x</a></svg>')}"></object>`,
		].join('\n');
		const hosts = hostsOf({html});
		for (const host of ['srcdoc.example.com', 'data.example.com', 'svg.example.com']) {
			assert.ok(hosts.includes(host), host);
		}

		// (nested deeper than they are read: never read whole)
		let deep = '<a href="https://deepest.example.com/">x</a>';
		for (let i = 0; i < 5; i++) {
			deep = `<iframe srcdoc="${deep.replaceAll('&', '&amp;').replaceAll('"', '&quot;')}"></iframe>`;
		}

		assert.equal(carriedLinkHosts({html: deep}).tooComplex, true);
	});

	it('reads links in the text, also without a scheme, and the link a security gateway wraps', () => {
		const safelinks = `https://nam02.safelinks.protection.outlook.com/?url=${encodeURIComponent('https://wrapped.example.com/login')}&data=x`;
		const text = `See www.www.example.com, see evil.example.com/path, url=after.example.com/x and ${safelinks} today`;
		const hosts = hostsOf({text});
		for (const host of ['www.www.example.com', 'evil.example.com', 'after.example.com', 'wrapped.example.com']) {
			assert.ok(hosts.includes(host), host);
		}

		// (not a file name, nor a name in the path of a link)
		const other = hostsOf({text: 'run build.js/ or https://github.com/x/inside.example.com/'});
		assert.ok(!other.includes('build.js'));
		assert.ok(!other.includes('inside.example.com'));
	});

	it('reads names with no "/" after them only with hostsInText, after the rest, as far as there is room', () => {
		const text = 'Go to loose.example.com. Or https://linked.example.com/';
		assert.deepEqual(hostsOf({text}), ['linked.example.com']);
		assert.deepEqual(hostsOf({text}, {hostsInText: true}), ['linked.example.com', 'loose.example.com']);
		// (never an address, nor a word)
		assert.deepEqual(hostsOf({text: 'bob@mail.example.com and straße.de'}, {hostsInText: true}), []);
	});

	it('reads text as UTF-16 a mail client decodes by a label mailparser does not know', () => {
		const text = Buffer.from('https://utf16.example.com/', 'utf16le').toString('latin1');
		assert.ok(hostsOf({text}).includes('utf16.example.com'));
	});

	it('reads attached messages, HTML, SVG and XML files, and text files', () => {
		const hosts = hostsOf({text: ''}, {
			mails: [{html: '<a href="https://attached.example.com/">x</a>'}],
			attachments: [
				{filename: 'page.html', contentType: 'application/octet-stream', content: Buffer.from('<a href="https://file.example.com/">x</a>')},
				{filename: 'image.svg', contentType: 'image/svg+xml', content: Buffer.from('<svg><a xlink:href="https://image.example.com/">x</a></svg>')},
				{filename: 'notes.txt', contentType: 'text/plain', content: Buffer.from('see https://notes.example.com/')},
				// (UTF-16 by its byte order mark)
				{filename: 'wide.html', contentType: 'text/html', content: Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from('<a href="https://wide.example.com/">x</a>', 'utf16le')])},
				// (not a program's content)
				{filename: 'tool.exe', contentType: 'application/octet-stream', content: Buffer.from('https://program.example.com/')},
			],
		});
		for (const host of ['attached.example.com', 'file.example.com', 'image.example.com', 'notes.example.com', 'wide.example.com']) {
			assert.ok(hosts.includes(host), host);
		}

		assert.ok(!hosts.includes('program.example.com'));
	});

	it('reads invitations and contact cards as their programs show them', () => {
		const hosts = hostsOf({}, {
			attachments: [
				// (folded, escaped, and with a backslash before ":")
				card('invite.ics', 'text/calendar', 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDESCRIPTION:Join at https\\://fold\r\n ed.example.com/x\r\nURL:https://url.example.com/\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'),
				// (an HTML description, and the document an ALTREP names)
				card('meeting.ics', 'text/calendar', 'BEGIN:VEVENT\r\nX-ALT-DESC;FMTTYPE=text/html:<a href="https://altdesc.example.com/">x</a>\r\nDESCRIPTION;ALTREP="https://altrep.example.com/":x\r\nEND:VEVENT\r\n'),
				// (vCard 2.1 quoted-printable, by its charset)
				card('contact.vcf', 'text/x-vcard', 'BEGIN:VCARD\r\nVERSION:2.1\r\nURL;ENCODING=QUOTED-PRINTABLE:https://q=\r\np.example.com/\r\nEND:VCARD\r\n'),
			],
		});
		for (const host of ['folded.example.com', 'url.example.com', 'altdesc.example.com', 'altrep.example.com', 'qp.example.com']) {
			assert.ok(hosts.includes(host), host);
		}
	});

	it('decodes every character reference a browser decodes by name', () => {
		// (a mathematical letter is the letter in a host name, as browsers read it)
		assert.deepEqual(hostsOf({html: '<a href="http://ev&iopf;l.example/">x</a>'}), ['evil.example']);
		// (and a Cyrillic letter makes the name it is looked up as)
		assert.deepEqual(hostsOf({text: 'see http://p&acy;ypal.com/ now'}), []);
		assert.deepEqual(hostsOf({html: '<p>see http://p&acy;ypal.com/ now</p>'}), ['xn--pypal-4ve.com']);
	});

	it('reads an HTML file by the name Windows saves it as', () => {
		for (const filename of ['x.html::$DATA', 'x.html:', 'C:x.html:$DATA ', 'x.\u202Dhtml']) {
			const hosts = hostsOf({}, {attachments: [{filename, contentType: 'application/octet-stream', content: Buffer.from('<a href="https://saved.example.com/">x</a>')}]});
			assert.deepEqual(hosts, ['saved.example.com'], filename);
		}
	});

	it('stops at maxHosts, and says so', () => {
		const html = Array.from({length: 30}, (_, i) => `<a href="https://h${i}.example.com/">x</a>`).join('');
		const result = carriedLinkHosts({html}, {maxHosts: 25});
		assert.equal(result.hosts.length, 25);
		assert.equal(result.more, true);
		assert.equal(carriedLinkHosts({html}, {maxHosts: 30}).more, false);
	});

	it('reads long HTML a part at a time without losing a link cut between parts, in linear time', () => {
		const filler = 'x'.repeat((1024 * 1024) - 10);
		const result = carriedLinkHosts({html: `${filler} https://cut.example.com/path ${'y'.repeat(100)}`});
		assert.ok(result.hosts.includes('cut.example.com'));
		assert.equal(result.tooComplex, false);
	});
});

describe('link checks of what a message carries', () => {
	const lookups = () => {
		const asked = [];
		return {
			asked,
			async resolve4(name) {
				asked.push(name);
				return name.startsWith('bad') ? ['0.0.0.0'] : ['192.0.2.1'];
			},
		};
	};

	const forwarded = message({
		text: 'See the attached message.',
		attachments: [
			{filename: 'fw.eml', contentType: 'message/rfc822', content: message({text: 'Sign in at https://bad.inner.example/login'})},
			{filename: 'page.html', contentType: 'text/html', content: '<a href="https://bad.page.example/">x</a>'},
		],
	});

	it('looks up the link hosts of attached messages and files, and blocks one Cloudflare blocks', async () => {
		const {asked, resolve4} = lookups();
		const scanner = new SpamScanner({classifier: false, dns: {resolve4}, phishing: {attachments: true}});
		const result = await scanner.scan(forwarded);
		assert.ok(asked.includes('bad.inner.example'));
		assert.ok(asked.includes('bad.page.example'));
		const domains = result.results.phishing.filter(item => item.type === 'malicious_domain').map(item => item.domain);
		assert.deepEqual(domains.sort(), ['bad.inner.example', 'bad.page.example']);
		assert.equal(result.results.linksTooComplex, false);
		assert.equal(result.results.linksIncomplete, false);
		// (with the attachments, of the attached message too)
		assert.ok(result.attached.some(item => item.filename === 'fw.eml'));
	});

	it('reads none of it by default (phishing.attachments off), or when no link host is looked up', async () => {
		for (const options of [{}, {phishing: {attachments: false}}, {phishing: {attachments: true, cloudflare: false}}]) {
			const {asked, resolve4} = lookups();
			const scanner = new SpamScanner({classifier: false, dns: {resolve4}});

			const result = await scanner.scan(forwarded, options);
			assert.ok(!asked.includes('bad.inner.example'), JSON.stringify(options));
			assert.ok(!result.results.phishing.some(item => item.type === 'malicious_domain'));
		}
	});

	it('waits for link lookups for phishing.timeout, else for timeout', async () => {
		const slow = async name => {
			await new Promise(resolve => {
				setTimeout(resolve, 300);
			});
			return name.startsWith('bad') ? ['0.0.0.0'] : ['192.0.2.1'];
		};

		const raw = message({text: 'Sign in at https://bad.slow.example/login'});
		const short = new SpamScanner({classifier: false, timeout: 100, dns: {resolve4: slow}});
		const missed = await short.scan(raw);
		assert.equal(missed.results.timedOutHosts, 1);
		const patient = new SpamScanner({
			classifier: false, timeout: 100, dns: {timeout: 2000, resolve4: slow}, phishing: {timeout: 2000},
		});
		const found = await patient.scan(raw);
		assert.equal(found.results.timedOutHosts, 0);
		assert.ok(found.results.phishing.some(item => item.type === 'malicious_domain'));
	});

	it('counts the hosts of what a message carries toward phishing.maxHosts', async () => {
		const {resolve4} = lookups();
		const scanner = new SpamScanner({classifier: false, dns: {resolve4}, phishing: {attachments: true}});
		const html = Array.from({length: 30}, (_, i) => `<a href="https://h${i}.example.com/">x</a>`).join('');
		const result = await scanner.scan(message({text: 'Hello.', attachments: [{filename: 'many.html', contentType: 'text/html', content: html}]}));
		assert.ok(result.results.uncheckedHosts >= 1);
	});
});

describe('carriedLinkHosts on every shape of input', () => {
	const read = (document, options) => carriedLinkHosts(document, options);
	const file = (filename, contentType, content) => ({filename, contentType, content: Buffer.isBuffer(content) ? content : Buffer.from(content)});

	it('reads attributes as a browser does: spaces, stray "=", no value, unclosed and unquoted values', () => {
		const hosts = hostsOf({
			html: [
				'<a href=" https://lead.example.com/">x</a>',
				'<a href="https://trail.example.com/ ">x</a>',
				'<a ="x" href="https://stray.example.com/">x</a>',
				'<a href = \'https://spaced.example.com/\'>x</a>',
				'<a download href="https://novalue.example.com/">x</a>',
				'<a href=https://unquoted.example.com/>x</a>',
				'<a href="https://unclosed.example.com/',
			].join('\n'),
		});
		for (const host of ['lead.example.com', 'trail.example.com', 'stray.example.com', 'spaced.example.com', 'novalue.example.com', 'unquoted.example.com', 'unclosed.example.com']) {
			assert.ok(hosts.includes(host), host);
		}
	});

	it('reads hosts with dots at their end and addresses, and not a namespace, nothing, or what is no URL', () => {
		const hosts = hostsOf({
			html: [
				'<a href="http://dots.example.com../">x</a>',
				'<a href="http://[2001:db8::1]/">x</a>',
				'<a href="http://192.0.2.1/">x</a>',
				'<a href="http://www.w3.org/1999/xhtml">x</a>',
				'<a href="http://./">x</a>',
				'<a href="https://[::1/">x</a>',
				'<a href="mailto:bob@example.com">x</a>',
			].join('\n'),
		});
		assert.deepEqual(hosts, ['dots.example.com', '2001:db8::1', '192.0.2.1']);
	});

	it('takes a link wrapped deeper than unwrapLink unwraps for one never read whole', () => {
		// (17 gateways, one more than unwrapLink unwraps)
		const gateway = 'https://eur01.safelinks.protection.outlook.com/?url=';
		const nested = `${gateway.repeat(17)}https://deep.example.com/`;
		assert.equal(read({text: nested}).tooComplex, true);
		assert.equal(read({text: `${gateway.repeat(3)}https://shallow.example.com/`}).tooComplex, false);
	});

	it('reads names before "/" as extractLinks reads them, and not what is no name', () => {
		const text = '//start.example.com/x port.example.com:8080/ dot.example.com./ x..two.example.com/ --.example.com/ see build.x1/ dup.example.com/ dup.example.com/ /alone';
		const hosts = hostsOf({text});
		for (const host of ['start.example.com', 'port.example.com', 'dot.example.com', 'two.example.com', 'dup.example.com']) {
			assert.ok(hosts.includes(host), host);
		}

		assert.ok(!hosts.some(host => host.includes('x1') || host.startsWith('-')));
	});

	it('reads names without "/" once each, not too long ones, and stops once there are more than room for', () => {
		const long = `${'a'.repeat(400)}.${'b'.repeat(400)}.com`;
		assert.deepEqual(hostsOf({text: `${long} once.example.com once.example.com`}, {hostsInText: true}), ['once.example.com']);
		// (one link and room for none of them)
		assert.deepEqual(hostsOf({text: 'https://link.example.com/ a.example.com b.example.com c.example.com'}, {hostsInText: true, maxHosts: 1}), ['link.example.com']);
		assert.deepEqual(hostsOf({text: 'a.example.com b.example.com c.example.com'}, {hostsInText: true, maxHosts: 1}), ['a.example.com']);
	});

	it('stops reading once there are more hosts than room for, in text, styles and documents', () => {
		const text = read({text: 'https://a.example.com/ https://b.example.com/ c.example.com/ https://d.example.com/'}, {maxHosts: 1});
		assert.deepEqual(text, {
			hosts: ['a.example.com'], more: true, tooComplex: false, incomplete: false,
		});
		const styles = read({html: '<style>.a{background:url(https://s1.example.com/a)}.b{background:url(https://s2.example.com/b)}.c{background:url(https://s3.example.com/c)}</style>'}, {maxHosts: 1});
		assert.equal(styles.more, true);
		const documents = read({html: '<a href="https://first.example.com/">x</a><a href="https://second.example.com/">y</a>'}, {mails: [{html: '<a href="https://third.example.com/">z</a>'}], maxHosts: 1});
		assert.deepEqual(documents.hosts, ['first.example.com']);
	});

	it('reads data: URLs by their escapes and charset, and not other data', () => {
		const hosts = hostsOf({
			html: [
				'<iframe src="data:text/html,%3ca href=%22https://lower.example.com/%22%3ex%3c/a%3e%zz"></iframe>',
				`<iframe src="data:text/html;charset=utf-16be;base64,${Buffer.from('<a href="https://wide.example.com/">x</a>', 'utf16le').swap16().toString('base64')}"></iframe>`,
				'<img src="data:image/png;base64,iVBORw0KGgo=">',
			].join('\n'),
		});
		assert.deepEqual(hosts.sort(), ['lower.example.com', 'wide.example.com']);
	});

	it('reads text files by their byte order mark or UTF-16 label, and skips what has no content', () => {
		const hosts = hostsOf({}, {
			attachments: [
				file('be.txt', 'text/plain', Buffer.concat([Buffer.from([0xFE, 0xFF]), Buffer.from('https://bom.example.com/', 'utf16le').swap16()])),
				{
					filename: 'le.txt', contentType: 'text/plain', content: Buffer.from('https://label.example.com/', 'utf16le'), headers: new Map([['content-type', {value: 'text/plain', params: {charset: 'UTF-16'}}]]),
				},
				{
					filename: 'odd.txt', contentType: 'text/plain', content: Buffer.from('https://odd.example.com/x', 'utf16le').swap16(), headers: new Map([['content-type', {value: 'text/plain', params: {charset: 'utf-16be'}}]]),
				},
				{filename: 'empty.html', contentType: 'text/html', content: Buffer.alloc(0)},
				// (by name alone: without a type, and names without an extension)
				{filename: 'typeless.html', content: Buffer.from('<a href="https://typeless.example.com/">x</a>')},
				file('README', 'application/octet-stream', 'https://readme.example.com/'),
				file('page.\t', 'application/octet-stream', 'https://tab.example.com/'),
				{filename: 'none.html', contentType: 'text/html'},
				null,
			],
		});
		assert.deepEqual(hosts.sort(), ['bom.example.com', 'label.example.com', 'odd.example.com', 'typeless.example.com']);
	});

	it('reads cards by every shape of their values', () => {
		const card = (text, filename = 'c.vcf') => file(filename, 'text/vcard', text);
		const many = `NOTE:${String.raw`\n`.repeat(40_000)}https://escapes.example.com/\r\n`;
		const hosts = hostsOf({}, {
			attachments: [
				// (quoted-printable with escapes, spaces after soft breaks, a charset no decoder has, and text beyond ASCII)
				card('BEGIN:VCARD\r\nURL;ENCODING=QUOTED-PRINTABLE;CHARSET=bogus:https=3A//qp1.example.com/   \r\nNOTE;QUOTED-PRINTABLE:é https=3A=2F=2Fqp2.example.com/\r\nEND:VCARD\r\n'),
				// (folded, with quoted-printable: also decoded with its folds kept)
				card('BEGIN:VCARD\r\nURL;ENCODING=QUOTED-PRINTABLE:https=3A//fol\r\n ded.example.com/\r\nEND:VCARD\r\n'),
				// (a quoted parameter value with a ":" in it, and one never closed)
				card('BEGIN:VCARD\r\nX-A;P="a:b":https://quoted.example.com/\r\nX-B;P="open:https://open.example.com/\r\nEND:VCARD\r\n'),
				// (binary values: a photo left out, another decoded, folded and vCard 2.1 lines of base64, and a link marked binary)
				card(`BEGIN:VCARD\r\nPHOTO;ENCODING=b:${Buffer.from('https://photo.example.com/').toString('base64')}\r\nNOTE;ENCODING=b:${Buffer.from('https://b64.example.com/').toString('base64')}\r\nX-N;ENCODING=BASE64:${Buffer.from('https://fold').toString('base64')}\r\n ${Buffer.from('.example.com/').toString('base64')}\r\nX-V;BASE64:${Buffer.from('https://v21x').toString('base64')}\r\n${Buffer.from('.example.com/').toString('base64')}\r\n\r\nURL;VALUE=binary:https://marked.example.com/\r\nEND:VCARD\r\n`),
				// (many escapes)
				card(many, 'e.ics'),
				// (an invitation's descriptions: no colon, no markup)
				card('BEGIN:VEVENT\r\nNOCOLON\r\nX-B;P="open:<b>x</b>\r\nDESCRIPTION:plain & simple https://desc.example.com/\r\nCOMMENT:no markup\r\nEND:VEVENT\r\n', 'd.ics'),
			],
		});
		for (const host of ['qp1.example.com', 'qp2.example.com', 'folded.example.com', 'quoted.example.com', 'b64.example.com', 'fold.example.com', 'v21x.example.com', 'marked.example.com', 'escapes.example.com', 'desc.example.com']) {
			assert.ok(hosts.includes(host), host);
		}

		assert.ok(!hosts.includes('photo.example.com'));
	});

	it('reads a card only so far, past which it was never read whole, and what follows it', () => {
		// (1 MB without its photos, which are not read)
		const photo = `PHOTO;ENCODING=b;TYPE=JPEG:${'QUJD'.repeat(500_000)}`;
		const withPhoto = read({}, {attachments: [file('photo.vcf', 'text/vcard', `BEGIN:VCARD\r\n${photo}\r\nURL;QUOTED-PRINTABLE:https=3A//qp.example.com/\r\nEND:VCARD\r\n`)]});
		assert.equal(withPhoto.tooComplex, false);
		assert.deepEqual(withPhoto.hosts, ['qp.example.com']);
		const big = 'x'.repeat(1024 * 1024);
		const past = read({}, {attachments: [file('big.vcf', 'text/vcard', `BEGIN:VCARD\r\nURL:https://before.example.com/\r\nNOTE:${big}\r\nURL:https://past.example.com/\r\nEND:VCARD\r\n`), file('after.html', 'text/html', '<a href="https://after.example.com/">x</a>')]});
		assert.equal(past.tooComplex, true);
		assert.deepEqual(past.hosts, ['before.example.com', 'after.example.com']);
		// (and 4 MB with them)
		const huge = read({}, {attachments: [file('huge.vcf', 'text/vcard', `BEGIN:VCARD\r\nURL:https://first.example.com/\r\nPHOTO;ENCODING=b:${'QUJD'.repeat(1_100_000)}\r\nEND:VCARD\r\n`)]});
		assert.equal(huge.tooComplex, true);
		assert.deepEqual(huge.hosts, ['first.example.com']);
	});

	it('reads at most so many HTML files', () => {
		const files = Array.from({length: 101}, (_, i) => file(`p${i}.html`, 'text/html', `<p>${i}</p>`));
		assert.equal(read({}, {attachments: files}).tooComplex, true);
	});

	it('reads long HTML cut where no link goes on, and a link across the cut', () => {
		const chunk = 1024 * 1024;
		// (">" is no place to cut, so each part is cut hard: a link at the start
		//  of the part after the cut is read in the part before it, whole)
		const start = read({html: `${'x'.repeat(chunk - 4097)}>https://cutstart.example.com/${'y'.repeat(chunk)}`});
		assert.deepEqual(start.hosts, ['cutstart.example.com']);
		// (a link whose host ends before the cut, one whose host runs a little
		//  past it, read whole in the next part, and one whose host runs past
		//  it, never read whole)
		const ends = read({html: `${'x'.repeat(chunk - 30)}>https://ends.example.com/${'z'.repeat(chunk)}`});
		assert.deepEqual(ends.hosts, ['ends.example.com']);
		const next = read({html: `${'x'.repeat(chunk - 10)}>https://next.example.com/ ${'w'.repeat(chunk)}`});
		assert.deepEqual(next.hosts, ['next.example.com']);
		const runs = read({html: `${'x'.repeat(chunk - 5000)}>https://${'a'.repeat(6000)}.example.com/`});
		assert.equal(runs.tooComplex, true);
		// (also a link without a scheme, and names with no "/" after them, which
		//  are not read where a part was cut)
		const www = read({html: `${'x'.repeat(chunk - 30)}>www.wends.example.com/${'z'.repeat(chunk)}`});
		assert.deepEqual(www.hosts, ['www.wends.example.com']);
		const loose = read({html: `${'x'.repeat(chunk - 4097)}>https://cutstart.example.com/${'y'.repeat(chunk)} loose.example.com`}, {hostsInText: true});
		assert.deepEqual(loose.hosts, ['cutstart.example.com', 'loose.example.com']);
	});

	it('stops reading at its time limit, and says so', () => {
		const {now} = Date;
		const clock = steps => {
			let calls = 0;
			Date.now = () => now() + (calls++ >= steps ? 10_000 : 0);
		};

		try {
			// (before an attachment)
			clock(1);
			assert.equal(read({}, {attachments: [file('a.html', 'text/html', '<a href="https://a.example.com/">x</a>')]}).incomplete, true);
			// (while an attachment is opened)
			clock(3);
			assert.deepEqual(read({}, {attachments: [file('a.html', 'text/html', '<a href="https://a.example.com/">x</a>')]}), {
				hosts: [], more: false, tooComplex: false, incomplete: true,
			});
			// (before a document)
			clock(1);
			assert.deepEqual(read({html: '<a href="https://b.example.com/">x</a>'}), {
				hosts: [], more: false, tooComplex: false, incomplete: true,
			});
			// (before a part of one)
			clock(2);
			assert.equal(read({html: 'https://c.example.com/'}).incomplete, true);
		} finally {
			Date.now = now;
		}
	});

	it('gives checkLinks the sender\'s domain as earlier versions did, and takes no options as none', async () => {
		const scanner = new SpamScanner({classifier: false, phishing: {cloudflare: false}});
		// (a brand's sign-in address shown through click tracking is deceptive
		//  from anyone but the brand)
		const links = [{url: 'https://example.us1.list-manage.com/track/click?u=1&id=2', host: 'example.us1.list-manage.com', text: 'https://www.paypal.com/signin'}];
		const deceptive = checked => checked.phishing.some(item => item.type === 'deceptive_link');
		assert.ok(deceptive(await scanner.checkLinks(links, scanner.config, [], 'notice-center.example')));
		assert.ok(!deceptive(await scanner.checkLinks(links, scanner.config, [], 'paypal.com')));
		assert.ok(!deceptive(await scanner.checkLinks(links, scanner.config, [], {from: 'paypal.com'})));
		const none = await scanner.checkLinks(links, scanner.config, [], null);
		assert.equal(none.uncheckedHosts, 0);
	});

	it('reads each document an iframe or data: URL holds once, so repeating one does not use up the documents read', () => {
		const frames = Array.from({length: 400}, (_, i) => `<iframe srcdoc="<a href=https://h${i % 5}.example.com/>x</a>"></iframe>`).join('');
		const result = read({html: frames});
		assert.equal(result.tooComplex, false);
		assert.deepEqual(result.hosts.sort(), ['h0.example.com', 'h1.example.com', 'h2.example.com', 'h3.example.com', 'h4.example.com']);
		// (and 400 different ones, nested three deep, within what is read)
		const distinct = Array.from({length: 400}, (_, i) => `<iframe srcdoc="<a href=https://d${i}.example.com/>x</a>"></iframe>`).join('');
		assert.equal(read({html: distinct}, {maxHosts: 1000}).tooComplex, false);
	});

	it('takes a link cut where a part is cut hard for one never read whole, unless the next part reads it whole', () => {
		const chunk = 1024 * 1024;
		// (the link a gateway's link wraps, cut: its own host is read, but where
		//  it goes is not known)
		const head = '>https://nam12.safelinks.protection.outlook.com/?x=';
		const gateway = read({html: `${'-'.repeat(chunk - 5000)}${head}${'A'.repeat(6000)}&url=https%3A%2F%2Fevil.example%2F`});
		assert.equal(gateway.tooComplex, true);
		// (one within the part after the cut is read there whole)
		const whole = read({html: `${'-'.repeat(chunk - head.length)}${head}${'A'.repeat(6000)}&url=https%3A%2F%2Fevil.example%2F`});
		assert.deepEqual(whole, {
			hosts: ['nam12.safelinks.protection.outlook.com', 'evil.example'], more: false, tooComplex: false, incomplete: false,
		});
		// (a part is not cut within a character reference, however long, but
		//  before it: the next part reads the link whole)
		const references = read({html: `${'-'.repeat(chunk - 6000)}>https://&#x${'0'.repeat(10_000)}65;vil.example/x`});
		assert.deepEqual(references, {
			hosts: ['evil.example'], more: false, tooComplex: false, incomplete: false,
		});
		// (so one cut where it would decode as a line break, which would end
		//  a link before the cut, is a link whose host runs past it, not one
		//  to "ev")
		const link = `http://${'a'.repeat(5000)}@ev&#10`;
		const broken = read({html: `${'x'.repeat(chunk - link.length - 1)}.${link}5;l.example?x end`});
		assert.deepEqual(broken, {
			hosts: [], more: false, tooComplex: true, incomplete: false,
		});
	});

	it('takes a long link across a hard cut whose host was read for one read whole, unless it is a gateway\'s, also in HTML with character references', () => {
		const chunk = 1024 * 1024;
		// (a long link, its host before the cut and its path past it)
		const long = read({html: `${'-'.repeat(chunk - 5000)}>https://long.example.com/${'p'.repeat(6000)}`});
		assert.deepEqual(long, {
			hosts: ['long.example.com'], more: false, tooComplex: false, incomplete: false,
		});
		// (a short one at the cut, in a part with a character reference before
		//  it, read whole in the next part)
		const references = read({html: `&amp;${'-'.repeat(chunk - 30)}>https://short.example.com/${'q'.repeat(chunk)}`});
		assert.deepEqual(references, {
			hosts: ['short.example.com'], more: false, tooComplex: false, incomplete: false,
		});
	});

	it('reads an attribute\'s value only so far, and checks the time limit before a long one', () => {
		const tooLong = read({html: `<a href="https://cut.example.com/?${'&amp;'.repeat(300_000)}">x</a>`});
		assert.deepEqual(tooLong.hosts, ['cut.example.com']);
		assert.equal(tooLong.tooComplex, true);
		const {now} = Date;
		let calls = 0;
		// (past the time limit after the first look at the clock)
		Date.now = () => now() + (calls++ >= 2 ? 10_000 : 0);
		try {
			const late = read({html: `<p>${'x'.repeat(10)}</p><a href="https://late.example.com/${'y'.repeat(70_000)}">x</a>`});
			assert.equal(late.incomplete, true);
			assert.deepEqual(late.hosts, []);
			// (also one read leniently, outside a tag)
			calls = 0;
			const lenient = read({html: `<p>text href=https://lenient.example.com/${'y'.repeat(70_000)}</p>`});
			assert.equal(lenient.incomplete, true);
			assert.deepEqual(lenient.hosts, []);
		} finally {
			Date.now = now;
		}
	});

	it('says attachments past what is read are too many before reading stops for more hosts', () => {
		const many = Array.from({length: 101}, (_, i) => file(`p${i}.html`, 'text/html', `<a href="https://h${i}.example.com/">x</a>`));
		const result = read({}, {attachments: many, maxHosts: 5});
		assert.equal(result.more, true);
		assert.equal(result.tooComplex, true);
	});

	it('checks the time limit once so much of attribute values was read, however short each', () => {
		const {now} = Date;
		let calls = 0;
		Date.now = () => now() + (calls++ >= 2 ? 10_000 : 0);
		try {
			const value = host => `https://${host}/?${'x'.repeat(40_000)}`;
			const result = read({html: ['a', 'b', 'c'].map(host => `<a href="${value(`${host}.example.com`)}">x</a>`).join('')});
			assert.deepEqual(result, {
				hosts: ['a.example.com'], more: false, tooComplex: false, incomplete: true,
			});
		} finally {
			Date.now = now;
		}
	});

	it('reads a CSS link only so far, as an attribute\'s value', () => {
		const result = read({html: `<p>x</p><style>p { background: url(https://css.example.com/?${'&amp;'.repeat(300_000)}) }</style>`});
		assert.deepEqual(result.hosts, ['css.example.com']);
		assert.equal(result.tooComplex, true);
	});

	it('stops reading a card at its time limit between the steps of reading it', () => {
		const {now} = Date;
		const card = file('c.vcf', 'text/vcard', 'BEGIN:VCARD\r\nURL:https://card.example.com/\r\nNOTE:x\r\nEND:VCARD\r\n');
		for (const steps of [2, 3, 4, 5, 6, 7]) {
			let calls = 0;
			Date.now = () => now() + (calls++ >= steps ? 10_000 : 0);
			try {
				const result = read({}, {attachments: [card]});
				assert.equal(result.incomplete, true);
				// (past it once the card is read for its text: nothing of it read)
				if (steps === 5) {
					assert.deepEqual(result.hosts, []);
				}
			} finally {
				Date.now = now;
			}
		}
	});

	it('collects the first host of each domain past maxHosts, so hosts of one domain do not keep another from being looked up', () => {
		const filler = Array.from({length: 30}, (_, i) => `<a href="https://a${i}.filler.example/">${i}</a>`).join('');
		const result = read({html: filler}, {attachments: [file('a.html', 'text/html', '<a href="https://evil.example/">x</a>')], maxHosts: 25});
		assert.equal(result.more, true);
		assert.ok(result.hosts.includes('evil.example'));
		assert.equal(result.hosts.length, 26);
		// (and no more domains than are looked up)
		const domains = Array.from({length: 60}, (_, i) => `<a href="https://d${i}.example/">${i}</a>`).join('');
		assert.equal(read({html: domains}, {maxHosts: 25}).hosts.length, 25);
	});

	it('stops reading text at its time limit, a part at a time', () => {
		const {now} = Date;
		let calls = 0;
		Date.now = () => now() + (calls++ >= 2 ? 10_000 : 0);
		try {
			assert.deepEqual(read({text: 'https://late.example.com/'}), {
				hosts: [], more: false, tooComplex: false, incomplete: true,
			});
		} finally {
			Date.now = now;
		}
	});

	it('looks up the first host of every domain, the message\'s own and those of what it carries, before more of one domain', async () => {
		const asked = [];
		const scanner = new SpamScanner({
			classifier: false,
			phishing: {attachments: true},
			dns: {
				async resolve4(name) {
					asked.push(name);
					return ['192.0.2.1'];
				},
			},
		});
		// (links to 30 hosts of one domain, and a ping, which only the reading of
		//  the whole message finds, to another)
		const stuffing = Array.from({length: 30}, (_, i) => `<a href="https://h${i}.stuffing.example/">${i}</a>`).join('');
		const result = await scanner.scan(message({text: 'Hello.', html: `<a ping="https://evil.example/p" href="#">x</a>${stuffing}`}));
		assert.ok(asked.includes('h0.stuffing.example'));
		assert.ok(asked.includes('evil.example'));
		assert.ok(result.results.uncheckedHosts >= 1);
	});

	it('decodes the angle brackets by name as browsers do', () => {
		assert.equal(decodeEntities('&lang;x&rang; &Lang;&Rang;'), '\u27E8x\u27E9 \u27EA\u27EB');
	});
});

describe('scan results sent to clients', () => {
	it('leave out the parsed message and its attachments', async () => {
		const scanner = new SpamScanner({classifier: false, phishing: {cloudflare: false}});
		const result = await scanner.scan(message({text: 'Hello.', attachments: [{filename: 'big.bin', contentType: 'application/octet-stream', content: Buffer.alloc(100_000, 7)}]}));
		assert.equal(result.attached.length, 1);
		const output = serializeResult(result);
		assert.equal(output.attached, undefined);
		assert.equal(output.mail, undefined);
		assert.ok(JSON.stringify(output).length < 20_000);
	});
});
