import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import SpamScanner from '../src/index.js';
import {carriedLinkHosts} from '../src/links.js';
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

	it('takes a card past what is read with a value in quoted-printable for one never read whole, and reads one without', () => {
		const big = 'x'.repeat((4 * 1024 * 1024) + 1);
		const withQp = read({}, {attachments: [file('big.vcf', 'text/vcard', `BEGIN:VCARD\r\nNOTE:${big}\r\nURL;QUOTED-PRINTABLE:https=3A//qp.example.com/\r\nEND:VCARD\r\n`), file('after.html', 'text/html', '<a href="https://after.example.com/">x</a>')]});
		assert.equal(withQp.tooComplex, true);
		assert.deepEqual(withQp.hosts, ['after.example.com']);
		const withoutQp = read({}, {attachments: [file('big.vcf', 'text/vcard', `BEGIN:VCARD\r\nNOTE:${big}\r\nURL:https://plain.example.com/\r\nEND:VCARD\r\n`)]});
		assert.equal(withoutQp.tooComplex, false);
		assert.ok(withoutQp.hosts.includes('plain.example.com'));
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

	it('gives checkLinks the sender\'s domain as earlier versions did', async () => {
		const scanner = new SpamScanner({classifier: false, phishing: {cloudflare: false}});
		const checked = await scanner.checkLinks([{url: 'https://example.com/', host: 'example.com', text: null}], scanner.config, [], 'example.com');
		assert.equal(checked.uncheckedHosts, 0);
	});
});
