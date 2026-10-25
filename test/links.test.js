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
