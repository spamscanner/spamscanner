import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {simpleParser} from 'mailparser';
import {
	characterClass, chunk, decodeEntities, extractHosts, extractLinks, getFeatures, isDeceptiveLink, normalizeText, obfuscationOf, readableText, registrableDomain, segmentWords, visibleText,
} from '../src/tokenizer.js';
import {message} from './helpers/index.js';

const parse = raw => simpleParser(raw, {skipImageLinks: true, skipTextToHtml: true, skipTextLinks: true});

describe('chunk', () => {
	it('splits long text at spaces, keeping every character', () => {
		const text = 'word '.repeat(1000);
		const pieces = chunk(text, 100);
		assert.ok(pieces.every(piece => piece.length <= 100));
		assert.equal(pieces.join(''), text);
	});

	it('cuts unspaced text hard, never inside a surrogate pair', () => {
		const text = `${'字'.repeat(99)}😀${'字'.repeat(50)}`;
		const pieces = chunk(text, 100);
		assert.equal(pieces.join(''), text);
		assert.ok(pieces.every(piece => !/[\uD800-\uDBFF]$/.test(piece)));
	});

	it('cuts at ideographic punctuation', () => {
		const pieces = chunk(`${'字'.repeat(60)}。${'字'.repeat(60)}`, 100);
		assert.equal(pieces[0].at(-1), '。');
	});

	it('segments 160,000 characters quickly (Node.js 18 is quadratic on one long string)', () => {
		const started = Date.now();
		const {words} = segmentWords('Congratulations you have won a free prize click here now. '.repeat(2700), {maxLength: 200_000});
		assert.ok(words.length > 20_000);
		assert.ok(Date.now() - started < 5000);
	});
});

describe('extractHosts', () => {
	it('finds host names written without a link, and the domains of email addresses', () => {
		assert.deepEqual(
			extractHosts('Sign in at paypa1-secure.com, or write to j.doe@mail.example.co.uk. End.Click here; see node.js, file.txt, readme.md, paypal-sdk.zip, xn--pypal-4ve.app, docs.example.md, first.name@x.org and paypa1-secure.com again.'),
			// (not file names whose extension is also a top-level domain)
			['paypa1-secure.com', 'mail.example.co.uk', 'xn--pypal-4ve.app', 'docs.example.md', 'x.org'],
		);
	});

	it('skips known hosts, nothing, and stops at 50', () => {
		assert.deepEqual(extractHosts('see example.com', new Set(['example.com'])), []);
		assert.deepEqual(extractHosts(''), []);
		assert.deepEqual(extractHosts(null), []);
		const many = Array.from({length: 60}, (_, i) => `host${i}.com`).join(' ');
		assert.equal(extractHosts(many).length, 50);
	});

	it('skips the end of a longer name in letters it does not read', () => {
		assert.deepEqual(extractHosts('see m\u00FCnchen-ups.de, \u{1D41A}paypa1.com, x\u0301paypa1.com and (paypa1.com)'), ['paypa1.com']);
		// (a "." or "-" not after a name starts none)
		assert.deepEqual(extractHosts('Go...paypa1.com, see -rnicrosoft.com, \u00FC.arnazon.com'), ['paypa1.com', 'rnicrosoft.com']);
	});

	it('reads "\u017F" and "\u212A" in names as "s" and "k", as browsers do, on either engine', () => {
		assert.deepEqual(extractHosts('see paypa1.\u017Fite or ban\u212Aofamerica-login.com'), ['paypa1.site', 'bankofamerica-login.com']);
		assert.deepEqual(extractLinks('https://paypa1.\u017Fite/x', '<a href="https://a.example/">https://www.payp\u212Aal.com/</a>').map(link => [link.host, link.text]), [['a.example', 'https://www.paypkal.com/'], ['paypa1.site', null], ['www.paypkal.com', null]]);
		// (also written as character references)
		assert.equal(extractLinks('', '<a href="https://a.example/">http&#383;://www.paypal.com/</a>')[0].text, 'https://www.paypal.com/');
	});

	it('gives the hosts that are not links with the features', async () => {
		const mail = await parse(message({text: 'Go to https://example.org/a or example.net, or ask help@example.com'}));
		assert.deepEqual(getFeatures(mail).hosts, ['example.net', 'example.com']);
	});
});

describe('normalizeText', () => {
	it('removes invisible characters and counts them, folds styled letters', () => {
		assert.deepEqual(normalizeText('fr\u{200B}ee m\u{AD}oney'), {text: 'free money', invisible: 2, styled: false});
		assert.equal(normalizeText('\u{1D405}\u{1D411}\u{1D404}\u{1D404}').text, 'free');
		assert.equal(normalizeText('\u{1D405}REE').styled, true);
		assert.equal(normalizeText('ｆｒｅｅ').text, 'free');
		assert.equal(normalizeText('a\u{200D}b').invisible, 0);
	});

	it('handles empty and non-string input', () => {
		assert.deepEqual(normalizeText(''), {text: '', invisible: 0, styled: false});
		assert.deepEqual(normalizeText(null), {text: '', invisible: 0, styled: false});
	});

	it('builds character classes from code points', () => {
		assert.ok(characterClass([[0x41, 0x43]], 'u').test('B'));
		assert.ok(!characterClass([[0x41]], 'u').test('B'));
	});
});

describe('segmentWords', () => {
	it('splits words in every script', () => {
		assert.deepEqual(segmentWords('Hello, World!').words, ['hello', 'world']);
		assert.ok(segmentWords('恭喜您赢得了一百万美元').words.length >= 4);
		assert.deepEqual(segmentWords('ยินดีด้วยคุณได้รับรางวัล').words, ['ยินดี', 'ด้วย', 'คุณ', 'ได้', 'รับ', 'รางวัล']);
		assert.deepEqual(segmentWords('Поздравляем! Вы выиграли').words, ['поздравляем', 'вы', 'выиграли']);
		assert.deepEqual(segmentWords('مبروك لقد ربحت').words, ['مبروك', 'لقد', 'ربحت']);
	});

	it('folds lookalike letters inside mixed-script words', () => {
		const result = segmentWords('Verify your pаypаl account'); // Cyrillic а
		assert.ok(result.words.includes('paypal'));
		assert.equal(result.mixed, 1);
	});

	it('undoes digit-for-letter tricks', () => {
		assert.deepEqual(segmentWords('h4x2r').words, ['hax2r']);
		const result = segmentWords('cheap v1agra and fr33dom');
		assert.ok(result.words.includes('viagra'));
		assert.ok(result.words.includes('freedom'));
		assert.equal(result.leet, 2);
	});

	it('drops single Latin letters but keeps single ideographs and numbers', () => {
		assert.deepEqual(segmentWords('a b 7 字').words, ['7', '字']);
	});

	it('accepts a locale hint, including an invalid one', () => {
		assert.ok(segmentWords('日本語の文章です', {locale: 'ja'}).words.length > 1);
		assert.deepEqual(segmentWords('hello world', {locale: 'not a locale!'}).words, ['hello', 'world']);
	});

	it('ignores non-string input', () => {
		assert.deepEqual(segmentWords(undefined).words, []);
	});
});

describe('obfuscationOf', () => {
	it('counts obfuscation as segmentWords does', () => {
		const pieces = ['pаypаl', 'Verify', 'αpple', 'h\u200Bello', '𝐟𝐫𝐞𝐞', 'Привет', 'world', '日本語', ' ', '\n', 'v1agra', 'ﬁnance', 'Ⅻ'];
		let seed = 11;
		const random = () => {
			seed = ((seed * 1_103_515_245) + 12_345) % 2_147_483_648;
			return seed / 2_147_483_648;
		};

		for (let i = 0; i < 500; i++) {
			const text = Array.from({length: Math.floor(random() * 12)}, () => pieces[Math.floor(random() * pieces.length)]).join(random() < 0.5 ? ' ' : '');
			const {invisible, mixed, styled} = segmentWords(text, {maxLength: 40});
			assert.deepEqual(obfuscationOf(text, {maxLength: 40}), {invisible, mixed, styled}, JSON.stringify(text));
		}

		// (long text, read in pieces)
		for (const separator of [' ', '', '\n']) {
			const text = Array.from({length: 3000}, (_, i) => pieces[(i * 7) % pieces.length]).join(separator);
			const {invisible, mixed, styled} = segmentWords(text);
			assert.deepEqual(obfuscationOf(text), {invisible, mixed, styled});
		}

		assert.deepEqual(obfuscationOf(undefined), {invisible: 0, mixed: 0, styled: false});
		assert.equal(obfuscationOf('Verify your pаypаl account').mixed, 1);
	});
});

describe('links', () => {
	it('finds links in text and HTML anchors, with the text shown', () => {
		const links = extractLinks('See www.example.com/page and https://shop.example.net/a?b=c.', '<a href="https://evil.example/login">https://paypal.com</a> <a href=\'https://example.org/x\'>Click</a> <a href=https://bare.example/>bare</a> <a href="mailto:x@example.org">mail</a> <a href="javascript:alert(1)">x</a> <a href="http://[::1">bad</a>');
		const urls = links.map(link => link.url);
		assert.ok(urls.includes('http://www.example.com/page'));
		assert.ok(urls.includes('https://shop.example.net/a?b=c'));
		assert.ok(urls.includes('https://evil.example/login'));
		assert.ok(urls.includes('https://bare.example/'));
		assert.ok(!urls.some(url => url.startsWith('mailto') || url.startsWith('javascript')));
		assert.equal(links.find(link => link.host === 'evil.example').text, 'https://paypal.com');
		assert.equal(links.find(link => link.host === 'example.org').text, null);
	});

	it('decodes entities in links and skips duplicates', () => {
		const links = extractLinks('', '<a href="https://example.org/?a=1&amp;b=2">x</a><a href="https://example.org/?a=1&amp;b=2">x</a>&#x41;&#65;&#0;&bogus;');
		assert.equal(links.length, 1);
		assert.equal(links[0].url, 'https://example.org/?a=1&b=2');
	});

	it('handles missing text and HTML', () => {
		assert.deepEqual(extractLinks(undefined, undefined), []);
		assert.deepEqual(extractLinks('example.com/path', ''), [{url: 'http://example.com/path', host: 'example.com', text: null}]);
	});

	it('flags links whose text names another site', () => {
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'https://paypal.com'}), true);
		assert.equal(isDeceptiveLink({host: 'www.paypal.com', text: 'paypal.com/signin'}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: null}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'localhost'}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'http://[bad'}), false);
	});

	it('finds registrable domains', () => {
		assert.equal(registrableDomain('mail.example.co.uk'), 'example.co.uk');
		assert.equal(registrableDomain('192.0.2.1'), '192.0.2.1');
		assert.equal(registrableDomain('localhost'), 'localhost');
		assert.equal(registrableDomain(''), '');
	});
});

describe('getFeatures', () => {
	it('describes a plain message', async () => {
		const mail = await parse(message({
			subject: 'Lunch on Thursday', text: 'Hi Bob, lunch on Thursday at noon? Call +1 555 010 0199 or mail alice@example.org. Order 12345678.',
		}));
		const {features, words, language, links} = getFeatures(mail);
		for (const feature of ['lunch', 'lunch on', 's:lunch', 'lang:en', 'script:Latin', 'pat:phone', 'pat:email', 'from:example.org', 'att:count:0', 'hdr:received:0', 'num:8']) {
			assert.ok(features.includes(feature), feature);
		}

		assert.ok(words.includes('thursday'));
		assert.equal(language, 'en');
		assert.deepEqual(links, []);
	});

	it('describes HTML-only mail with forms, scripts, hidden text, images and tracking pixels', async () => {
		const html = '<html><style>p{}</style><p style="display:none">hidden words</p><form><input></form><script>x()</script><iframe></iframe><img src="a.png"><img src="b.png" width="1" height="1"><a href="https://192.0.2.7/x">Win</a></html>';
		const mail = await parse(message({subject: 'WIN A FREE PRIZE NOW!!! 🎉', html}));
		const {features} = getFeatures(mail);
		for (const feature of ['html:only', 'html:form', 'html:script', 'html:embed', 'html:hidden', 'html:img:1', 'html:img_little_text', 'html:pixel', 'url:ip', 's:caps', 's:punct', 's:emoji']) {
			assert.ok(features.includes(feature), feature);
		}
	});

	it('describes links, senders and obfuscation', async () => {
		const mail = await parse(message({
			from: '"service@paypal.com" <alerts@gmail.com>',
			headers: {
				'Reply-To': 'refunds@yahoo.com', 'X-Mailer': 'MassMailer/2.0', 'List-Unsubscribe': '<mailto:u@example.org>', 'List-Id': '<list.example.org>', Precedence: 'bulk', 'X-Priority': '1', Received: 'from a by b; Mon, 05 Oct 2026 09:30:00 +0000',
			},
			subject: 'Re: your pаyment', // Cyrillic а
			text: 'Pay with bitcoin 1BoatSLRHtKNngkdXEeobR76b53LETtpyT now, $500 only. fr\u{200B}ee g\u{200B}ift \u{1D405}\u{1D411}\u{1D404}\u{1D404} v1agra https://bit.ly/abc http://user@xn--pple-43d.com/ https://evil.example/ 1.2.3.4 4111 1111 1111 1111 Supercalifragilisticexpialidociouslywonderfulword',
			html: '<p>Pay now</p><a href="https://evil.example/pay">https://paypal.com/pay</a>',
		}));
		const {features} = getFeatures(mail);
		for (const feature of ['from:gmail.com', 'from:freemail', 'from:name_has_other_address', 'replyto:other_domain', 'replyto:freemail', 'hdr:mailer:massmailer', 'hdr:list_unsubscribe', 'hdr:list_id', 'hdr:precedence:bulk', 'hdr:priority_high', 'hdr:received:1', 's:reply', 'pat:btc', 'pat:money', 'pat:card', 'pat:ip', 'obf:invisible', 'obf:styled', 'obf:mixed', 'obf:leet', 'url:shortener', 'url:punycode', 'url:userinfo', 'url:deceptive', 'html:alternative', 'long:Latin:4']) {
			assert.ok(features.includes(feature), feature);
		}
	});

	it('works on hand-built mail objects and missing parts', () => {
		const headers = new Map([['received', ['a', 'b', 'c', 'd']], ['importance', 'High'], ['x-mailer', {value: 'Thing'}], ['user-agent', ['Ua 1.0']]]);
		const {features} = getFeatures({
			headers, subject: '', attachments: [{filename: 'Invoice.PDF', contentType: 'application/pdf'}, {contentType: 'image/png'}, {filename: 'noextension'}],
		});
		for (const feature of ['from:none', 's:empty', 'body:empty', 'hdr:priority_high', 'hdr:received:3', 'hdr:no_message_id', 'hdr:no_date', 'att:ext:pdf', 'att:type:application/pdf', 'att:type:image/png', 'att:count:2', 'hdr:mailer:thing']) {
			assert.ok(features.includes(feature), feature);
		}

		assert.ok(getFeatures().features.includes('body:empty'));
		const noMailer = getFeatures({headers: new Map([['user-agent', ['Ua 1.0']]]), messageId: 'x', date: new Date()});
		assert.ok(noMailer.features.includes('hdr:mailer:ua'));
		assert.ok(noMailer.features.includes('hdr:received:0'));
	});

	it('reads HTML without a text part, decoding entities and skipping scripts', () => {
		const {features, words} = getFeatures({html: '<p>Caf&#xe9; &#77;enu &amp; drinks &#0; &bogus;</p><script>secretword()</script>', subject: 'Hello and Привет мир'});
		assert.ok(words.includes('café'));
		assert.ok(words.includes('menu'));
		assert.ok(!words.includes('secretword'));
		assert.ok(features.includes('html:only'));
		assert.ok(features.includes('script:mixed'));
	});

	it('copes with odd header values and addresses', () => {
		const headers = new Map([['x-mailer', {text: 'TextMailer 1'}], ['precedence', 12], ['content-type', 'text/html']]);
		const {features} = getFeatures({
			headers, subject: '12345 !!', text: 'plain text', html: '<p>plain text</p>', from: {value: [{address: 'nobody'}]}, replyTo: {value: [{address: 'x@other.example'}]},
		});
		for (const feature of ['hdr:mailer:textmailer', 'hdr:precedence:12', 'html:only', 'replyto:other_domain']) {
			assert.ok(features.includes(feature), feature);
		}

		assert.ok(!features.some(feature => feature.startsWith('from:tld')));
	});

	it('limits the words read and the word pairs made', () => {
		const {features} = getFeatures({text: 'alpha beta gamma delta epsilon '.repeat(100)}, {maxLength: 60, maxBigrams: 2});
		assert.ok(features.includes('alpha beta'));
		assert.ok(features.includes('beta gamma'));
		assert.ok(!features.includes('gamma delta'));
		assert.ok(features.includes('body:words:0'));
	});

	it('is the same for the same message', async () => {
		const raw = message({subject: 'Same', text: 'Exactly the same text every time'});
		const [a, b] = await Promise.all([parse(raw), parse(raw)]);
		assert.deepEqual(getFeatures(a).features.sort(), getFeatures(b).features.sort());
	});
});

describe('visibleText', () => {
	const shown = html => visibleText(html).text.replaceAll(/\s+/g, ' ').trim();

	it('reads text as a mail client shows it: inline tags join, blocks break', () => {
		assert.equal(shown('Free Sp<span>ins</span> now, <b>c</b>a<i>s</i>ino'), 'Free Spins now, casino');
		assert.equal(shown('<table><tr><td>a</td><td>b</td></tr></table><p>c</p>d<br>e'), 'a b c d e');
		assert.equal(shown('<!doctype html><!-- note --><head><title>T</title><style>p{}</style></head><script>x()</script><template>t</template>body'), 'body');
		// (as browsers do with what never closes)
		assert.equal(shown('a<!-- b'), 'a');
		assert.equal(shown('a<style>b'), 'a');
		assert.equal(shown('a < b and <3 <?php ?>'), 'a < b and <3');
		assert.equal(shown('a<!doctype'), 'a');
		assert.deepEqual(visibleText(''), {text: '', hidden: 0});
		assert.deepEqual(visibleText(null), {text: '', hidden: 0});
		assert.equal(readableText(null), '');
		assert.equal(readableText('Ｆr\u200Bee'), 'Free');
	});

	it('decodes character references as browsers do', () => {
		assert.equal(shown('caf&eacute; &Eacute; &AMP; &amp;lt; &euro;5 &#x48;&#105; &zwnj;'), 'café É & &lt; €5 Hi ‌');
		// (by number also without a ";", C1 controls as Windows-1252, and what no
		//  character is as U+FFFD)
		assert.equal(decodeEntities('V&#105agra don&#146;t &#x0000000041; &#0;&#55296;&#x110000;'), 'Viagra don\u2019t A \uFFFD\uFFFD\uFFFD');
		// (the names browsers read without a ";", in text, not in an attribute
		//  where a letter, digit or "=" follows)
		assert.equal(decodeEntities('Free&nbspSpins &amp &notin;'), 'Free\u00A0Spins & &notin;');
		assert.equal(decodeEntities('?a=1&copy=2&amp;b&lt', {attribute: true}), '?a=1&copy=2&b<');
		// (an unknown name, and names of object properties, stay)
		assert.equal(decodeEntities('&nosuch; &constructor; &__proto__; &zz'), '&nosuch; &constructor; &__proto__; &zz');
	});

	it('leaves out what the HTML hides, and counts it', () => {
		for (const style of ['font-size:5%', 'font-size:0.05rem', 'display:none', 'DISPLAY : NONE', 'visibility:hidden', 'opacity:0', 'opacity:0.0', 'color:transparent', 'font-size:0', 'font-size:1px', 'font-size:0.5pt', 'font-size:0em', 'max-height:0;overflow:hidden', 'height:0px; overflow: hidden']) {
			const result = visibleText(`<p>Buy now</p><div style="${style}">harmless filler words</div><p>today</p>`);
			assert.equal(result.text.replaceAll(/\s+/g, ' ').trim(), 'Buy now today', style);
			assert.equal(result.hidden, 'harmlessfillerwords'.length, style);
		}

		// (in any quotes, or none)
		assert.equal(shown('<p style=\'display:none\'>a</p><p style=display:none>b</p>c'), 'c');
		// (also by the attribute, nested, and to the end of the hiding element)
		assert.equal(shown('<span hidden>a</span>b<div style="display:none"><div>c</div>d</div>e'), 'b e');
		// (not a value saying "hidden", a font of a readable size, or a box
		//  that only clips)
		assert.equal(shown('<div class="hidden" title=" hidden">a</div><p style="font-size:12px">b</p><p style="overflow:hidden">c</p>'), 'a b c');
	});

	it('reads styles as browsers do', () => {
		// (a child can show again what is invisible, transparent or in a tiny
		//  font where it is, as responsive templates do, but not what an
		//  element hides)
		assert.equal(shown('<div style="font-size:0px"><table><tr><td style="font-size:0"><div style="font-size:13px">Your order shipped</div></td></tr></table></div>'), 'Your order shipped');
		assert.equal(shown('<div style="visibility:hidden">a<span style="visibility:visible">b</span></div>'), 'b');
		assert.equal(shown('<div style="color:transparent">a<span style="color:red">b</span></div>'), 'b');
		assert.equal(shown('<div style="font-size:0">a<span style="font-size:2em">b</span><span style="font-size:larger">c</span></div>'), '');
		assert.equal(shown('<div style="display:none"><span style="display:block">a</span></div>'), '');
		// (the last declaration wins, an important one over the rest; a value
		//  is read whole, in units browsers know)
		assert.equal(shown('<p style="display:none;display:block">a</p><p style="display:block!important;display:none">b</p><p style="display:nonesuch">c</p>'), 'a b c');
		assert.equal(shown('<p style="font-size:1in">a</p><p style="font-size:1e1px">b</p><p style="font-size:1pc">c</p><p style="font-size:-5px">d</p><p style="font-size:2vw">e</p>'), 'a b c d e');
		assert.equal(shown('<p style="FONT-SIZE:0.9PX">a</p><p style="opacity:0%">b</p><p style="display:/* x */none">c</p><p style="display&#58;none">d</p><p style="font:0/0 a">e</p>f'), 'f');
		assert.equal(shown('<p style="color:rgba(0,0,0,0)">a</p><p style="color:#fff0">b</p><p style="color:#ffffff00">c</p><p style="color:rgb(0 0 0 / 0%)">d</p><p style="color:rgba(0,0,0,0.5)">e</p>'), 'e');
		assert.equal(shown('<p style="height:0;overflow:hidden;min-height:40px">a</p><p style="text-indent:-9999px">b</p><p style="position:absolute;left:-10000px">c</p><p style="position:relative;left:-10000px">d</p>'), 'a d');
		// (attributes as browsers read them: the first of a name, values in
		//  quotes or not, a quote opening a value only after "=")
		assert.equal(shown('<div title=" style=display:none">a</div><div class= hidden>b</div><div style="color:red" style="display:none">c</div><div/style="display:none">d</div>'), 'a b c');
		assert.equal(shown('<b x\'>BUY</b> now don\'t>'), 'BUY now don\'t>');
		assert.equal(shown(`<div title="${'a'.repeat(7000)}>ham words">x</div>`), 'x');
	});

	it('reads what is left unfinished or unusual as browsers do', () => {
		// (a quoted value or a comment the input ends in, a declaration without
		//  a value, a number too large, a "</" at the end)
		assert.equal(shown('a<p title="b'), 'a');
		assert.equal(shown('a</'), 'a</');
		assert.equal(shown(`<p style="color:red;/* display:none">a</p><p style="junk;display:none">b</p><p style="font-size:1e999px">c</p><p style="font-size:${'0'.repeat(70)}px">d</p>`), 'a c d');
		// (sizes in ex, ch, keywords, and relative ones)
		assert.equal(shown('<div style="font-size:2px"><span style="font-size:1ch">a</span><span style="font-size:small">b</span></div><div style="font-size:1.1px">c<span style="font-size:smaller">d</span></div>'), 'b c');
		// (an opaque colour, a box of no width, a page position out of view)
		assert.equal(shown('<p style="color:rgb(0,0,0)">a</p><p style="width:0;overflow:hidden">b</p><p style="position:fixed;top:-2000px">c</p><p style="position:absolute;left:auto">d</p><p style="font:inherit">e</p>'), 'a d e');
		// (a <style> that closes itself in an <svg>)
		assert.equal(shown('<svg><style/>a</svg>'), 'a');
	});

	it('ends comments and raw text as browsers do', () => {
		// (a comment joins what is around it)
		assert.equal(shown('<!-->a<!--->b<!-- c --!>d'), 'abd');
		assert.equal(shown('<xmp><b>a</b></xmp><textarea>&lt;c&gt;<!--</textarea>d'), '<b>a</b> <c><!-- d');
		assert.equal(shown('<image hidden src=x>a<keygen hidden>b'), 'a b');
		assert.equal(shown('</>a</ b>c'), 'ac');
	});

	it('reads elements as browsers do', () => {
		// (unknown and custom elements are shown in the line, so they join a
		//  word; an image or a field breaks it)
		assert.equal(shown('V<foo>iag</foo>ra Fr<o:p>ee</o:p> a<img src=x>b'), 'Viagra Free a b');
		// (an end tag does not close through a block open inside it)
		assert.equal(shown('<span style="display:none"><div>x</span>ham</div>tail'), '');
		assert.equal(shown('<div style="display:none"><b>x</div>shown'), 'shown');
		// (a closed <details> shows only its summary; a template nothing; the
		//  hidden attribute yields to a style that shows the element)
		assert.equal(shown('<details><summary>S</summary>body</details>after <details open><summary>T</summary>text</details>'), 'S after T text');
		assert.equal(shown('<template><template>a</template>b</template>c<div hidden style="display:block">d</div>'), 'c d');
		// (a font size after the weight; a negative opacity; <plaintext> to the
		//  end; a "/" ending a value, not the tag)
		assert.equal(shown('<p style="font:400 0px Arial">a</p><p style="font:bold 12px/1.4 Arial">b</p><p style="opacity:-1">c</p><div title=a/>d</div>e<plaintext><b>f'), 'b d e <b>f');
		// (past the most open elements kept, an element goes in beside the
		//  innermost)
		assert.equal(shown(`${'<div>'.repeat(1024)}<span style="display:none">a</span>b`), 'b');
	});

	it('ends a hidden element where a browser does', () => {
		assert.equal(shown(`<div style="display:none">x${'<b>'.repeat(70)}</div>a`), 'a');
		assert.equal(shown('<table><tr style="display:none"><td>x<tr><td>a</table>'), 'a');
		assert.equal(shown('<table><thead style="display:none"><tr><td>x<tbody><tr><td>a</table>'), 'a');
		assert.equal(shown('<ul><p hidden>x<li>a</ul>'), 'a');
		// (a paragraph at the next block, a cell at the next cell, an element
		//  at the end of the one it is in)
		assert.equal(shown('<p style="display:none">a<div>b</div>'), 'b');
		assert.equal(shown('<table><tr><td style="display:none">a<td>b</table>'), 'b');
		assert.equal(shown('<table><tr><td><div style="display:none">a</td><td>b</td></tr></table>'), 'b');
		// (an element that closes itself only in an <svg>)
		assert.equal(shown('<span style="display:none"/>a'), '');
		assert.equal(shown('<svg><rect style="display:none"/></svg>a<svg><rect hidden / ></svg>b'), 'a b');
	});
});

describe('the parts of a message read', () => {
	const words = mail => new Set(getFeatures(mail).words);

	it('reads the words of the HTML a mail client shows, not a plain part beside it', async () => {
		const mail = await simpleParser(message({
			text: 'Hi Bob, see you at lunch on Tuesday. Regards, Alice. Let me know which place works, and whether Carol is coming too.',
			html: '<p>Cheap pi<span>lls</span> online, buy now, limited offer, best prices guaranteed for everyone today only, no questions asked, shipped worldwide in discreet packages within days</p>',
		}));
		const read = words(mail);
		assert.ok(read.has('pills'));
		assert.ok(!read.has('tuesday'));
		// (a plain part saying something else than the HTML)
		assert.ok(getFeatures(mail).features.includes('html:text_mismatch'));
	});

	it('compares at most 2000 words of each part', () => {
		const many = Array.from({length: 2500}, (_, i) => `w${i.toString(36)}x`).join(' ');
		const {features} = getFeatures({html: `<p>${many}</p>`, text: many});
		assert.ok(!features.includes('html:text_mismatch'));
	});

	it('reads the plain part too when the HTML shows little text, as an image of the message', async () => {
		const mail = await simpleParser(message({
			text: 'Save money on your prescriptions with our online pharmacy offer',
			html: '<p>Click <img src="cid:offer"> to continue</p>',
		}));
		assert.ok(words(mail).has('pharmacy'));
		assert.ok(!getFeatures(mail).features.includes('html:text_mismatch'));
	});

	it('leaves hidden filler out of the words but reads links and host names everywhere', () => {
		const features = getFeatures({
			html: '<p>Your account is locked</p><div style="display:none">weather report garden recipes <a href="https://hidden.example/x">x</a> https&#58;//encoded.example/y</div>',
			text: 'Go to https://plain.example/z or paypa1.com',
		});
		assert.ok(!features.words.includes('weather'));
		assert.ok(features.features.includes('html:hidden_text'));
		assert.ok(features.hidden > 0);
		assert.deepEqual(features.links.map(link => link.host).sort(), ['encoded.example', 'hidden.example', 'plain.example']);
		const visible = getFeatures({html: '<p>See https&#58;//encoded.example/y</p>'});
		assert.ok(visible.links.some(link => link.url === 'https://encoded.example/y'));
		assert.equal(visible.text.trim(), 'See https://encoded.example/y');
	});
});
