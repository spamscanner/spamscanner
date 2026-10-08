import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {simpleParser} from 'mailparser';
import {
	characterClass, chunk, extractLinks, getFeatures, isDeceptiveLink, normalizeText, registrableDomain, segmentWords,
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
