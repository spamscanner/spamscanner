import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {simpleParser} from 'mailparser';
import {
	characterClass, chunk, decodeEntities, extractHosts, extractLinks, getFeatures, isDeceptiveLink, normalizeText, obfuscationOf, readableText, registrableDomain, segmentWords, unmixedText, unwrapLink, visibleText,
} from '../src/tokenizer.js';
import SpamScanner from '../src/index.js';
import {drawnQrCode} from '../src/qr.js';
import {message} from './helpers/index.js';
import {cpuTime} from './helpers/cpu-time.js';

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
		const started = cpuTime();
		const {words} = segmentWords('Congratulations you have won a free prize click here now. '.repeat(2700), {maxLength: 200_000});
		assert.ok(words.length > 20_000);
		assert.ok(cpuTime() - started < 5000);
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

	it('reads names right after Chinese, Japanese or Thai text, written without spaces', () => {
		assert.deepEqual(extractHosts('\u8BF7\u767B\u5F55paypa1.com\u786E\u8BA4'), ['paypa1.com']);
		// (also after a Thai mark)
		assert.deepEqual(extractHosts('\u0E01\u0E23\u0E38\u0E13\u0E32\u0E40\u0E02\u0E49\u0E32\u0E2A\u0E39\u0E48paypa1.com'), ['paypa1.com']);
		assert.deepEqual(extractLinks('\u8ACB\u8A2A\u554Fpaypal-secure.com/login \u3053\u3061\u3089evil.example.com/login', '').map(link => link.host), ['paypal-secure.com', 'evil.example.com']);
		// (not after a Latin letter, nor a Korean one: Korean has spaces)
		assert.deepEqual(extractLinks('stra\u00DFe.de/x \uD55C\uAD6Dpaypal.com/x', ''), []);
	});

	it('reads, for the links looked up, a link without "http://" after punctuation in another link', () => {
		const hosts = (text, html = '') => extractLinks(text, html, {bareHosts: true}).map(link => link.host);
		// (only with bareHosts: the links the classifier learned from are as before)
		assert.deepEqual(extractLinks('Mirror: a.example.org/x,evil.example.com/y', '').map(link => link.host), ['a.example.org']);
		assert.deepEqual(hosts('Mirror: a.example.org/x,evil.example.com/y'), ['a.example.org', 'evil.example.com']);
		assert.deepEqual(hosts('', '<p>a.example.org/x|evil.example.com/y</p>'), ['a.example.org', 'evil.example.com']);
		// (not a name in a path, in a word, or in a link with "://" before it;
		//  nor a name under no real public suffix)
		assert.deepEqual(hosts('github.com/x/example.net/ stra\u00DFe.de/x https://x!y.evil.example/z a.b1/ -.example/ .com/ file.js/ readme.md/'), ['github.com', 'x!y.evil.example', 'readme.md']);
		// (after a link that a quote, "<" or any space ends, as links end)
		assert.deepEqual(hosts('', '<img src="https://cdn.example.org/p.png"><p>a.example.org/x,evil.example.com/y</p>'), ['cdn.example.org', 'a.example.org', 'evil.example.com']);
		assert.deepEqual(hosts('https://t.example.org/x\u00A0a.example.org/x,evil.example.com/y'), ['t.example.org', 'a.example.org', 'evil.example.com']);
		// (with a port or dots after it; under a top-level domain as links
		//  without "http://" are, also one of files or in punycode)
		assert.deepEqual(hosts('a.example.org/x,evil.example.com./y,evil.example.net:8080/y,evil.example.info:/y,login.app/y,update.zip/y,evil.xn--p1ai/y'), ['a.example.org', 'evil.example.com', 'evil.example.net', 'evil.example.info', 'login.app', 'update.zip', 'evil.xn--p1ai']);
		// (as links "http://host/", marked as found without one)
		assert.deepEqual(extractLinks('a.example.org/x,evil.example.com/y', '', {bareHosts: true}).map(link => [link.url, link.bare]), [['http://a.example.org/x,evil.example.com/y', undefined], ['http://evil.example.com/', true]]);
		// (a link of another part with that host is a link)
		assert.deepEqual(extractLinks('a.example.org/x,evil.example.com/y', '<p>Visit http://evil.example.com/</p>', {bareHosts: true}).map(link => [link.url, link.bare]), [['http://a.example.org/x,evil.example.com/y', undefined], ['http://evil.example.com/', undefined]]);
		// (each once, however often)
		assert.deepEqual(hosts('a.example.org/x,evil.example.com/y;evil.example.com/z ;evil.example.com/w'), ['a.example.org', 'evil.example.com']);
		// (in linear time, however the text is made)
		const started = cpuTime();
		hosts(`${'a.'.repeat(300_000)}b/ ${',a.bc/'.repeat(100_000)}${'/'.repeat(300_000)}`);
		assert.ok(cpuTime() - started < 3000);
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
		assert.deepEqual(normalizeText('fr\u{200B}ee m\u{2060}oney'), {text: 'free money', invisible: 2, styled: false});
		assert.equal(normalizeText('\u{1D405}\u{1D411}\u{1D404}\u{1D404}').text, 'free');
		assert.equal(normalizeText('\u{1D405}REE').styled, true);
		assert.equal(normalizeText('ｆｒｅｅ').text, 'free');
		// (joiners, which Persian, Indic scripts and emoji need)
		assert.equal(normalizeText('\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645 \u0915\u094D\u200D\u0937 \u{1F468}\u200D\u{1F469} a\u200D\u{1F469}').invisible, 0);
	});

	it('counts joiners between Latin letters, and a zero width space after one', () => {
		assert.equal(normalizeText('v\u200Ci\u200Ca\u200Dgra').invisible, 3);
		assert.equal(normalizeText('fr\u200D\u200Bee').invisible, 2);
		assert.equal(normalizeText('fr\u200B\u200Dee').invisible, 2);
		assert.equal(normalizeText('pay\u200C\u0430').invisible, 0);
	});

	it('takes a zero width space between letters of Thai, Lao, Khmer, Burmese or Tibetan for a word break', () => {
		// (as writers of those scripts put them where a word ends)
		for (const text of ['\u0E40\u0E23\u0E35\u0E22\u0E19\u200B\u0E04\u0E38\u0E13\u200B\u0E2A\u0E21\u0E0A\u0E32\u0E22', '\u179F\u17BC\u1798\u200B\u17A2\u179A\u1782\u17BB\u178E\u200B\u179F\u1798\u17D2\u179A\u17B6\u1794\u17CB', '\u0E82\u0EAD\u0E9A\u200B\u0EC3\u0E88', '\u1000\u103B\u1031\u1038\u200B\u1007\u1030\u1038', '\u0F56\u0F40\u0FB2\u200B\u0F64\u0F72\u0F66']) {
			assert.equal(normalizeText(text).invisible, 0, text);
		}

		// (but between Latin letters, or a Thai letter and a Latin one, and
		//  other invisible characters there)
		assert.equal(normalizeText('\u0E04\u0E38\u200Bfr\u200Bee \u0E04\u200Bx \u0E04\u2060\u0E38').invisible, 4);
	});

	it('counts invisible characters only between letters, and not those other scripts need', () => {
		assert.equal(normalizeText('fr\u200B\u200Bee').invisible, 2);
		assert.equal(normalizeText('\uFEFFHello \u200Bworld\u200B. 12\u200B34 a\u200B').invisible, 0);
		// (soft hyphens are hints where a word may break)
		assert.deepEqual(normalizeText('Garten\u00ADm\u00F6bel und Kinder\u00ADspielzeug'), {text: 'gartenmöbel und kinderspielzeug', invisible: 0, styled: false});
		// (bidirectional marks in Hebrew and Arabic text, but not in Latin text)
		assert.equal(normalizeText('\u05E9\u05DC\u05D5\u05DD\u200F, \u05EA\u05D5\u05D3\u05D4\u200F\u05D0').invisible, 0);
		assert.equal(normalizeText('\u202B\u0645\u0631\u062D\u0628\u0627 2026\u202C \u0648\u202Ba\u202Cb \u2067\u0645\u2069x').invisible, 0);
		assert.equal(normalizeText('pay\u202Epal').invisible, 1);
		// (but not the overrides, which change the order letters are shown in,
		//  with a Hebrew or Arabic letter or not)
		assert.equal(normalizeText('pay\u202Epal \u05E9').invisible, 1);
		assert.equal(normalizeText('\u0645\u0631 pa\u202Dy\u202Epal').invisible, 2);
		// (a zero width space in Hebrew text all the same)
		assert.equal(normalizeText('\u05E9\u200B\u05DC').invisible, 1);
	});

	it('counts invisible characters between a letter and a digit, not between digits', () => {
		assert.equal(normalizeText('v\u200B1\u200Bagra').invisible, 2);
		assert.equal(normalizeText('fr3\u2060e c\u200B4sh').invisible, 2);
		// (put in numbers so phones do not take them for phone numbers)
		assert.equal(normalizeText('Call 555\u200B010\u200B0100 or visit 12\u200B34 Main St').invisible, 0);
		assert.equal(getFeatures({text: 'Buy v\u200B1\u200Bagra now'}).features.includes('obf:invisible'), true);
	});

	it('takes fullwidth letters and circled numbers for styled ones only without Chinese, Japanese or Korean', () => {
		assert.equal(normalizeText('\u3054\u6CE8\u6587\u756A\u53F7\uFF1A\uFF21\uFF22\uFF11\uFF12\uFF13 \u2460\u30ED\u30B0\u30A4\u30F3').styled, false);
		assert.equal(normalizeText('\uB3C8 \uFF26\uFF52\uFF45\uFF45').styled, false);
		assert.equal(normalizeText('\uFF26\uFF52\uFF45\uFF45 money').styled, true);
		assert.equal(normalizeText('Step \u2460').styled, true);
		assert.equal(normalizeText('\u5B57 \u{1D405}\u{1D411}\u{1D404}\u{1D404}').styled, true);
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

	it('keeps single Korean syllables', () => {
		assert.deepEqual(segmentWords('\uB3C8 \uC744 \uBC8C\uB2E4 \uC9C0\uAE08').words, ['\uB3C8', '\uC744', '\uBC8C\uB2E4', '\uC9C0\uAE08']);
	});

	it('takes order numbers and terms with digits for no leet words', () => {
		const result = segmentWords('Order AB12CD ships via UPS 1Z999AA10123456784, see i18n, k8s, mp3, win10 and l10n');
		assert.equal(result.leet, 0);
		assert.ok(result.words.includes('ab12cd'));
		assert.ok(result.words.includes('1z999aa10123456784'));
		assert.ok(result.words.includes('i18n'));
		assert.equal(segmentWords('fr33dom v14gr4 h4x0r c4sh').leet, 4);
		// (more than three digits, or a run of three)
		assert.equal(segmentWords('v1a4g3r4a fr333dom').leet, 0);
	});

	it('takes no unit for a word mixing scripts', () => {
		const result = segmentWords('Dose 10 \u00B5g daily, filter 5 \u00B5m, 4.7 k\u2126');
		assert.equal(result.mixed, 0);
		assert.ok(result.words.includes('\u03BCg'));
		assert.equal(segmentWords('\u03BCpaypal').mixed, 1);
		assert.equal(segmentWords('p\u03B1yp\u03B1l').mixed, 1);
		assert.equal(obfuscationOf('Dose 10 \u00B5g, 4.7 k\u2126, p\u03B1yp\u03B1l').mixed, 1);
	});

	it('reads at most maxLength characters after folding', () => {
		const started = cpuTime();
		const {words} = segmentWords('\uFDFA'.repeat(100_000));
		assert.ok(words.join('').length <= 100_000);
		assert.ok(cpuTime() - started < 2000);
		assert.deepEqual(segmentWords('\uFDFA', {maxLength: 5}).words, ['\u0635\u0644\u0649']);
		assert.ok(obfuscationOf(`${'\uFDFA'.repeat(10)}p\u0430ypal`, {maxLength: 10}).mixed === 0);
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

	it('takes a Greek letter of a unit for no other script only in a unit', () => {
		assert.equal(obfuscationOf('Take 10 \u00B5g, 10\u00B5mol or 3 \u03BCs through 5 k\u2126 and 2 M\u2126').mixed, 0);
		assert.equal(obfuscationOf('\u03BCpdate your account on our \u03C9ebsite').mixed, 2);
		assert.equal(obfuscationOf('An area of 4 \u00B5m\u00B2, 0.1\u00B5m\u00B2 or 3 \u00B5m2').mixed, 0);
		assert.equal(obfuscationOf('Download \u00B5Torrent').mixed, 1);
		assert.deepEqual(segmentWords('\u03BCpdate now').words, ['update', 'now']);
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
		assert.deepEqual(extractLinks('example.com/path', ''), [{
			url: 'http://example.com/path', host: 'example.com', text: null, userinfo: false,
		}]);
	});

	it('flags links whose text names another site', () => {
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'https://paypal.com'}), true);
		assert.equal(isDeceptiveLink({host: 'www.paypal.com', text: 'paypal.com/signin'}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: null}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'localhost'}), false);
		// (of a sender that passes DMARC, only the address of a brand it is not)
		assert.equal(isDeceptiveLink({host: 'links.mailer-service.example', text: 'www.shop.example'}, {from: 'mail.shop.example', authenticated: true}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'paypal.com/myaccount'}, {from: 'evil.example', authenticated: true}), true);
		assert.equal(isDeceptiveLink({host: 'links.mailer-service.example', text: 'www.paypal.com'}, {from: 'mail.paypal.com', authenticated: true}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'paypal.com'}, {authenticated: true}), false);
		// (nor a partner's name over its own click tracking, which is on its
		//  own domain: only a brand's address that asks to sign in or pay)
		for (const text of ['www.apple.com', 'amazon.co.uk', 'https://www.paypal.com/', 'www.visa.com', 'facebook.com']) {
			assert.equal(isDeceptiveLink({host: 'click.mail.bigstore.example', text}, {from: 'mail.bigstore.example', authenticated: true}), false, text);
			assert.equal(isDeceptiveLink({host: 'click.mail.bigstore.example', text}, {from: 'mail.bigstore.example'}), true, text);
			// (another's, a brand's front page, but not one newsletters link to
			//  as a matter of course)
			assert.equal(isDeceptiveLink({host: 'click.other.example', text}, {from: 'mail.bigstore.example', authenticated: true}), text !== 'facebook.com', text);
		}

		for (const text of ['paypal.com/signin', 'https://www.apple.com/account/billing', 'www.facebook.com/login']) {
			assert.equal(isDeceptiveLink({host: 'click.mail.bigstore.example', text}, {from: 'mail.bigstore.example', authenticated: true}), true, text);
		}

		// (or the page it goes to does, not its click tracking)
		const page = url => isDeceptiveLink({host: 'click.mail.bigstore.example', url, text: 'www.paypal.com'}, {from: 'mail.bigstore.example', authenticated: true});
		assert.deepEqual(['https://click.mail.bigstore.example/login', 'https://click.mail.bigstore.example/secure/verify?id=1', 'https://click.mail.bigstore.example/c/eyJ1IjoiMSJ9', 'https://click.mail.bigstore.example/?qs=5f1a', 'not an address'].map(url => page(url)), [true, true, false, false, false]);

		// (a provider of mailboxes holds anyone's pages on its domain)
		assert.equal(isDeceptiveLink({host: 'sites.gmail.com', text: 'www.paypal.com'}, {from: 'gmail.com', authenticated: true}), true);
		// (nor any of a known sender that goes to its own domain)
		assert.equal(isDeceptiveLink({host: 'click.mail.bigstore.example', text: 'paypal.com/signin'}, {from: 'mail.bigstore.example', authenticated: true, known: true}), false);
		assert.equal(isDeceptiveLink({host: 'click.mail.bigstore.example', text: 'www.apple.com'}, {from: 'mail.bigstore.example', authenticated: true, known: true}), false);
		assert.equal(isDeceptiveLink({host: 'click.mail.bigstore.example', text: 'www.apple.com'}, {from: 'mail.bigstore.example', known: true}), true);
		// (and on another domain, only an address that asks to sign in: an
		//  order shipped, under the carrier's address)
		assert.equal(isDeceptiveLink({host: 'shop-tracking.example', text: 'www.ups.com'}, {from: 'mail.bigstore.example', authenticated: true, known: true}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'www.apple.com/account/signin'}, {from: 'mail.bigstore.example', authenticated: true, known: true}), true);
		assert.equal(isDeceptiveLink({host: 'shop-tracking.example', text: 'www.ups.com'}, {from: 'mail.bigstore.example', authenticated: true}), true);
		// (the brand by its domain, not its name on another one)
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'https://www.paypal.com/signin'}, {from: 'paypal.top', authenticated: true}), true);
		// (another domain of the company whose address is shown is its own
		//  site, whoever sends it)
		for (const [text, host] of [['www.tangocard.com', 'www.rewardlink.com'], ['redeem.microsoft.com', 'www.xbox.com'], ['www.amazon.co.uk', 'www.amazon.com'], ['xfinity.com', 'customer.comcast.com'], ['https://www.icloud.com/', 'support.apple.com'], ['www.paypal.de', 'data.news.paypal.com'], ['zoom.com', 'click.e.zoom.us'], ['www.americanexpress.es', 'go.amex'], ['citibank.com', 'click.info.citi.com']]) {
			assert.equal(isDeceptiveLink({host, text}), false, text);
			assert.equal(isDeceptiveLink({host, text}, {from: 'mail.shop.example', authenticated: true}), false, text);
		}

		// (a payment service's address in a shop's footer, over the click
		//  tracking of the shop's mailing service; a sign-in address still counts)
		for (const host of ['cdn.uk.exponea.com', 'uk1-cdn.eng.bloomreach.com', 'click.mlsend.com']) {
			assert.equal(isDeceptiveLink({host, text: 'klarna.com'}, {from: 'mail.shop.example', authenticated: true}), false, host);
			assert.equal(isDeceptiveLink({host, text: 'https://www.paypal.com/signin'}, {from: 'mail.shop.example', authenticated: true}), true, host);
		}

		// (not where anyone publishes under the company's name, a domain of
		//  another company, or a look-alike)
		for (const [text, host] of [['www.microsoft.com', 'forms.office.com'], ['microsoft.com', 'contoso.sharepoint.com'], ['redeem.microsoft.com', 'www.amazon.com'], ['redeem.microsoft.com', 'xbox.com.evil.example']]) {
			assert.equal(isDeceptiveLink({host, text}), true, text);
			assert.equal(isDeceptiveLink({host, text: `https://${text}/`}, {from: 'mail.shop.example', authenticated: true}), true, text);
		}

		// (a brand newsletters link to: its sign-in address, not another page
		//  of it, nor its front page from a sender that passes DMARC)
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'https://www.facebook.com/login'}, {from: 'evil.example', authenticated: true}), true);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'facebook.com'}, {from: 'other.example', authenticated: true}), false);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'facebook.com'}, {from: 'other.example'}), true);
		// (a file shared, under WeTransfer's name)
		assert.equal(isDeceptiveLink({host: 'files.cdn.example', text: 'studio.wetransfer.com'}, {from: 'studio.example'}), true);
		assert.equal(isDeceptiveLink({host: 'links.mailer-service.example', text: 'www.facebook.com/shop.example'}, {from: 'shop.example', authenticated: true}), false);
		// (through click tracking, as from any sender)
		assert.equal(isDeceptiveLink({host: 'example.us1.list-manage.com', text: 'www.paypal.com'}, {from: 'shop.example', authenticated: true}), false);
		assert.equal(isDeceptiveLink({host: 'example.us1.list-manage.com', text: 'https://www.paypal.com/signin'}, {from: 'shop.example', authenticated: true}), true);
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'http://[bad'}), false);
		// (CSID, Experian's click tracking for American Express CreditSecure)
		assert.equal(isDeceptiveLink({host: 'click.csid.com', text: 'https://www.americanexpress.com/'}, {from: 'mail.membershipmail.net', authenticated: true}), false);
	});

	it('takes a link to a domain that authenticated the message for the sender\'s own click tracking', () => {
		// (a shop that does not pass DMARC, through its mailing service's domain,
		//  which signed it and SPF passes for)
		const shop = {from: 'news.homes.example', senders: ['homes-marketing.example']};
		assert.equal(isDeceptiveLink({host: 'email.homes-marketing.example', text: 'www.apple.com/iphone/'}, {from: 'news.homes.example'}), true);
		assert.equal(isDeceptiveLink({host: 'email.homes-marketing.example', text: 'www.apple.com/iphone/'}, shop), false);
		assert.equal(isDeceptiveLink({host: 'email.homes-marketing.example', text: 'www.homes.example'}, shop), false);
		// (a partner shown, or the mailing service's own site)
		assert.equal(isDeceptiveLink({host: 'email.homes-marketing.example', text: 'www.partner.example'}, shop), false);
		assert.equal(isDeceptiveLink({host: 'other.example', text: 'homes-marketing.example'}, shop), false);
		// (a brand's address, only when it asks to sign in)
		assert.equal(isDeceptiveLink({host: 'email.homes-marketing.example', text: 'www.paypal.com'}, shop), false);
		assert.equal(isDeceptiveLink({host: 'email.homes-marketing.example', text: 'https://www.paypal.com/signin'}, shop), true);
		// (or the address it goes to does, by a word no click tracking link records)
		const page = url => isDeceptiveLink({host: 'email.homes-marketing.example', url, text: 'www.apple.com'}, shop);
		assert.deepEqual(['https://email.homes-marketing.example/login', 'https://email.homes-marketing.example/oauth2/authorize', 'https://email.homes-marketing.example/c/1?account=12&update=1', 'https://email.homes-marketing.example/secure/confirm', 'https://email.homes-marketing.example/u/billing'].map(url => page(url)), [true, true, false, false, false]);
		// (another domain of the company of one that signed it)
		assert.equal(isDeceptiveLink({host: 'click.citibank.com', text: 'amazon.com'}, {from: 'citi.com', authenticated: true}), false);
		assert.equal(isDeceptiveLink({host: 'click.citibank.com', text: 'amazon.com'}, {from: 'news.example', senders: ['citi.com']}), false);
		// (not a mailing service's click tracking, which anyone sends through:
		//  its rule for a brand's address holds)
		assert.equal(isDeceptiveLink({host: 'u1.ct.sendgrid.net', text: 'https://www.paypal.com'}, {from: 'shop.example', senders: ['sendgrid.net']}), true);
		// (nor a provider of mailboxes, nor a brand's domain, which carries
		//  anyone's mail: a shared document or a calendar invitation)
		assert.equal(isDeceptiveLink({host: 'sites.gmail.com', text: 'www.ssa.gov'}, {from: 'gmail.com', senders: ['gmail.com']}), true);
		assert.equal(isDeceptiveLink({host: 'docs.google.com', text: 'www.paypal.com'}, {from: 'gmail.com', authenticated: true, senders: ['google.com']}), true);
		assert.equal(isDeceptiveLink({host: 'docs.google.com', text: 'www.ssa.gov'}, {from: 'evil.example', senders: ['google.com']}), true);
		// (a brand's own sending domain, linking to itself)
		assert.equal(isDeceptiveLink({host: 'www.facebookmail.com', text: 'https://www.facebook.com/login'}, {from: 'facebookmail.com', authenticated: true}), false);
		assert.equal(isDeceptiveLink({host: 'www.facebookmail.com', text: 'https://www.facebook.com/login'}, {from: 'facebookmail.com', senders: ['facebookmail.com']}), true);
		// (a brand that signed it carries anyone's mail too: a PayPal invoice
		//  from a stranger)
		assert.equal(isDeceptiveLink({host: 'other.example', text: 'www.paypal.com'}, {from: 'news.example', senders: ['paypal.com']}), true);
	});

	it('takes another site than a brand\'s for no disguise, but a recipient\'s or a government\'s', () => {
		const recipients = ['customer.example'];
		assert.equal(isDeceptiveLink({host: 't.mailer.example', text: 'www.shop.example'}, {from: 'shop.example', recipients}), false);
		assert.equal(isDeceptiveLink({host: 't.mailer.example', text: 'www.shop.example/sale'}, {from: 'news.shop.example', recipients}), false);
		// (nor without recipients given, as getFeatures reads it)
		assert.equal(isDeceptiveLink({host: 't.mailer.example', text: 'www.shop.example'}, {from: 'shop.example'}), false);
		// (a phishing page under the recipient's own domain, from it, wherever
		//  the link goes)
		assert.equal(isDeceptiveLink({host: 'firebasestorage.googleapis.com', text: 'customer.example'}, {from: 'customer.example', recipients}), true);
		assert.equal(isDeceptiveLink({host: 'mail.customer.example', text: 'www.customer-files.example'}, {from: 'customer.example', recipients}), false);
		assert.equal(isDeceptiveLink({host: 'login.customer.example', text: 'customer.example'}, {from: 'customer.example', recipients}), false);
		assert.equal(isDeceptiveLink({host: 'www.shop.example', text: 'mail.customer.example'}, {from: 'shop.example', recipients}), true);
		// (or a sister site's address over a link to its own)
		assert.equal(isDeceptiveLink({host: 'www.north.example', text: 'www.south.example'}, {from: 'north.example', recipients}), false);
		// (nor another site, a person's, a project's or a shop's, whatever it
		//  links to: a site is named another way than where it is, "docs.example.dev"
		//  over its repository, "www.shop.example" over its shop's platform)
		for (const [host, text] of [['evil.example', 'www.courts.example'], ['github.com', 'https://docs.project.dev/'], ['myapp-staging.herokuapp.com', 'https://staging.myapp.io/login'], ['shop.platform.example', 'www.shop.example']]) {
			for (const options of [{from: 'shop.example', recipients}, {from: 'gmail.com', authenticated: true, recipients}, {}]) {
				assert.equal(isDeceptiveLink({host, text}, options), false, text);
			}
		}

		// (a recipient's domain from another sender, also one that passes
		//  DMARC, but not to the recipient's own domain from it)
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'https://mail.customer.example/owa'}, {from: 'gmail.com', authenticated: true, recipients}), true);
		assert.equal(isDeceptiveLink({host: 'customer.sharepoint.com', text: 'intranet.customer.example'}, {from: 'customer.example', authenticated: true, recipients}), false);
		// (from a sender that authenticated itself, only its front page, mail
		//  or sign-in host, or a page that asks to sign in or lures: a partner
		//  names another page of it over the host of a preview)
		for (const text of ['https://customer.example', 'www.customer.example/en/', 'https://webmail.customer.example/', 'https://owa.customer.example/', 'https://login.customer.example/', 'https://intranet.customer.example/signin', 'https://files.customer.example/invoice/2026']) {
			assert.equal(isDeceptiveLink({host: 'evil.example', text}, {from: 'vendor.example', authenticated: true, recipients}), true, text);
		}

		for (const text of ['https://staging.customer.example/', 'https://staging.customer.example/feature/checkout', 'https://www.customer.example/blog/launch']) {
			assert.equal(isDeceptiveLink({host: 'customer-staging.vercel.app', text}, {from: 'vendor.example', authenticated: true, recipients}), false, text);
			assert.equal(isDeceptiveLink({host: 'customer-staging.vercel.app', text}, {from: 'vendor.example', recipients}), true, text);
		}

		// (a government's site, from anyone but a known sender that passes
		//  DMARC, and not to another government's site, nor through click
		//  tracking or to the sender's own domain)
		for (const text of ['https://www.uscourts.gov/case', 'www.gov.uk/tax-refund', 'impots.gouv.fr', 'https://www.nta.go.jp/', 'canada.ca', 'https://ec.europa.eu/', 'https://www.service.nsw.gov.au/fines', 'detran.sp.gov.br', 'https://www.city.osaka.lg.jp/', 'https://nav.gov.hu/', 'www.belastingdienst.nl', 'https://www.ameli.fr/', 'www.nhs.uk', 'https://www.gosuslugi.ru/', 'elster.de', 'https://www.incometax.gov.in/']) {
			assert.equal(isDeceptiveLink({host: 'evil.example', text}, {from: 'shop.example', recipients}), true, text);
			assert.equal(isDeceptiveLink({host: 'evil.example', text}, {from: 'gmail.com', authenticated: true}), true, text);
			assert.equal(isDeceptiveLink({host: 'evil.example', text}, {from: 'shop.example', authenticated: true, known: true}), false, text);
		}

		assert.equal(isDeceptiveLink({text: 'https://www.uscourts.gov/'}, {from: 'shop.example'}), true);
		assert.equal(isDeceptiveLink({host: 'www.treasury.gov', text: 'https://www.irs.gov'}, {from: 'shop.example'}), false);
		assert.equal(isDeceptiveLink({host: 'www.canada.ca', text: 'https://www.cra-arc.gc.ca/'}, {from: 'shop.example'}), false);
		assert.equal(isDeceptiveLink({host: 'mijn.overheid.nl', text: 'www.belastingdienst.nl'}, {from: 'shop.example'}), false);
		// (not a site that only looks like a government's suffix)
		for (const text of ['www.nic.example', 'https://shop.lg.example/', 'gov-hu.example']) {
			assert.equal(isDeceptiveLink({host: 'evil.example', text}, {from: 'shop.example'}), false, text);
		}

		assert.equal(isDeceptiveLink({host: 'u1.ct.sendgrid.net', text: 'https://www.uscourts.gov'}, {from: 'firm.example'}), false);
		assert.equal(isDeceptiveLink({host: 'email.firm-mail.example', text: 'https://www.uscourts.gov'}, {from: 'firm.example', senders: ['firm-mail.example']}), false);
		assert.equal(isDeceptiveLink({host: 'other.example', text: 'https://www.gov.uk.evil.example'}, {from: 'shop.example'}), false);
		// (and a brand's address from its own domain or over a link to the
		//  From domain still counts)
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'www.paypal.com'}, {from: 'paypal.com', recipients}), true);
		assert.equal(isDeceptiveLink({host: 'www.shop.example', text: 'www.paypal.com'}, {from: 'shop.example', recipients}), true);
		// (nor a provider of mailboxes' address, which is anyone's)
		assert.equal(isDeceptiveLink({host: 'evil.example', text: 'gmail.com'}, {from: 'gmail.com', recipients}), true);
	});

	it('takes no host that no one reaches on the internet for a disguise', () => {
		for (const [text, host] of [['http://127.0.0.1:8000', 'localhost'], ['http://192.168.1.10/admin', 'router.lan'], ['http://[::1]:3000/', 'localhost'], ['http://nas.local/login', 'evil.example'], ['https://grafana.internal/', 'evil.example'], ['http://intranet.home.arpa/', 'evil.example'], ['https://example.com/api', 'github.com'], ['https://api.example.org/v1/login', 'evil.example']]) {
			assert.equal(isDeceptiveLink({host, text}, {from: 'shop.example', recipients: ['example.com', 'local']}), false, text);
		}

		// (but a brand's, whatever a link's domain is)
		assert.equal(isDeceptiveLink({host: '192.0.2.1', text: 'https://www.paypal.com/'}, {from: 'shop.example'}), true);
	});

	it('takes a brand\'s other domains for its own', () => {
		for (const [text, host] of [['google.com', 'blog.google'], ['https://about.google/', 'www.google.com'], ['https://azure.microsoft.com', 'portal.azure.com'], ['www.google.com', 'www.youtube.com'], ['https://www.apple.com', 'www.apple']]) {
			assert.equal(isDeceptiveLink({host, text}, {from: 'shop.example'}), false, text);
		}

		// (not under a top-level domain anyone may register)
		assert.equal(isDeceptiveLink({host: 'google.top', text: 'https://www.google.com'}, {from: 'shop.example'}), true);
		assert.equal(isDeceptiveLink({host: 'login.paypal.evil', text: 'https://www.paypal.com'}, {from: 'shop.example'}), true);
	});

	it('takes the pages of a brand a person who passes DMARC links to for none', () => {
		// (copied through another site, or in a newsletter forwarded)
		for (const [text, host] of [['https://docs.aws.amazon.com/lambda/latest/dg/welcome.html', 'wiki.acme-corp.io'], ['https://www.apple.com/newsroom/2026/11/story/', 'news.media.example'], ['https://github.com/acme/repo', 'acme.github.io'], ['https://www.usps.com/business/', 'click.retailer.example']]) {
			assert.equal(isDeceptiveLink({host, text}, {from: 'gmail.com', authenticated: true}), false, text);
			// (but from a sender that does not pass)
			assert.equal(isDeceptiveLink({host, text}, {from: 'gmail.com'}), true, text);
		}

		// (its front page, also in a language, a page that asks to sign in, and
		//  one that lures with a parcel, a payment or a locked account, still
		//  count, as phishing from a domain of its own shows them)
		for (const text of ['https://www.paypal.com', 'https://www.paypal.com/us/home', 'https://www.apple.com/en-gb/', 'https://www.dhl.com/index.html', 'https://www.apple.com/account/signin', 'https://github.com/login', 'https://www.usps.com/track/9400100000', 'https://www.amazon.com/refund?id=1', 'https://www.netflix.com/account/suspended', 'www.dhl.com/de/redelivery']) {
			assert.equal(isDeceptiveLink({host: 'acme.github.io', text}, {from: 'gmail.com', authenticated: true}), true, text);
			assert.equal(isDeceptiveLink({host: 'landing.evil.example', text}, {from: 'notice.evil-mail.example', authenticated: true}), true, text);
		}

		// (but not a page deeper than a language's, nor a parcel through a
		//  shop's own click tracking or its mailing service's)
		assert.equal(isDeceptiveLink({host: 'acme.github.io', text: 'https://www.apple.com/us/iphone/'}, {from: 'gmail.com', authenticated: true}), false);
		assert.equal(isDeceptiveLink({host: 'click.mail.shop.example', text: 'https://www.ups.com/track?tracknum=1Z999'}, {from: 'mail.shop.example', authenticated: true}), false);
		assert.equal(isDeceptiveLink({host: 'u1.ct.sendgrid.net', text: 'https://www.ups.com/track?tracknum=1Z999'}, {from: 'shop.example', authenticated: true}), false);
	});

	it('reads "wallet" as a product, not as a page that asks to sign in', () => {
		// (a card's newsletter on adding it to Apple, Google and Samsung Wallet)
		for (const text of ['www.apple.com/wallet/', 'https://www.google.com/wallet', 'samsung.com/us/samsung-wallet']) {
			assert.equal(isDeceptiveLink({host: 'e.emails.card.example', text}, {from: 'emails.card.example', authenticated: true}), false, text);
		}

		assert.equal(isDeceptiveLink({host: 'e.emails.card.example', text: 'www.apple.com/account/signin'}, {from: 'emails.card.example', authenticated: true}), true);
	});

	it('finds registrable domains', () => {
		assert.equal(registrableDomain('mail.example.co.uk'), 'example.co.uk');
		assert.equal(registrableDomain('192.0.2.1'), '192.0.2.1');
		assert.equal(registrableDomain('localhost'), 'localhost');
		assert.equal(registrableDomain(''), '');
	});

	it('reads a user name or password before cutting a long address, and never throws', async () => {
		const long = `http://a:${'b'.repeat(20_000)}@evil.com/`;
		const [link] = extractLinks(long, '');
		assert.deepEqual([link.host, link.url.length, link.userinfo], ['evil.com', 16_384, true]);
		assert.ok(getFeatures({text: long}).features.includes('url:userinfo'));
		assert.ok(getFeatures({html: `<a href="${long}">x</a>`}).features.includes('url:userinfo'));
		// (an empty user name with a password)
		assert.equal(extractLinks('https://:paypal.com@evil.example/', '')[0].userinfo, true);
		assert.equal(extractLinks('https://evil.example/', '')[0].userinfo, false);
		const mail = await parse(message({text: `click ${long}`}));
		assert.ok(getFeatures(mail).features.includes('url:userinfo'));
	});

	it('reads an address as the URL parser does, without tabs, line breaks and control characters', () => {
		for (const href of ['ht\ttps://evil.example/', 'ht&#10;tps://evil.example/', 'https&Tab;://evil.example/', 'h&NewLine;ttps://evil.example/', '\u0001https://evil.example/', ' \u0001https://evil.example/\u0000\u001F ', 'https://evil.\r\nexample/']) {
			assert.deepEqual(extractLinks('', `<a href="${href}">click here</a>`).map(link => link.host), ['evil.example'], JSON.stringify(href));
		}

		assert.deepEqual(extractLinks('', '<a href="java\tscript:alert(1)">x</a><a href="\u0001\u0002">y</a>'), []);
		// (in linear time on long runs of them)
		const started = cpuTime();
		const links = extractLinks('', `<a href="${'\u0001 '.repeat(100_000)}https://e.example/${' \u0001'.repeat(100_000)}">x</a><a href="${'h\t'.repeat(100_000)}">y</a>`);
		// (the second's host, 100,000 characters, longer than any is, is not read)
		assert.deepEqual(links.map(link => link.host.length), [9]);
		assert.ok(cpuTime() - started < 1500);
	});

	it('finds the address shown in a link\'s visible text', () => {
		const shown = html => extractLinks('', html).filter(link => link.text).map(link => [link.host, link.text, isDeceptiveLink(link)]);
		const deceptive = [['evil.example', 'https://www.paypal.com/', true]];
		// (a "</a>" in the value of an attribute ends no link)
		assert.deepEqual(shown('<a href="https://evil.example/"><span title="</a>"></span>https://www.paypal.com/</a>'), deceptive);
		// (without hidden text and invisible characters)
		assert.deepEqual(shown('<a href="https://evil.example/">https://www.paypal.com/<span style="display:none">a b</span></a>'), deceptive);
		assert.deepEqual(shown('<a href="https://evil.example/">\u200Bhttps://www.paypal.com/\u2060</a>'), deceptive);
		assert.deepEqual(shown('<a href="https://evil.example/"><b>https://www.</b>paypal<b>.com/</b></a>'), deceptive);
		// (the first word of the text written as an address)
		assert.deepEqual(shown('<a href="https://evil.example/">Sign in at https://www.paypal.com/.</a>'), deceptive);
		assert.deepEqual(shown('<a href="https://evil.example/">Version 2.0 of report.pdf, at (https://paypal.com/signin)</a>'), [['evil.example', 'https://paypal.com/signin', true]]);
		assert.deepEqual(shown('<a href="https://evil.example/">Version 2.0 of report.pdf</a>'), []);
		assert.deepEqual(shown('<a href="https://www.paypal.com/x">Sign in at https://www.paypal.com</a>'), [['www.paypal.com', 'https://www.paypal.com', false]]);
		// (a whole text written as an address, as before)
		assert.deepEqual(shown('<a href="https://evil.example/">PAYPAL.COM</a>'), [['evil.example', 'PAYPAL.COM', true]]);
		assert.deepEqual(shown('<a href="https://evil.example/">www.paypal.com/signin</a>'), [['evil.example', 'www.paypal.com/signin', true]]);
	});

	it('takes no file name, version or name in a sentence for the address a link shows', () => {
		const deceptive = inner => extractLinks('', `<a href="https://tracker.esp-example.net/c/1">${inner}</a>`).filter(link => isDeceptiveLink(link)).map(link => link.text);
		const shownText = inner => extractLinks('', `<a href="https://tracker.esp-example.net/c/1">${inner}</a>`).map(link => link.text).filter(Boolean);
		for (const inner of ['Download report.zip', 'Open README.md', 'Watch clip.mov', 'Run setup.sh', 'See script.py', 'report.zip', 'README.md', 'invoice.pdf', 'v2.0', 'Read: why Booking.com switched', 'Read about Socket.IO', 'Built with ASP.NET', 'Listen on Last.fm', 'Mr.Bean', 'Weitere Infos unter www.firma.de', 'View in browser: brand.com', 'Download the invoice (invoice.zip)', 'Contact support@example-shop.com']) {
			assert.deepEqual(shownText(inner), [], inner);
		}

		assert.deepEqual(extractLinks('', '<a href="https://l.facebookmail.com/x">Go to facebook.com</a>').filter(link => isDeceptiveLink(link)), []);
		assert.ok(!getFeatures({html: '<a href="https://tracker.esp-example.net/c/1">Download report.zip</a>'}).features.includes('url:deceptive'));
		// (but an address with a scheme in a sentence, or a whole text that is
		//  one, is)
		assert.deepEqual(deceptive('Sign in at https://www.paypal.com/'), ['https://www.paypal.com/']);
		assert.deepEqual(deceptive('https://www.paypal.com'), ['https://www.paypal.com']);
		assert.deepEqual(deceptive('www.paypal.com'), ['www.paypal.com']);
		assert.deepEqual(deceptive('secure.paypal.com'), ['secure.paypal.com']);
		// (and names under top-level domains that are sites more often than
		//  files)
		assert.deepEqual(shownText('linear.app'), ['linear.app']);
		assert.deepEqual(shownText('cash.app'), ['cash.app']);
		assert.deepEqual(shownText('character.ai'), ['character.ai']);
	});

	it('takes a link through an email service\'s click tracking for no deceptive one', () => {
		for (const host of ['u1.ct.sendgrid.net', 'example.us1.list-manage.com', 'mandrillapp.com', 'abc.r.us-east-1.awstrack.me', 'click.pstmrk.it', 'd2.hubspotlinks.com', 'r20.rs6.net', 'trk.klclick.com', 'x.mjt.lu', 'click.exacttarget.com']) {
			assert.equal(isDeceptiveLink({host, text: 'https://www.paypal.com/'}), false, host);
		}

		assert.equal(isDeceptiveLink({host: 'sendgrid.net.evil.example', text: 'https://www.paypal.com/'}), true);
		assert.equal(isDeceptiveLink({host: 'notsendgrid.net', text: 'https://www.paypal.com/'}), true);
		assert.equal(isDeceptiveLink({text: 'https://www.paypal.com/'}), true);
		const {features} = getFeatures({html: '<a href="https://u1.ct.sendgrid.net/ls/click?upn=x">www.example-shop.com</a>'});
		assert.ok(!features.includes('url:deceptive'));
	});

	it('takes a brand\'s address shown through click tracking for a deceptive link from anyone but the brand', () => {
		const tracked = {host: 'u1.ct.sendgrid.net', text: 'https://www.paypal.com/signin'};
		assert.equal(isDeceptiveLink(tracked, {from: 'example-shop.com'}), true);
		assert.equal(isDeceptiveLink(tracked, {from: ''}), true);
		// (from the brand, or with no sender known, as a scan's findings
		//  have none)
		assert.equal(isDeceptiveLink(tracked, {from: 'mail.paypal.com'}), false);
		assert.equal(isDeceptiveLink(tracked, {from: 'paypal.de'}), false);
		assert.equal(isDeceptiveLink(tracked), false);
		// (an address without a scheme, or of a site that is no brand's, is a
		//  newsletter's link)
		assert.equal(isDeceptiveLink({host: 'u1.ct.sendgrid.net', text: 'www.paypal.com'}, {from: 'example-shop.com'}), false);
		assert.equal(isDeceptiveLink({host: 'u1.ct.sendgrid.net', text: 'https://www.example-partner.com/'}, {from: 'example-shop.com'}), false);
		const features = from => getFeatures({from: {value: [{address: from}]}, html: '<p>Your account is limited.</p><a href="https://u1.ct.sendgrid.net/ls/click?upn=x">https://www.paypal.com/</a>'}).features;
		assert.ok(features('news@example-shop.com').includes('url:deceptive'));
		assert.ok(!features('service@paypal.com').includes('url:deceptive'));
		assert.ok(getFeatures({html: '<a href="https://u1.ct.sendgrid.net/ls/click?upn=x">https://www.paypal.com/</a>'}).features.includes('url:deceptive'));
	});

	it('takes no newsletter\'s links to social networks, shops or maps through click tracking for deceptive ones', () => {
		const tracked = text => isDeceptiveLink({host: 'acme.us1.list-manage.com', text}, {from: 'acmecoffee.com'});
		for (const text of ['https://www.facebook.com/acmecoffee', 'https://www.facebook.com/', 'https://www.instagram.com/acmecoffee', 'https://www.linkedin.com/company/acme', 'https://twitter.com/acme', 'https://github.com/acme', 'https://open.spotify.com/playlist/1', 'https://zoom.us/j/123', 'https://www.amazon.com/dp/B000000000', 'https://www.google.com/maps/place/Acme', 'https://www.paypal.com/donate/?hosted_button_id=X']) {
			assert.equal(tracked(text), false, text);
		}

		// (nor a brand's address from one of its own sending domains, listed:
		//  others with "mail" are anyone's)
		assert.equal(isDeceptiveLink({host: 'x.ct.sendgrid.net', text: 'https://www.facebook.com/'}, {from: 'facebookmail.com'}), false);
		assert.equal(isDeceptiveLink({host: 'x.ct.sendgrid.net', text: 'https://www.dropbox.com/login'}, {from: 'mail.dropboxmail.com'}), false);
		// (a sending domain under another suffix is anyone's, and Gmail users' too)
		assert.equal(isDeceptiveLink({host: 'x.ct.sendgrid.net', text: 'https://www.ups.com/'}, {from: 'upsemail.xyz'}), true);
		assert.equal(isDeceptiveLink({host: 'x.ct.sendgrid.net', text: 'https://accounts.google.com/'}, {from: 'googlemail.com'}), true);
		assert.equal(isDeceptiveLink({host: 'x.ct.sendgrid.net', text: 'https://www.paypal.com/'}, {from: 'paypalmail.top'}), true);
		assert.equal(isDeceptiveLink({host: 'x.ct.sendgrid.net', text: 'https://www.paypal.com/'}, {from: 'paypalmail.com'}), true);
		// (a word asking to sign in as a part of the path, also joined to
		//  another, in any case, not a page)
		for (const path of ['/ServiceLogin', '/YourAccount', '/LoginHelp', '/common/oauth2/authorize', '/signin2', '/accountverification', '/securelogin', '/updatepayment', '/billinginfo', '/account/update', '/login.php', '/your-account', '/myaccount/summary', '/sign-in', '/log-in', '/Sign-On', '/authenticate']) {
			assert.equal(tracked(`https://www.amazon.com${path}`), true, path);
		}

		for (const path of ['/shop/updates', '/products/iphone', '/blog/accounting-tips', '/signing-day']) {
			assert.equal(tracked(`https://www.amazon.com${path}`), false, path);
		}

		// (but a brand's home page or sign-in page, from anyone else)
		for (const text of ['https://www.amazon.com', 'https://www.amazon.com/ap/signin', 'https://www.paypal.com/cgi-bin/webscr?cmd=_login', 'https://www.google.com/accounts']) {
			assert.equal(tracked(text), true, text);
		}
	});

	it('adds no link of a part of a name split by tags in HTML, but one of the name the text shows', () => {
		assert.deepEqual(extractLinks('', '<a href="https://evil.example/"><b>https://www.</b>paypal<b>.com/</b></a>').map(link => link.host), ['evil.example', 'www.paypal.com']);
		// (the name goes on after up to four tags, but a link that ends with
		//  its path or at a tag after which text starts is one)
		assert.deepEqual(extractLinks('', '<p>https://www.pay<i></i><b></b>pal.com/x</p>').map(link => link.host).filter(host => host.startsWith('www')), ['www.paypal.com']);
		assert.deepEqual(extractLinks('', `<p>https://a.example/<br>Next https://b.example<br> https://c.example<br>x https://d.example<i></i><i></i><i></i><i></i><i>x https://e.example<b x="${'y'.repeat(300)}">z https://f.example<b>\u{1D41A}</p>`).map(link => link.host), ['a.example', 'b.example', 'c.example', 'd.example', 'e.example', 'f.example']);
		assert.deepEqual(extractLinks('https://www.<b>pay', '').map(link => link.host), ['www']);
	});

	it('keeps a link that ends at the end of a line, cell or block, or before a word', () => {
		const hosts = html => extractLinks('', html).map(link => link.host);
		assert.deepEqual(hosts('<p>Go to https://paypa1.com</p><p>Regards</p>'), ['paypa1.com']);
		assert.deepEqual(hosts('https://evil.com<br>Thanks'), ['evil.com']);
		assert.deepEqual(hosts('<td>www.evil.com</td><td>next</td>'), ['www.evil.com']);
		assert.deepEqual(hosts('<div>https://evil.com</div>Bye'), ['evil.com']);
		assert.deepEqual(hosts('https://evil.com<o:p></o:p>x'), ['evil.com']);
		// (a word or a full stop after an inline tag goes on no host name)
		assert.deepEqual(hosts('<b>https://evil.com</b>Thanks'), ['evil.com']);
		assert.deepEqual(hosts('<b>https://evil.com</b>. Thanks'), ['evil.com']);
		assert.deepEqual(hosts('<b>https://evil.com:8080</b>x'), ['evil.com']);
		// (a name that goes on across inline tags and a comment is no link)
		// (read whole as the text shows it)
		assert.deepEqual(hosts('https://www.paypal<span>.com</span>'), ['www.paypal.com']);
		assert.deepEqual(hosts('x https://shop.com<!-- c -->pany.com'), ['shop.company.com']);
	});

	it('reads links of the text shown broken where its lines, cells and blocks are', () => {
		const urls = html => extractLinks('', html).map(link => link.url);
		// (a cell, a line break and a block end a link, also a block a style
		//  makes of an inline element, or one it hides that still takes its
		//  place, or one a browser ends by itself before a hidden one)
		assert.deepEqual(urls('<table><tr><td>https://shop.example.com/</td><td>Prices</td></tr></table>'), ['https://shop.example.com/']);
		assert.deepEqual(urls('<span style="display:block">https://shop.example.com/</span><span style="display: flex">Prices from $5</span>'), ['https://shop.example.com/']);
		assert.deepEqual(urls('<a style="display:block">https://shop.example.com/</a><b style="display:list-item">Prices</b>'), ['https://shop.example.com/']);
		assert.deepEqual(urls('<div>Visit https://shop.example.com/<div style="opacity:0">filler</div>Offers</div>'), ['https://shop.example.com/']);
		assert.deepEqual(urls('Visit https://shop.example.com/<span style="opacity:0"><br></span>Offers'), ['https://shop.example.com/']);
		assert.deepEqual(urls('<p>Track it at https://track.example.com/<div style="display:none">x</div>Status: shipped'), ['https://track.example.com/']);
		assert.deepEqual(urls('<h1>https://track.example.com/<h2 hidden>x</h2>Status</h1>'), ['https://track.example.com/']);
		// (but not a block that takes no place, or a block a style shows in
		//  the line: a name split there reads whole, as one split by an
		//  inline tag does; the markup, read without styles, may give its
		//  parts too)
		assert.deepEqual(urls('<p>Visit https://www.exam<b>ple.com</b>/deals</p>'), ['https://www.example.com/deals']);
		for (const html of ['<div>Visit https://www.exam<div style="display:inline">ple.com/deals</div></div>', '<div>Visit https://www.exam<div style="display:none">x</div>ple.com/deals</div>', '<p>Visit https://www.exam<span style="display:inline-block">ple.com/deals</span></p>', '<div>Visit https://www.exam<div style="position:absolute;left:-9999px">x</div>ple.com/deals</div>']) {
			assert.ok(urls(html).includes('https://www.example.com/deals'), html);
		}
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

	it('makes no feature of a country\'s top-level domain', () => {
		const {features} = getFeatures({
			html: '<p><a href="https://www.example.at/a">Wien</a> <a href="https://shop.example.co.in/b">Delhi</a> <a href="https://www.example.shop/c">Shop</a></p>', from: {value: [{address: 'news@example.at'}]},
		});
		assert.deepEqual(features.filter(feature => feature.startsWith('url:tld:') || feature.startsWith('from:tld:')), ['url:tld:shop']);
		assert.ok(getFeatures({from: {value: [{address: 'news@example.online'}]}}).features.includes('from:tld:online'));
		assert.ok(features.includes('url:example.at'));
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
		// (and a word that mixes scripts in the one most of its letters are
		//  in, words of one script as they are)
		assert.equal(unmixedText('p\u0430ypal \u043F\u0440\u0438\u0432\u0435\u0442 caf\u00E9 10\u03BCg'), 'paypal \u043F\u0440\u0438\u0432\u0435\u0442 caf\u00E9 10\u03BCg');
		// (in text as written each letter keeps its case, a capital read as
		//  the capital it looks like, a Greek "\u039D" as "N", or left when it
		//  looks like none, and a unit as in small letters; the letters of
		//  the phonetic alphabet that look like plain ones are those)
		assert.equal(unmixedText('\u039Detflix P\u0430yP\u0410L D\u0397L \u03A9mega 5 k\u03A9 p\u0251yp\u0251l Goo\u0261le \u0130\u03C4\u03B1 P\u0440\u0438\u0432\u0435\u0442'), 'Netflix PayPAL DHL \u03A9mega 5 k\u03A9 paypal Google \u0399\u03C4\u03B1 \u0420\u0440\u0438\u0432\u0435\u0442');
		// (as typed, only what a keyboard explains: a letter of another
		//  script at the start or the end of a Latin word, and Latin letters
		//  in a word of another script; not one inside a Latin word, nor a
		//  letter of the phonetic alphabet)
		assert.equal(unmixedText('\u039D\u0395\u03A4flix Netfli\u03C7 P\u0430ypal \u0410m\u0430zon p\u0251ypal C\u0431\u0435\u0440\u0431a\u043D\u043A', true), 'NETflix Netflix P\u0430ypal Am\u0430zon p\u0251ypal \u0421\u0431\u0435\u0440\u0431\u0430\u043D\u043A');
	});

	it('decodes character references as browsers do', () => {
		assert.equal(shown('caf&eacute; &Eacute; &AMP; &amp;lt; &euro;5 &#x48;&#105; &zwnj;'), 'café É & &lt; €5 Hi ‌');
		// (by number also without a ";", C1 controls as Windows-1252, and what no
		//  character is as U+FFFD)
		assert.equal(decodeEntities('V&#105agra don&#146;t &#x0000000041; &#0;&#55296;&#x110000;'), 'Viagra don\u2019t A \uFFFD\uFFFD\uFFFD');
		// (the names browsers read without a ";", in text, not in an attribute
		//  where a letter, digit or "=" follows)
		assert.equal(decodeEntities('Free&nbspSpins &amp &notin;'), 'Free\u00A0Spins & \u2209');
		// (every name browsers know, with its ";": a mathematical letter, a
		//  Cyrillic one, two letters)
		assert.equal(decodeEntities('ev&iopf;l p&acy;ypal &fjlig;'), 'ev\u{1D55A}l p\u0430ypal fj');
		assert.equal(decodeEntities('?a=1&copy=2&amp;b&lt', {attribute: true}), '?a=1&copy=2&b<');
		// (an unknown name, and names of object properties, stay)
		assert.equal(decodeEntities('&nosuch; &constructor; &__proto__; &zz'), '&nosuch; &constructor; &__proto__; &zz');
		// (the punctuation of a web address by name, as browsers read it)
		assert.equal(decodeEntities('https&colon;&sol;/bank.example&commat;evil.example&quest;a&equals;1&num;x', {attribute: true}), 'https://bank.example@evil.example?a=1#x');
	});

	it('leaves out what the HTML hides, and counts it', () => {
		for (const style of ['font-size:5%', 'font-size:0.05rem', 'display:none', 'DISPLAY : NONE', 'visibility:hidden', 'opacity:0', 'opacity:0.0', 'color:transparent', 'font-size:0', 'font-size:1px', 'font-size:0.5pt', 'font-size:0em', 'max-height:0;overflow:hidden', 'height:0px; overflow: hidden']) {
			const result = visibleText(`<p>Buy now</p><div style="${style}">harmless filler words</div><p>today</p>`);
			assert.equal(result.text.replaceAll(/\s+/g, ' ').trim(), 'Buy now today', style);
			assert.equal(result.hidden, 'harmlessfillerwords'.length, style);
		}

		// (in any quotes, or none)
		assert.equal(shown('<p style=\'display:none\'>a</p><p style=display:none>b</p>c'), 'c');
		// (also by the attribute, nested, and to the end of the hiding element,
		//  which breaks no word)
		assert.equal(shown('<span hidden>a</span>b<div style="display:none"><div>c</div>d</div>e'), 'be');
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
		assert.equal(shown('<image hidden src=x>a<keygen hidden>b c<img src=x>d'), 'ab c d');
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
		// (a block a style shows in the line joins a word, unless the style
		//  is one browsers do not know; a block in a closed <details> breaks
		//  nothing)
		assert.equal(shown(`V<div style="display:inline">iag</div>ra F<div style="display:inline ${'x'.repeat(70)}">re</div>e Sp<div style="display:inline nonesuch">in</div>s`), 'Viagra F re e Sp in s');
		assert.equal(shown('Fr<details><summary></summary><p>x</p></details>ee'), 'Fr ee');
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

describe('visibleText as browsers build the page', () => {
	const shown = html => visibleText(html).text.replaceAll(/\s+/g, ' ').trim();
	const deep = '<x>'.repeat(100);

	it('closes an element however deep what it holds is', () => {
		assert.equal(shown(`<span hidden>${deep}</span>BUY PILLS`), 'BUY PILLS');
		assert.equal(shown(`<table><tr><td><span hidden>${deep}<td>BUY PILLS</table>`), 'BUY PILLS');
		assert.equal(shown(`<p hidden>${deep}<div>BUY PILLS</div>`), 'BUY PILLS');
		assert.equal(shown(`<ul><li><span hidden>${deep}<li>BUY PILLS</ul>`), 'BUY PILLS');
		// (not through a block open inside it, however deep)
		assert.equal(shown(`<span hidden><div>${deep}</span>x</div>`), '');
	});

	it('puts text and elements written in a table in front of it', () => {
		assert.equal(shown('<table style="display:none">BUY PILLS NOW<tr><td>x</td></tr></table>'), 'BUY PILLS NOW');
		assert.equal(shown('<table hidden><span>BUY PILLS</span></table>'), 'BUY PILLS');
		assert.equal(shown('<table hidden><tr>FOSTER<td>cell</td>more</tr></table>'), 'FOSTERmore');
		assert.equal(shown('<div hidden><table><tr><td>a</td></tr>b</table></div>c'), 'c');
		assert.equal(shown('<table hidden><caption>a</caption><tbody> <tr><td>b</table>c'), 'c');
		assert.equal(shown('<table hidden><svg><text>BUY PILLS</text></svg></table>'), 'BUY PILLS');
	});

	it('reads an <svg> and a <math> as browsers do', () => {
		// (no raw text in them, and what an <svg> does not show)
		assert.equal(shown('<svg><title></svg><p>BUY PILLS NOW</p>'), 'BUY PILLS NOW');
		assert.equal(shown('<svg><style></svg><div>BUY PILLS NOW</div>'), 'BUY PILLS NOW');
		assert.equal(shown('<math><style></math><div>BUY PILLS NOW</div>'), 'BUY PILLS NOW');
		assert.equal(shown('<svg><title>tip</title><desc>d</desc><text>shown</text></svg>'), 'shown');
		// (an HTML element ends them, but not in one of their elements that
		//  holds HTML; an end tag closes an element of the name in them)
		assert.equal(shown('<svg><style><div>BREAKOUT</div></style></svg><svg><g><font color=red>F</font></g></svg>'), 'BREAKOUT F');
		assert.equal(shown('<svg><title><div>x</div></svg>y<svg><desc>a</title>b</desc></svg>c'), 'y c');
		assert.equal(shown('<svg><foreignObject><div>FO</div></foreignObject></svg><svg style="display:none"><foreignObject><p>P</p></foreignObject></svg>'), 'FO');
		assert.equal(shown('<svg><foreignObject><div hidden>a</svg>b</div>c<math><mi><b hidden>x</math>y'), 'c');
		assert.equal(shown('<svg><g hidden><rect/>t</g>u<image/>v</svg>'), 'u v');
	});

	it('ends a paragraph at every block that ends it', () => {
		for (const html of ['<p hidden><listing>BUY PILLS</listing>', '<p hidden><plaintext>BUY PILLS', '<p hidden><summary>BUY PILLS</summary>', '<p hidden><search>BUY PILLS</search>']) {
			assert.equal(shown(html), 'BUY PILLS', html);
		}
	});

	it('hides by a size, overflow or indent only an element that is a box', () => {
		for (const style of ['max-height:0;overflow:hidden', 'height:0;overflow:hidden', 'width:0;overflow:hidden', 'text-indent:-9999px']) {
			assert.equal(shown(`<span style="${style}">BUY</span><font style="${style}">PILLS</font>`), 'BUYPILLS', style);
			assert.equal(shown(`<div style="display:inline;${style}">BUY</div>`), 'BUY', style);
			assert.equal(shown(`<span style="display:block;${style}">a</span><span style="display:inline-block;${style}">b</span><span style="position:absolute;${style}">c</span><b style="float:left;${style}">d</b><table><tr><td style="position:absolute;${style}">e</td></tr></table>f`), 'f', style);
		}

		// (a part of a table grows to what it holds, whatever its size; an
		//  indent moves its text all the same)
		for (const name of ['table', 'tr', 'td', 'th']) {
			for (const style of ['width:0;overflow:hidden', 'height:0;overflow:hidden', 'max-height:0;overflow:hidden', 'width:0;height:0;overflow:hidden']) {
				assert.equal(shown(`<table${name === 'table' ? ` style="${style}"` : ''}><tr${name === 'tr' ? ` style="${style}"` : ''}><${name === 'th' ? 'th' : 'td'}${['td', 'th'].includes(name) ? ` style="${style}"` : ''}>BUY</td></tr></table>`), 'BUY', `${name} ${style}`);
			}
		}

		assert.equal(shown('<div style="display:table-cell;width:0;overflow:hidden">a</div><div style="display:inline-table;width:0;overflow:hidden">b</div><div style="display:table-caption;height:0;overflow:hidden">c</div><table><tr><td style="text-indent:-9999px">d</td><td style="display:block;height:0;overflow:hidden">e</td><td style="float:left;height:0;overflow:hidden">f</td></tr></table>'), 'a b');
	});

	it('keeps a table in a paragraph in quirks mode', () => {
		assert.equal(shown('<p hidden>x<table><tr><td>HAM WORDS</td></tr></table>'), '');
		assert.equal(shown('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"><p hidden>x<table><tr><td>HAM</td></tr></table>'), '');
		assert.equal(shown('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><p hidden>x<table><tr><td>HAM</td></tr></table>'), '');
		assert.equal(shown('<!DOCTYPE svg><p hidden>x<table><tr><td>HAM</td></tr></table>'), '');
		// (not with a doctype of standards mode, or almost so)
		for (const doctype of ['<!doctype html>', '  <!DOCTYPE html SYSTEM "about:legacy-compat">', '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">', '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">', '<!DOCTYPE html PUBLIC \'-//W3C//DTD HTML 4.01//EN\'>']) {
			assert.equal(shown(`${doctype}<p hidden>x<table><tr><td>HAM</td></tr></table>`), 'HAM', doctype);
		}
	});

	it('opens again a formatting element something else closed', () => {
		assert.equal(shown('<p><b style="display:none">x</p><p>HAM WORDS</p>'), '');
		assert.equal(shown('<p><b style="display:none">x</p>\n<p>HAM WORDS</p>'), '');
		assert.equal(shown('<p><i hidden>a<b>b</p>c<td>d'), '');
		assert.equal(shown('<p><b hidden>a<i>b</p><p>c</b>d</p>e'), 'd e');
		// (not one closed by its own end tag, nor past a cell)
		assert.equal(shown('<p><b hidden>x</b></p><p>SHOWN</p>'), 'SHOWN');
		assert.equal(shown('<table><tr><td><b hidden>x</td><td>SHOWN</td></tr></table>'), 'SHOWN');
		assert.equal(shown('<div style="display:none"><b>x</div>shown<span style="display:none"><b>y</span>ham'), 'shownham');
		// (at most three alike, as browsers keep them, and many in all, the
		//  first left out past them, where a browser keeps more)
		assert.equal(shown(`<p>${'<b hidden>'.repeat(5)}<b>x</p>y</b>z</b></b></b>w`), 'w');
		assert.equal(shown(`<p><s hidden>${'<b>'.repeat(9)}x</p>y`), '');
		assert.equal(shown(`<p><s hidden>${Array.from({length: 11}, (_, i) => `<b style="--n:${i}">`).join('')}x</p>y`), '');
		assert.equal(shown(`<p><s hidden>${Array.from({length: 12}, (_, i) => `<b style="--n:${i}">`).join('')}x</p>y`), 'y');
	});

	it('reads tables, lists and links as browsers do', () => {
		// (a part of a table outside one is nothing; in one, it closes what
		//  was put in front of the table; a table in a table ends it)
		assert.equal(shown('<span hidden><tbody><tr><td>x</span>y'), 'y');
		assert.equal(shown('<table><b hidden>x<tr><td>SHOWN</td></tr></table>'), 'SHOWN');
		assert.equal(shown('<table hidden><tr><span>a<table>b'), 'a b');
		assert.equal(shown('<template><tr><td>a</td></tr></template>b'), 'b');
		// (text in a part of a table in a template stays in the template, which
		//  shows nothing, with a table around it or not)
		assert.equal(shown('<template><tr>secret words here</tr></template>shown'), 'shown');
		assert.equal(shown('<div hidden><template><tr>sec</template></div>'), '');
		assert.equal(shown('<table><template><tr>secret</tr></template></table>ok'), 'ok');
		assert.equal(shown('<template><tbody><b>secret</b></template>x'), 'x');
		assert.equal(shown('<table><template><table><tr>x</table></template></table>k'), 'k');
		assert.equal(shown('<template><table></table></template><table><b>in front</b><tr><td>c</td></tr></table>'), 'in front c');
		// (a list item not past a block other than an address, a <div> or a
		//  <p>)
		assert.equal(shown('<ul><li><pre hidden>a<li>b</ul>c'), 'c');
		assert.equal(shown('<ul><li hidden><div>a<li>b</ul>'), 'b');
		assert.equal(shown('<dl><dd hidden><p>a<dt>b</dl>'), 'b');
		// (a link ends the link open, not past an <object> it holds)
		assert.equal(shown('<a hidden href=x>a<a href=y>BUY PILLS</a>'), 'BUY PILLS');
		assert.equal(shown('<a hidden href=x>a<object><a href=y>b</a></object>c'), '');
	});

	it('closes by an end tag only what is in scope', () => {
		assert.equal(shown('<div hidden><table><tr><td></div>x</td></tr></table>y'), '');
		assert.equal(shown('<b hidden><table><tr><td></b>x</table>y'), '');
		assert.equal(shown('<p hidden><button></p>x</button>y'), '');
		assert.equal(shown('<ul><li hidden><ol></li>x</ol>y</ul>z'), 'z');
		assert.equal(shown('<table><tr><td><table><tr><td></td></tr></table></td><td hidden>a</td></tr></table>b'), 'b');
		assert.equal(shown('<table><tr><td hidden><table><tr><td></td></tr></table></td></tr></table>b'), 'b');
	});

	it('ends an <svg> or <math> at a </p> or </br>', () => {
		assert.equal(shown('<svg style="display:none"><g></p>BUY PILLS</svg>'), 'BUY PILLS');
		assert.equal(shown('<math hidden><mrow></br>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<p hidden><svg><g></p>BUY PILLS'), 'BUY PILLS');
		// (not in an element of theirs that holds HTML)
		assert.equal(shown('<svg style="display:none"><desc></p>x</desc></svg>y'), 'y');
	});

	it('ends headings, buttons, cells and column groups as browsers do', () => {
		// (a heading in a heading, an end tag of any heading)
		assert.equal(shown('<h1 style="display:none"><h2>BUY PILLS</h2>'), 'BUY PILLS');
		assert.equal(shown('<h1 style="display:none">a</h3>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<h1 style="display:none"><span><h2>x</h2></span></h1>y'), 'y');
		// (a button in a button)
		assert.equal(shown('<button style="display:none"><button>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<button style="display:none"><b><button>BUY</b>PILLS'), 'BUYPILLS');
		assert.equal(shown('<button style="display:none"><table><tr><td><button>x</table>y'), '');
		// (a caption, a column or a column group in a cell, and a part of a
		//  table in a caption)
		assert.equal(shown('<table><tr><td style="display:none"><caption>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<table><tr><th style="display:none"><colgroup><col>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<table><caption style="display:none">a<tr><td>BUY PILLS'), 'BUY PILLS');
		// (text and elements in a column group, put in front of the table)
		assert.equal(shown('<table><colgroup style="display:none">BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<table><colgroup style="display:none"><b>BUY PILLS</b></table>'), 'BUY PILLS');
		assert.equal(shown('<table><colgroup style="display:none"><svg><text>BUY PILLS</text></svg></table>'), 'BUY PILLS');
		assert.equal(shown('<table hidden><colgroup> <col></colgroup><tr><td>x</table>y'), 'y');
		// (a <nobr> in a <nobr> ends it)
		assert.equal(shown('<nobr style="display:none"><nobr>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<nobr style="display:none">a<b><nobr>BUY PILLS'), 'BUY PILLS');
		// (formatting elements opened again before an <svg>)
		assert.equal(shown('<h1><b hidden>a<h2></h2><svg><text>x</text></svg>'), '');
		assert.equal(shown('<p><b hidden>a</p><svg><text>x</text></svg><math><mi>y</mi></math>'), '');
	});

	it('reads forms as browsers do', () => {
		// (a form in a form is left out)
		assert.equal(shown('<form><form style="display:none">BUY PILLS</form>'), 'BUY PILLS');
		// (a form in a table holds nothing, and what follows is put in front
		//  of the table)
		assert.equal(shown('<table><form style="display:none">BUY PILLS</table>'), 'BUY PILLS');
		assert.equal(shown('<table><tr><form hidden><td>BUY PILLS</td></tr></table>'), 'BUY PILLS');
		assert.equal(shown('<table><p hidden><form style="visibility:visible">x</form>y</table>z'), 'z');
		// (but one in a cell is a form, as is one in a template)
		assert.equal(shown('<table><tr><td><form hidden>x</form>y</td></tr></table>'), 'y');
		assert.equal(shown('<template><form></template><form hidden>x</form>y'), 'y');
		assert.equal(shown('<form hidden><template><form>x</form></template>y'), '');
		assert.equal(shown('<table><template><form hidden>x</form></template></table>y'), 'y');
		// (an end tag ends the form open, and the elements open in it stay
		//  open; a paragraph or list item in it is closed first)
		assert.equal(shown('<form><div style="display:none"></form>x</div>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<span style="display:none"><form><div></form></div></span>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<form style="display:none"><p></form>BUY PILLS'), 'BUY PILLS');
		assert.equal(shown('<form style="display:none"><ul><li></form>x</ul>y'), 'y');
		// (not one out of scope, nor a form in an <svg> or <math>)
		assert.equal(shown('<form><table><tr><td style="display:none"></form>x</td></tr></table>y'), 'y');
		assert.equal(shown('<math><form style="display:none">x</form>BUY PILLS</math>'), 'BUY PILLS');
		assert.equal(shown('</form><form><p hidden>a</form>b'), 'b');
		// (a form a </form> took out no longer stops a list item from closing)
		assert.equal(shown('<ul><li>a<form style="display:none"><span>b</form><li>Buy cheap pills now'), 'a Buy cheap pills now');
		assert.equal(shown('<dl><dt>a<form style="display:none"><b>b</form><dd>shown'), 'a shown');
	});

	it('breaks no word at a hidden element', () => {
		assert.equal(shown('Vi<span style="display:none"><br></span>agra Vi<br hidden>agra Vi<div hidden>x</div>agra'), 'Viagra Viagra Viagra');
		// (a closed <details> breaks at its summary, not at what it hides)
		assert.equal(visibleText('a<details><summary>S</summary>b<div>c</div></details>d').text.replaceAll(/\s+/g, ' '), 'a S d');
	});

	it('reads a name ending in ";" that starts with one read without it, in text', () => {
		assert.equal(decodeEntities('Buy Vi&shyagra; now'), 'Buy Vi­agra; now');
		assert.equal(decodeEntities('a&nbspfoo; &notin; &ltimes; &zz;'), 'a foo; \u2209 \u22C9 &zz;');
		assert.equal(decodeEntities('?Vi&shyagra;', {attribute: true}), '?Vi&shyagra;');
	});
});

describe('links and lookalikes in a full scan', () => {
	const scanner = new SpamScanner({phishing: {cloudflare: false}});
	const scan = options => scanner.scan(message({text: 'Your account is locked. Please sign in.', ...options}));
	const names = result => result.tests.map(test => test.name);

	it('finds a lookalike host at the end of a paragraph, line or cell of HTML', async () => {
		for (const html of ['<p>Go to https://paypa1.com</p><p>Regards</p>', 'Go to https://paypa1.com<br>Thanks', '<table><tr><td>www.paypa1.com</td><td>next</td></tr></table>', '<div>https://paypa1.com</div>Bye']) {
			const result = await scan({html});
			assert.ok(names(result).includes('PHISHING_LOOKALIKE_DOMAIN'), html);
		}
	});
});

describe('QR codes drawn without an image', () => {
	const testNames = result => result.tests.map(test => test.name);
	const grid = (size, cell) => `<table>${Array.from({length: size}, () => `<tr>${cell.repeat(size)}</tr>`).join('')}</table>`;
	const blocks = rows => Array.from({length: rows}, () => '\u2588\u2588  \u2580\u2584\u2588 \u2584\u2584\u2580 \u2588\u2588\u2588  \u2580 \u2588'.repeat(2)).join('\n');

	it('finds a grid of small cells with background colors', () => {
		for (const cell of ['<td width="4" height="4" bgcolor="#000000"></td>', '<td style="width:5px;height:5px;background-color:#111"></td>', '<div style="background:#000;width: 3.5px;height:3.5px"></div>', '<TD WIDTH=4 BGCOLOR=black></TD>']) {
			assert.equal(drawnQrCode(grid(25, cell), []), true, cell);
		}

		// (not fewer cells than a QR code has, cells too big, or without colors)
		assert.equal(drawnQrCode(grid(20, '<td width="4" height="4" bgcolor="#000"></td>'), []), false);
		assert.equal(drawnQrCode(grid(25, '<td width="40" height="40" bgcolor="#000"></td>'), []), false);
		assert.equal(drawnQrCode(grid(25, '<td width="4" height="4"></td>'), []), false);
		assert.equal(drawnQrCode(grid(25, '<td bgcolor="#000"></td>'), []), false);
		// (nor past the characters read)
		assert.equal(drawnQrCode(`${' '.repeat(5000)}${grid(25, '<td width="4" bgcolor="#000"></td>')}`, [], {maxLength: 2000}), false);
		assert.equal(drawnQrCode(null, null), false);
	});

	it('finds ten lines of block characters or more, one after another', () => {
		assert.equal(drawnQrCode('', blocks(10)), true);
		assert.equal(drawnQrCode('', ['', `Scan me:\n\n  ${blocks(12).replaceAll('\n', '\n  ')}\n`]), true);
		// (not nine, lines broken by others, a bar, or a frame of lines)
		assert.equal(drawnQrCode('', blocks(9)), false);
		assert.equal(drawnQrCode('', `${blocks(5)}\nScan me\n${blocks(5)}`), false);
		assert.equal(drawnQrCode('', Array.from({length: 12}, () => `[${'\u2588'.repeat(30)}] 100%`).join('\n')), false);
		assert.equal(drawnQrCode('', Array.from({length: 12}, () => '\u2502 \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 \u2502').join('\n')), false);
		assert.equal(drawnQrCode('', Array.from({length: 12}, () => `\u2588${' '.repeat(30)}`).join('\n')), false);
		assert.equal(drawnQrCode('', Array.from({length: 12}, () => '\u25A1'.repeat(30)).join('\n')), false);
	});

	it('scores a QR code drawn without an image, also from a sender that passes DMARC', async () => {
		const scanner = new SpamScanner({phishing: {cloudflare: false}, classifier: false});
		// (a grid of 45 by 45 cells of 4 pixels, black and white)
		const cell = index => `<td width="4" height="4" bgcolor="${(index * 7) % 3 ? '#000000' : '#FFFFFF'}"></td>`;
		const grid = Array.from({length: 45}, (_, row) => `<tr height="4">${Array.from({length: 45}, (_, column) => cell((row * 45) + column)).join('')}</tr>`).join('');
		const html = `<p>Scan to keep your mailbox</p><table role="presentation" width="180" height="180" cellpadding="0" cellspacing="0">${grid}</table>`;
		const drawn = await scanner.scan(message({subject: 'Mailbox notice', html}));
		assert.ok(testNames(drawn).includes('DRAWN_QR_CODE'));
		assert.equal(drawn.results.obfuscation.qrCode, true);
		const passed = {authenticationResults: {dmarc: {status: {result: 'pass'}, domain: 'example.com'}}};
		assert.ok(testNames(await scanner.scan(message({subject: 'Mailbox notice', html}), passed)).includes('DRAWN_QR_CODE'));
		assert.equal((await scanner.scan(message({subject: 'Mailbox notice', html}), {scores: {drawnQrCode: 0}})).tests.find(test => test.name === 'DRAWN_QR_CODE')?.score ?? 0, 0);
		// (with block characters in the text)
		const text = `Scan to keep your mailbox:\n${Array.from({length: 12}, (_, row) => '\u2588\u2580\u2584 '.repeat(8).slice(row % 2)).join('\n')}`;
		assert.ok(testNames(await scanner.scan(message({subject: 'Mailbox notice', text}))).includes('DRAWN_QR_CODE'));
		// (not a newsletter's layout tables, nor a line of blocks)
		const layout = `<table>${'<tr><td width="300" bgcolor="#f5f5f5">News</td><td width="10"></td></tr>'.repeat(500)}</table>`;
		assert.ok(!testNames(await scanner.scan(message({subject: 'News', html: layout}))).includes('DRAWN_QR_CODE'));
		assert.ok(!testNames(await scanner.scan(message({subject: 'Progress', text: `Upload: ${'\u2588'.repeat(30)} 100%`}))).includes('DRAWN_QR_CODE'));
	});

	it('reads a long message in linear time', () => {
		const text = `${'\u2588 '.repeat(200_000)}\n`.repeat(5);
		const start = cpuTime();
		// (tags never closed, closed at the end, and sizes after many spaces)
		for (const html of ['<td width="4" bgcolor="#000"'.repeat(40_000), '<td'.repeat(700_000), `${'<td'.repeat(700_000)}>`, `<td bgcolor=1 width=${' '.repeat(380)}x>`.repeat(5000)]) {
			assert.equal(drawnQrCode(html, text), false);
		}

		assert.ok(cpuTime() - start < 1000);
	});
});

describe('links through security gateways and mailing services', () => {
	const safeLinks = target => `https://eur01.safelinks.protection.outlook.com/?url=${encodeURIComponent(target)}&data=05%7C02&reserved=0`;
	// (Proofpoint's second form: "-" and two hex digits for "%", "_" for "/")
	const proofpoint2 = target => `https://urldefense.proofpoint.com/v2/url?u=${encodeURIComponent(target).replaceAll('-', '%2D').replaceAll('_', '%5F').replaceAll('%', '-').replaceAll('/', '_')}&d=DwMFaQ&c=abc&r=def&m=ghi&s=jkl&e=`;
	const proofpoint3 = target => `https://urldefense.com/v3/__${target}__;!!AbCdEf!GhIj$`;

	it('reads the address a gateway goes on to', () => {
		assert.equal(unwrapLink(safeLinks('https://www.example.org/news?a=1&b=2')).href, 'https://www.example.org/news?a=1&b=2');
		assert.equal(unwrapLink(proofpoint2('https://my-site.example.org/a_b/c?d=1')).href, 'https://my-site.example.org/a_b/c?d=1');
		assert.equal(unwrapLink(proofpoint3('https://www.example.org/report')).href, 'https://www.example.org/report');
		// (wrapped twice, also by the same gateway, and many times)
		assert.equal(unwrapLink(safeLinks(proofpoint3('https://www.example.org/'))).hostname, 'www.example.org');
		assert.equal(unwrapLink(proofpoint3(proofpoint3('http://www.example.org/a'))).href, 'http://www.example.org/a');
		let wrapped = 'https://www.example.org/deep';
		for (let i = 0; i < 16; i++) {
			wrapped = i % 2 ? safeLinks(wrapped) : proofpoint3(wrapped);
		}

		assert.equal(unwrapLink(wrapped).href, 'https://www.example.org/deep');
		// (past as many as are unwrapped: a gateway's link, still wrapping one)
		assert.equal(unwrapLink(safeLinks(wrapped)).hostname, 'urldefense.com');
		// (a link through no gateway makes one URL, rather than also one that
		//  throws for each)
		const {URL: Original} = globalThis;
		let made = 0;
		globalThis.URL = class extends Original {
			constructor(...args) {
				made++;
				super(...args);
			}
		};
		try {
			assert.equal(unwrapLink('https://www.example.org/plain').href, 'https://www.example.org/plain');
		} finally {
			globalThis.URL = Original;
		}

		assert.equal(made, 1);
		// (no address in it, or none that is a web address: the gateway's own)
		for (const address of ['https://eur01.safelinks.protection.outlook.com/?data=1', safeLinks('mailto:a@example.org'), 'https://urldefense.proofpoint.com/v2/url?u=https-3A__', 'https://urldefense.proofpoint.com/v2/url?u=-E0', 'https://urldefense.proofpoint.com/v2/url?d=DwMFaQ', 'https://urldefense.com/v3/__https://www.example.org/', 'https://protect-eu.mimecast.com/s/AbCd?domain=example.org']) {
			assert.equal(registrableDomain(unwrapLink(address).hostname), registrableDomain(new URL(address).hostname), address);
		}

		assert.equal(unwrapLink('not a url'), null);
	});

	it('reads the address a redirect of a site people copy links from goes on to', () => {
		const target = 'https://docs.project.dev/guide?a=1';
		const encoded = encodeURIComponent(target);
		for (const url of [`https://www.google.com/url?q=${encoded}&sa=D&source=editors`, `https://www.google.co.uk/url?url=${encoded}`, `https://l.facebook.com/l.php?u=${encoded}&h=AT0`, `https://lm.facebook.com/l.php?u=${encoded}`, `https://l.messenger.com/l.php?u=${encoded}`, `https://l.instagram.com/?u=${encoded}&e=AT0`, `https://slack-redir.net/link?url=${encoded}`, `https://www.linkedin.com/redir/redirect?url=${encoded}`, `https://www.youtube.com/redirect?q=${encoded}&v=abc`, `https://steamcommunity.com/linkfilter/?url=${encoded}`, `https://vk.com/away.php?to=${encoded}`, `https://web.archive.org/web/20200101000000/${target}`]) {
			assert.equal(unwrapLink(url).href, target, url);
		}

		// (not another page of theirs, or a parameter that is no address)
		for (const url of ['https://www.google.com/search?q=https://docs.project.dev/', 'https://www.google.com/url?q=javascript:alert(1)', 'https://www.facebook.com/l.php?u=https://docs.project.dev/', 'https://l.facebook.com/other?u=https://docs.project.dev/', 'https://www.google.evil.example/url?q=https://docs.project.dev/', 'https://web.archive.org/web/*/docs.project.dev']) {
			assert.equal(unwrapLink(url).href, new URL(url).href, url);
		}

		// (and Google's AMP pages)
		assert.equal(unwrapLink('https://www.google.com/amp/s/docs.project.dev/guide?a=1').href, target);
		assert.equal(unwrapLink('https://www.google.com/amp/docs.project.dev/').href, 'http://docs.project.dev/');
		// (not a link that gives two addresses, which goes to one of them only
		//  the site knows: it is read as the site's own)
		for (const url of [`https://www.google.com/url?q=${encodeURIComponent('https://www.paypal.com/')}&url=${encodeURIComponent('https://evil.example/')}`, 'https://l.facebook.com/l.php?u=https://www.paypal.com/&u=https://evil.example/', `https://eur01.safelinks.protection.outlook.com/?url=${encodeURIComponent('https://www.paypal.com/')}&url=${encodeURIComponent('https://evil.example/')}`]) {
			assert.equal(unwrapLink(url).href, new URL(url).href, url);
			assert.equal(isDeceptiveLink({host: new URL(url).hostname, url, text: 'https://www.paypal.com/'}, {from: 'shop.example'}), true, url);
		}

		assert.equal(unwrapLink(`https://www.google.com/url?q=${encoded}&q=${encoded}`).href, target);
		// (so a link shown is read by where it goes, the address it shows or
		//  another)
		const link = (url, text) => ({host: new URL(url).hostname, url, text});
		assert.equal(isDeceptiveLink(link(`https://www.google.com/url?q=${encodeURIComponent('https://www.paypal.com/us/home')}&sa=D`, 'https://www.paypal.com/us/home'), {from: 'shop.example'}), false);
		assert.equal(isDeceptiveLink(link('https://www.google.com/url?q=https://evil.example/x&sa=D', 'https://www.paypal.com/signin'), {from: 'gmail.com', authenticated: true}), true);
		assert.equal(isDeceptiveLink(link(`https://l.facebook.com/l.php?u=${encodeURIComponent('https://evil.example/')}`, 'https://www.paypal.com'), {from: 'gmail.com', authenticated: true}), true);
		// (a brand's open redirect shown under its own name)
		assert.equal(isDeceptiveLink(link('https://www.google.com/amp/s/evil.example/login', 'https://www.google.com/'), {from: 'shop.example'}), true);
	});

	it('compares the address a gateway goes on to with the address shown', () => {
		const link = (url, text) => ({host: new URL(url).hostname, url, text});
		// (a message forwarded from behind the gateway shows the address it had)
		assert.equal(isDeceptiveLink(link(safeLinks('https://www.example.org/news'), 'https://www.example.org/news')), false);
		assert.equal(isDeceptiveLink(link(proofpoint2('https://www.example.org/news'), 'www.example.org/news')), false);
		assert.equal(isDeceptiveLink(link(proofpoint3('https://www.example.org/news'), 'https://www.example.org/news')), false);
		// (but not one that shows another)
		assert.equal(isDeceptiveLink(link(safeLinks('https://evil.example.net/login'), 'https://www.paypal.com/')), true);
		assert.equal(isDeceptiveLink(link(proofpoint3('https://evil.example.net/login'), 'https://www.paypal.com/')), true);
		// (a link to the gateway itself or through a click tracker behind it)
		assert.equal(isDeceptiveLink(link(safeLinks('https://x.ct.sendgrid.net/ls/click?upn=abc'), 'https://www.example.org/')), false);
		assert.equal(isDeceptiveLink(link(safeLinks('https://x.ct.sendgrid.net/ls/click?upn=abc'), 'https://www.paypal.com/'), {from: 'example.org'}), true);
		// (gateways whose links do not show the address are click trackers)
		for (const url of ['https://protect-us.mimecast.com/s/AbCdEf?domain=example.org', 'https://url.uk.m.mimecastprotect.com/s/AbCdEf?domain=example.org', 'https://linkprotect.cudasvc.com/url?a=https%3a%2f%2fwww.example.org&c=E,1,abc', 'https://secure-web.cisco.com/1AbCdEf/https%3A%2F%2Fwww.example.org', 'https://eur01.safelinks.protection.outlook.com/?data=1']) {
			assert.equal(isDeceptiveLink(link(url, 'https://www.example.org/')), false, url);
		}
	});

	it('takes the click tracking of more mailing services for no deception', () => {
		const link = (url, text = 'www.paypal.com') => ({host: new URL(url).hostname, url, text});
		for (const url of ['https://click.convertkit-mail2.com/abc123/def456', 'https://click.convertkit-mail.com/abc/def', 'https://844e968a.click.kit-mail3.com/abc', 'https://abcd.r.bh.d.sendibt3.com/tr/cl/abc', 'https://abc.r.sendibt2.com/tr/cl/abc', 'https://janewriter.createsend1.com/t/r-l-abc-def', 'https://cmail20.com/t/r-l-abc', 'https://abcd.clicks.mlsend.com/tj/c/abc', 'https://janewriter.lt.acemlnb.com/Prod/link-tracker?redirectUrl=abc', 'https://link.mail.beehiiv.com/ss/c/abc', 'https://elink.bhclick.com/ss/c/abc', 'https://substack.com/redirect/2/eyJlIjoi?j=abc', 'https://example-mid-prod1-t.adobe-campaign.com/r/?id=abc', 'https://app.mirabelsmarketingmanager.com/r/abc', 'https://tr-apac.apsis.one/c/abc']) {
			assert.equal(isDeceptiveLink(link(url)), false, url);
		}

		// (the numbered domains of a service, the gateways that rewrite links,
		//  and the links of affiliate networks and of apps)
		for (const url of ['https://trk.klclick1.com/ls/click?upn=abc', 'https://click.convertkit-mail4.com/abc', 'https://abc.r.a.d.sendibm1.com/mk/cl/f/abc', 'https://janewriter.cmail19.com/t/y-l-abc', 'https://janewriter.createsend27.com/t/abc', 'https://janewriter.lt.acemlna.com/Prod/link-tracker?abc', 'https://janewriter.lt.emlnk1.com/Prod/link-tracker?abc', 'https://links.mkt41.net/ctt?abc', 'https://t.sidekickopen01.com/abc', 'https://ab123.keap-link004.com/v2/click/abc', 'https://t.sidekickopen90.com/abc', 'https://click.eomail3.com/abc', 'https://www.anrdoezrs.net/click-abc', 'https://track.mdrctr.com/track/click/abc', 'https://a1b2c.musvc2.net/e/t?q=abc', 'https://www.anpdm.com/redirect/abc', 'https://mag.cuenote.jp/c/abc', 'https://janewriter.us5.list-manage1.com/track/click?u=abc', 'https://s123.t.en25.com/e/er?abc', 'https://email.r1.dmtrk.net/abc', 'https://go.spgo.io/f/a/abc', 'https://eu.spgo.io/f/a/abc', 'https://www.imiclk.com/abc', 'https://cl.exct.net/?qs=abc', 'https://janewriter.intercom-clicks.com/via/e?abc', 'https://nam12.safelinks.protection.office365.us/?id=abc', 'https://us-west-2.protection.sophos.com?d=abc', 'https://clicktime.symantec.com/abc', 'https://url.avanan.click/v2/abc', 'https://urlsand.esvalabs.com/?u=abc', 'https://url.emailprotection.link/?abc', 'https://click.linksynergy.com/deeplink?id=abc', 'https://janewriter.onelink.me/abc', 'https://janewriter.app.link/abc']) {
			assert.equal(isDeceptiveLink(link(url)), false, url);
		}

		// (not a number the service has not registered, which is anyone's, nor
		//  a name that only starts or ends as one of them)
		for (const url of ['https://cmail.com/t/abc', 'https://cmail31.com/t/abc', 'https://klclick6.com/abc', 'https://kit-mail.com/abc', 'https://dripemail4.com/abc', 'https://sendibt5.com/abc', 'https://mkt4.net/abc', 'https://notklclick1.com/abc', 'https://klclick1.com.example/abc', 'https://spgo.io.example/abc']) {
			assert.equal(isDeceptiveLink(link(url)), true, url);
		}

		// (but other pages of Substack, and beehiiv's newsletters, are sites)
		assert.equal(isDeceptiveLink(link('https://substack.com/@janewriter')), true);
		assert.equal(isDeceptiveLink(link('https://janewriter.beehiiv.com/p/hello')), true);
	});
});

describe('scripts in a word', () => {
	it('reads a Russian case ending after a name in Latin letters as no mix', () => {
		const text = 'Купил два iPhone\'а, у MacBook’и экран лучше, а Windows’а не было';
		assert.equal(segmentWords(text).mixed, 0);
		assert.equal(obfuscationOf(text).mixed, 0);
		// (but a word mixing scripts before or after an apostrophe)
		assert.equal(segmentWords('pаypal\'s сompany’s').mixed, 2);
	});

	it('folds lookalike letters to the script most of a word is in', () => {
		assert.deepEqual(segmentWords('пpивет').words, ['привет']);
		assert.deepEqual(segmentWords('pаypаl').words, ['paypal']);
		// (Latin when as many are Latin)
		assert.deepEqual(segmentWords('pаyраl').words, ['paypal']);
		// (Greek, and letters with no lookalike there kept)
		assert.deepEqual(segmentWords('ελληνikά').words, ['ελληνικά']);
		assert.deepEqual(segmentWords('приfетβ').words, ['приfетβ']);
		// (Greek and Cyrillic, without Latin letters: Cyrillic kept)
		assert.deepEqual(segmentWords('\u03B1\u03B2\u0433').words, ['\u03B1\u03B2\u0433']);
	});
});

describe('styled letters and host names in capitals', () => {
	it('takes squared letters for styled ones, not the negative circled and squared letters NFKC keeps', () => {
		assert.equal(normalizeText('\u{1F13F}\u{1F130}\u{1F148}').styled, true);
		assert.equal(normalizeText('\u{1F17F}\uFE0F Free parking, \u{1F170}\u{1F171} \u{1F150} \u{1F189}').styled, false);
	});

	it('reads host names written in capitals, not in mixed case', () => {
		assert.deepEqual(extractHosts('Log in at PAYPAL-VERIFY.COM today, or paypa1.com'), ['paypal-verify.com', 'paypa1.com']);
		assert.deepEqual(extractHosts('We moved to PAYPA1.COM and paypa1.com', new Set(['paypa1.com'])), []);
		// (not capitalised words, initials or acronyms)
		assert.deepEqual(extractHosts('Made in the U.S.A. by E.ON, see NOTES.TXT and README.MD. Thanks.Click here. AT&T INC.'), []);
	});
});
