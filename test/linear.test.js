import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import process from 'node:process';
import {describe, it} from 'node:test';
import {fileURLToPath} from 'node:url';
import {
	linear, loadRe2, matchesOf, re2Source, replaceTags, stripTags, trimEndOf, usesRe2,
} from '../src/linear.js';
import {
	anchors, hrefOf, extractHosts, extractLinks, getFeatures, normalizeText, segmentWords, tagEnd,
} from '../src/tokenizer.js';
import {parseVerdict} from '../src/llm.js';
import {parseReportFields} from '../src/arf.js';
import {run} from './helpers/linear-workload.js';
import {cpuTime} from './helpers/cpu-time.js';

// Each function reads 100,000 characters of its worst input in well under this
// (the regular expressions of 7.0.1 took seconds for 20,000 and minutes for
// 100,000).
const BUDGET = 1500;

// (tests of RE2 itself, skipped when the optional package is not installed)
const onRe2 = {skip: usesRe2 ? false : 're2 is not installed'};

function assertFast(result) {
	for (const [name, ms] of Object.entries(result.times)) {
		assert.ok(ms < BUDGET, `${name}: ${Math.round(ms)}ms`);
	}
}

describe('linear time on message content', () => {
	it('uses RE2 when it is installed', onRe2, () => {
		assert.equal(usesRe2, true);
		assert.equal(linear('a').constructor.name, 'RE2');
	});

	it('reads worst-case content in linear time on RE2', onRe2, () => {
		const result = run();
		assert.equal(result.re2, true);
		assertFast(result);
	});

	it('reads worst-case content in linear time without RE2 (JavaScript regular expressions)', () => {
		const output = execFileSync(process.execPath, [
			'--require',
			fileURLToPath(new URL('helpers/without-re2.cjs', import.meta.url)),
			'--input-type=module',
			'--eval',
			`import {run} from ${JSON.stringify(new URL('helpers/linear-workload.js', import.meta.url).href)}; console.log(JSON.stringify(run()));`,
		], {encoding: 'utf8'});
		const result = JSON.parse(output.trim().split('\n').at(-1));
		assert.equal(result.re2, false);
		assertFast(result);
	});
});

describe('the same results on either engine', () => {
	// (bounds of DNS: 63 characters a label, a bare link of at most 12 labels
	//  and a host name of at most 11)
	it('bounds names as DNS does on RE2 too', () => {
		assert.deepEqual(extractLinks('see a.b.c.d.e.f.g.h.i.j.k.l.com/x and b.c.d.e.f.g.h.i.j.k.l.com/x', '').map(link => link.host), ['b.c.d.e.f.g.h.i.j.k.l.com']);
		assert.deepEqual(extractLinks(`x ${'a'.repeat(64)}.com/path ${'a'.repeat(63)}.com/path`, '').map(link => link.host), [`${'a'.repeat(63)}.com`]);
		assert.ok(!getFeatures({text: `x ${'a'.repeat(70)}.com/path`}).features.includes('pat:url'));
		assert.deepEqual(extractHosts('see a.b.c.d.e.f.g.h.i.j.k.com and b.c.d.e.f.g.h.i.j.k.com'), ['b.c.d.e.f.g.h.i.j.k.com']);
	});

	it('reads new worst cases in linear time', () => {
		const SIZE = 100_000;
		const fill = unit => unit.repeat(Math.ceil(SIZE / unit.length)).slice(0, SIZE);
		const cases = [
			() => anchors(fill('<a href=x><span title="</a>">')),
			() => anchors(fill('<a href=x><b t=">')),
			() => anchors(fill(`<a href=x>${'<b>'.repeat(600)}`)),
			() => anchors(fill(`<a href=x><b a="${'q'.repeat(3000)}<b c='${'q'.repeat(3000)}`)),
			() => anchors(`<a href=x>${fill('</a ')}`),
			() => anchors(fill('<a href=x"y ')),
			() => extractLinks('', fill('<a href=https://e.example/>Sign in at paypal.com today v2.0 x</a>')),
			() => extractLinks('', fill('http://a<')),
			() => extractLinks('', fill(`http://a${'<b>'.repeat(20)}`)),
			() => extractLinks(fill('\u8ACBa.com/x '), ''),
			() => normalizeText(fill('\u200B')),
			() => normalizeText(fill('a\u200B')),
			() => segmentWords(fill('h4x2r ab12cd \uB3C8 ')),
			() => getFeatures({text: fill('\u8BF7a.b.c.d.e.f.g.h.i.j.k.l.com/x \u200B\u00AD')}),
			// (re2 calls a replacement function in quadratic time on text outside
			//  ASCII: 200,000 characters took seconds)
			() => getFeatures({text: fill('\u8BF7a.com/x ').repeat(2)}, {maxLength: 200_000}),
		];
		for (const [index, run] of cases.entries()) {
			const started = cpuTime();
			run();
			const ms = cpuTime() - started;
			assert.ok(ms < BUDGET, `case ${index}: ${Math.round(ms)}ms`);
		}
	});
});

describe('linear helpers', () => {
	it('loads RE2, or nothing when it cannot load', () => {
		assert.equal(loadRe2(() => {
			throw new Error('missing');
		}), null);
		assert.equal(typeof loadRe2(), usesRe2 ? 'function' : 'object');
	});

	it('writes patterns for RE2, also where RE2 is not installed', () => {
		// (bounded repetition of a class of Unicode properties made unbounded,
		//  every other bound kept, and \s and \S as JavaScript reads them,
		//  outside a class and in one)
		const space = String.raw`\t\n\x0B\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`;
		assert.equal(re2Source('a{1,64}b{0,10}c{2,24}'), 'a{1,64}b{0,10}c{2,24}');
		assert.equal(re2Source(String.raw`[\p{L}._-]{1,64}@[a-z]{1,63}(?:\.[\P{N}]{0,63}){0,10}[\p{L}]{2,24}[\p{L}]x{1,10}[a\]]{1,10}[\p{L}]{1,2}`), String.raw`[\p{L}._-]+@[a-z]{1,63}(?:\.[\P{N}]*){0,10}[\p{L}]{2,24}[\p{L}]x{1,10}[a\]]{1,10}[\p{L}]{1,2}`);
		assert.equal(re2Source(String.raw`a\s[^\s<]\S`), `a[${space}][^${space}<][^${space}]`);
		assert.equal(re2Source('[a]]'), '[a]]');
		const js = linear('a{1,64}b{0,10}c{2,24}', 'g', null);
		assert.ok(js instanceof RegExp);
		assert.equal(js.source, 'a{1,64}b{0,10}c{2,24}');
		// (an engine given is passed the pattern written for RE2)
		const Engine = class {
			constructor(source, flags) {
				Object.assign(this, {source, flags});
			}
		};
		assert.deepEqual({...linear(String.raw`[\p{L}]{0,64}`, 'g', Engine)}, {source: String.raw`[\p{L}]*`, flags: 'g'});
	});

	it('compiles JavaScript regular expressions, and bounded repetition for RE2', onRe2, () => {
		const js = linear('a{1,64}b{0,10}c{2,24}', 'g', null);
		assert.ok(js instanceof RegExp);
		assert.equal(js.source, 'a{1,64}b{0,10}c{2,24}');
		const re2 = linear('a{1,64}b{0,10}c{2,24}', 'g');
		assert.equal(re2.source, 'a{1,64}b{0,10}c{2,24}');
		assert.equal('xaaab'.replace(re2, '-'), 'xaaab');
		assert.equal('xaaacc'.replace(re2, '-'), 'x-');
		assert.equal(`x${'a'.repeat(70)}cc`.replace(re2, '-'), `x${'a'.repeat(6)}-`);
		// (a class of Unicode properties unbounded: bounded, it is too large for RE2)
		assert.equal(linear(String.raw`[\p{L}\p{N}]{1,64}@`, 'u').source, String.raw`[\p{L}\p{N}]+@`);
	});

	it('gives RE2 JavaScript\'s whitespace (no-break and ideographic spaces too)', () => {
		const source = String.raw`a\s[^\s<]\S`;
		assert.throws(() => re2Source(String.raw`[\S]`), /character class/);
		assert.equal(re2Source(String.raw`a\.b\\c`), String.raw`a\.b\\c`);
		// (a trailing backslash is left for the engine to refuse)
		assert.equal(re2Source('a\\'), 'a\\');
		const re2 = linear(source, 'u');
		const js = linear(source, 'u', null);
		for (const text of ['a bc', 'a\u00A0bc', 'a\u3000bc', 'a\u2028bc', 'a\uFEFFbc', 'a\vbc', 'a b c', 'a\u00A0\u00A0c', 'axbc', 'a b<c', 'a b ']) {
			assert.equal(re2.test(text), js.test(text), JSON.stringify(text));
		}

		// What mailparser makes of "&nbsp;": the same links, phone numbers and
		// amounts as without RE2.
		const features = getFeatures({text: 'Visit www.example.com\u00A0today, call +1\u00A0555\u00A0123\u00A04567, only $\u00A099 http://example.com\u3000今日'});
		assert.deepEqual(features.links.map(link => link.host), ['www.example.com', 'example.com']);
		assert.ok(features.features.includes('pat:phone'));
		assert.ok(features.features.includes('pat:money'));
	});

	it('finds each match from the start, past matches of empty text', () => {
		const pattern = /b*/g;
		pattern.lastIndex = 2;
		assert.deepEqual([...matchesOf(pattern, 'abba')].map(match => [match.index, match[0]]), [[0, ''], [1, 'bb'], [3, ''], [4, '']]);
		assert.deepEqual([...matchesOf(/x/g, 'axbx')].map(match => match.index), [1, 3]);
	});

	it('finds the patterns of a message without matchAll, which compiles a pattern again on RE2', () => {
		// (on both engines)
		const prototypes = [RegExp.prototype, loadRe2()?.prototype].filter(Boolean);
		const originals = prototypes.map(prototype => prototype[Symbol.matchAll]);
		let calls = 0;
		for (const [index, prototype] of prototypes.entries()) {
			prototype[Symbol.matchAll] = function (...arguments_) {
				calls++;
				return originals[index].apply(this, arguments_);
			};
		}

		try {
			const text = 'Write to a@example.com or 192.0.2.1, see https://example.com/x and example.org/y, call +1 555 010 0100';
			const {features} = getFeatures({text, html: `<p>${text.replace('see', 'look at')}</p>`});
			assert.ok(features.includes('pat:email') && features.includes('pat:url'));
		} finally {
			for (const [index, prototype] of prototypes.entries()) {
				prototype[Symbol.matchAll] = originals[index];
			}
		}

		assert.equal(calls, 0);
	});

	it('trims characters from the end', () => {
		assert.equal(trimEndOf('http://example.com/a).,', ').,'), 'http://example.com/a');
		assert.equal(trimEndOf('))', ')'), '');
		assert.equal(trimEndOf('abc', ')'), 'abc');
	});

	it('strips tags and script and style elements, in any case', () => {
		assert.equal(stripTags(''), '');
		assert.equal(stripTags(null), '');
		assert.equal(stripTags('a<b>c</b><SCRIPT>x<y</script >d<style>e</STYLE>f', ''), 'acdf');
		// An element without its closing tag stays (its tags are stripped), and
		// so does every later one of its kind.
		assert.equal(stripTags('a<script>b<script>c</style>d', '|'), 'a|b|c|d');
		assert.equal(stripTags('<style>a</style><style>b', '|'), '||b');
		// (as /<[^>]*>/g: from each "<" to the next ">")
		assert.equal(stripTags('a < b <c> d', ''), 'a  d');
		// (tag names in ASCII letters only, on either engine, as browsers read
		// them: "\u017F" folds to "s" in Unicode)
		assert.equal(stripTags('<\u017Fcript>a</script>b', ''), 'ab');
		assert.equal(stripTags('<script>a</\u017Fcript>b</script>c', ''), 'c');
	});

	it('replaces tags exactly as /<[^>]*>/g does', () => {
		assert.equal(replaceTags('a<b>c<d', '|'), 'a|c<d');
		assert.equal(replaceTags('no tags'), 'no tags');
		let seed = 7;
		const random = () => {
			seed = ((seed * 1_103_515_245) + 12_345) % 2_147_483_648;
			return seed / 2_147_483_648;
		};

		for (let i = 0; i < 2000; i++) {
			const html = Array.from({length: Math.floor(random() * 30)}, () => '<>a "\''[Math.floor(random() * 5)]).join('');
			assert.equal(replaceTags(html, '_'), html.replaceAll(/<[^>]*>/g, '_'), JSON.stringify(html));
		}
	});
});

describe('links in HTML', () => {
	it('reads each link and its text', () => {
		assert.deepEqual(anchors('<p><a class="x" href="https://a.example/1">one <b>1</b></a> <A HREF=\'https://b.example/2\'>two</a > <a href=https://c.example/3>three</a></p>'), [
			{href: 'https://a.example/1', inner: 'one 1'},
			{href: 'https://b.example/2', inner: 'two'},
			{href: 'https://c.example/3', inner: 'three'},
		]);
	});

	it('reads tags whose quoted attributes hold ">" or "<"', () => {
		assert.deepEqual(anchors('<a href="https://evil.example/x?a=>b">https://www.paypal.com/</a>'), [{href: 'https://evil.example/x?a=>b', inner: 'https://www.paypal.com/'}]);
		assert.deepEqual(anchors('<a title=\'a<b\' href="https://evil.example/">https://www.paypal.com/</a>'), [{href: 'https://evil.example/', inner: 'https://www.paypal.com/'}]);
		assert.deepEqual(extractLinks('', '<a title="a<b" href="https://evil.example/">https://www.paypal.com/</a>').map(link => link.host), ['evil.example', 'www.paypal.com']);
		assert.equal(tagEnd('<a href="x">', 0), 12);
		assert.equal(tagEnd('<a href="x', 0), -1);
		// (a "<" outside quotes is part of the tag, as browsers read it)
		assert.equal(tagEnd('<a href=x <b>', 0), 13);
		// (a quote not closed within 6000 characters: the next ">")
		assert.equal(tagEnd(`<a "${'x'.repeat(6000)}>`, 0), 6005);
		assert.equal(tagEnd('<a "x>y', 0), 6);
		// (a quote opens a value only after "=": in an unquoted value it is
		//  part of it)
		assert.equal(tagEnd('<a href=x"y>z">', 0), 12);
		assert.equal(tagEnd('<a href = "y>z" x=\'>\'>', 0), 22);
		assert.equal(tagEnd('<a x="a""b>c">', 0), 11);
		assert.deepEqual(extractLinks('', '<a href=https://ok.example/"a>Hi</a> <a href="https://evil.example/">https://www.paypal.com/</a> <b title=">">x</b>').filter(link => link.text).map(link => link.host), ['evil.example']);
		// (a "</a>" in the value of an attribute ends no link, a "</a" tag with
		//  attributes does)
		assert.deepEqual(anchors('<a href="https://a.example/">one <i title="</a>">two</i></a><a href="https://b.example/">b</a title=x><a href="https://c.example/">c</a'), [{href: 'https://a.example/', inner: 'one two'}, {href: 'https://b.example/', inner: 'b'}, {href: 'https://c.example/', inner: ''}]);
		assert.deepEqual(anchors('<a href="https://a.example/">y</A\n><A href="https://b.example/">z<a'), [{href: 'https://a.example/', inner: 'y'}, {href: 'https://b.example/', inner: ''}]);
		for (const html of ['<a href="https://evil.example/" <x>https://www.paypal.com/</a>', '<a <b href="https://evil.example/">https://www.paypal.com/</a>', '<a href="https://evil.example/"/<>https://www.paypal.com/</a>']) {
			assert.deepEqual(extractLinks('', html).filter(link => link.text).map(link => link.host), ['evil.example'], html);
		}
	});

	it('keeps every link, without its text when "</a>" is not close by, and skips tags without an href', () => {
		assert.deepEqual(anchors('<a name="top">top</a>'), []);
		assert.deepEqual(anchors('<a href="">x</a>'), []);
		// (a long href, or a long tag, is a link all the same)
		const long = `https://a.example/${'x'.repeat(4000)}`;
		assert.deepEqual(anchors(`<a href="${long}">x</a>`), [{href: long, inner: 'x'}]);
		assert.deepEqual(anchors(`<a title="${'x'.repeat(6000)}" href="https://a.example/">x</a>`), [{href: 'https://a.example/', inner: 'x'}]);
		// (a mail client shows a link never closed, or around long markup)
		assert.deepEqual(anchors(`<a href="https://a.example/">${'x'.repeat(2001)}</a>`), [{href: 'https://a.example/', inner: ''}]);
		assert.deepEqual(anchors('<a href="https://a.example/">no end'), [{href: 'https://a.example/', inner: ''}]);
		// (an "href=" inside the value of another attribute is not the href)
		assert.deepEqual(anchors('<a title="x href=\'https://fake.example/\'" href="https://real.example/">x</a>'), [{href: 'https://real.example/', inner: 'x'}]);
		assert.deepEqual(anchors('<a/href=https://a.example/>x</a>'), [{href: 'https://a.example/', inner: 'x'}]);
		// (an attribute without a value, and a tag without attributes)
		assert.equal(hrefOf('<a download href="https://a.example/">'), 'https://a.example/');
		assert.equal(hrefOf('<a'), null);
		assert.equal(hrefOf('<a href = "https://a.example/">'), 'https://a.example/');
		// (another <a> ends a link, as browsers read it; and "<a-b" or "<a"
		//  with a no-break space is no <a>)
		assert.deepEqual(anchors('<a href="https://ok.example/">Click <a href="https://evil.example/">here</a>'), [{href: 'https://ok.example/', inner: 'Click'}, {href: 'https://evil.example/', inner: 'here'}]);
		assert.deepEqual(anchors('<a-b href="https://custom.example/">x</a-b> <a\u00A0href="https://nbsp.example/">y</a>'), []);
		// (an address is kept up to 16,384 characters)
		assert.equal(extractLinks('', `<a href="https://long.example/${'a'.repeat(20_000)}">t</a>`)[0].url.length, 16_384);
		// (a link in brackets, as mailparser writes the links of HTML in its text)
		assert.deepEqual(extractLinks('here [https://a.example/x]then', '').map(link => link.url), ['https://a.example/x']);
		// (a quote not closed in the tag runs to its end)
		assert.equal(hrefOf('<a href="https://a.example/x>'), 'https://a.example/x>');
		assert.equal(hrefOf('<a title="x">'), null);
	});

	it('pairs each link with the next "</a>", once', () => {
		// The first tag's "</a>" is too far (so it has no text); the second tag
		// uses the same one.
		const html = `<a href="https://a.example/">${'x'.repeat(2001)}<a href="https://b.example/">b</a> <a href="https://c.example/">c</a>`;
		assert.deepEqual(anchors(html), [{href: 'https://a.example/', inner: ''}, {href: 'https://b.example/', inner: 'b'}, {href: 'https://c.example/', inner: 'c'}]);
		// A "</a>" too far for one link, then a link after it.
		assert.deepEqual(anchors(`<a href="https://a.example/">${'x'.repeat(2001)}</a><a href="https://b.example/">b</a>`), [{href: 'https://a.example/', inner: ''}, {href: 'https://b.example/', inner: 'b'}]);
		// (another <a> tag ends a link even with no "</a>" after it, as browsers
		//  read it; the last link, never closed, has no text)
		assert.deepEqual(anchors('<a href="https://a.example/">a <a href="https://b.example/">b'), [{href: 'https://a.example/', inner: 'a'}, {href: 'https://b.example/', inner: ''}]);
		assert.equal(extractLinks('', '<a href="https://a.example/x">https://shown.example</a>')[0].text, 'https://shown.example');
	});
});

describe('reasoning and report fields', () => {
	it('removes <think> blocks, an unclosed one to the end', () => {
		assert.equal(parseVerdict('<think>ham</think>{"verdict":"spam","confidence":0.9}').verdict, 'spam');
		assert.equal(parseVerdict('<THINK>a</THINK><think>b</think>{"verdict":"phishing","confidence":0.8}').verdict, 'phishing');
		// Unclosed (a model cut off while it reasons): what it quotes from the
		// message is no verdict.
		assert.equal(parseVerdict('<think>The email says {"verdict":"ham","confidence":0.99}. But the links'), null);
		assert.equal(parseVerdict('<think>The user asks if this is ham'), null);
		assert.equal(parseVerdict('{"verdict":"spam"} <think>ham').verdict, 'spam');
		// (thinking of any length)
		assert.equal(parseVerdict(`<think>${'x'.repeat(30_000)}</think>{"verdict":"spam","confidence":0.9}`).verdict, 'spam');
	});

	it('reads report fields, skipping lines with a line break of their own', () => {
		assert.deepEqual(parseReportFields('Feedback-Type: abuse\nUser-Agent:\r\nSource-IP: \u2028 192.0.2.1\nBroken: a\rb'), {
			feedback_type: 'abuse', user_agent: '', source_ip: '192.0.2.1',
		});
	});
});
