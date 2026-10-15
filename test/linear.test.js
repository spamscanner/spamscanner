import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import process from 'node:process';
import {describe, it} from 'node:test';
import {fileURLToPath} from 'node:url';
import {
	linear, loadRe2, re2Source, replaceTags, stripTags, trimEndOf, usesRe2,
} from '../src/linear.js';
import {
	anchors, extractLinks, getFeatures, tagEnd,
} from '../src/tokenizer.js';
import {parseVerdict} from '../src/llm.js';
import {parseReportFields} from '../src/arf.js';
import {run} from './helpers/linear-workload.js';

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

describe('linear helpers', () => {
	it('loads RE2, or nothing when it cannot load', () => {
		assert.equal(loadRe2(() => {
			throw new Error('missing');
		}), null);
		assert.equal(typeof loadRe2(), usesRe2 ? 'function' : 'object');
	});

	it('writes patterns for RE2, also where RE2 is not installed', () => {
		// (repetition bounded for JavaScript only made unbounded, and \s and \S
		//  as JavaScript reads them, outside a class and in one)
		const space = String.raw`\t\n\x0B\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`;
		assert.equal(re2Source('a{1,64}b{0,10}c{2,24}'), 'a+b*c{2,24}');
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
		assert.deepEqual({...linear('a{0,64}', 'g', Engine)}, {source: 'a*', flags: 'g'});
	});

	it('compiles JavaScript regular expressions, and unbounded repetition for RE2', onRe2, () => {
		const js = linear('a{1,64}b{0,10}c{2,24}', 'g', null);
		assert.ok(js instanceof RegExp);
		assert.equal(js.source, 'a{1,64}b{0,10}c{2,24}');
		const re2 = linear('a{1,64}b{0,10}c{2,24}', 'g');
		assert.equal(re2.source, 'a+b*c{2,24}');
		assert.equal('xaaab'.replace(re2, '-'), 'xaaab');
		assert.equal('xaaacc'.replace(re2, '-'), 'x-');
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
		for (const html of ['<a href="https://evil.example/" <x>https://www.paypal.com/</a>', '<a <b href="https://evil.example/">https://www.paypal.com/</a>', '<a href="https://evil.example/"/<>https://www.paypal.com/</a>']) {
			assert.deepEqual(extractLinks('', html).filter(link => link.text).map(link => link.host), ['evil.example'], html);
		}
	});

	it('skips tags without an href, with a long href or tag, or without "</a>" close by', () => {
		assert.deepEqual(anchors('<a name="top">top</a>'), []);
		assert.deepEqual(anchors('<a href="">x</a>'), []);
		assert.deepEqual(anchors(`<a href="https://a.example/${'x'.repeat(4000)}">x</a>`), []);
		assert.deepEqual(anchors(`<a title="${'x'.repeat(6000)}" href="https://a.example/">x</a>`), []);
		assert.deepEqual(anchors(`<a href="https://a.example/">${'x'.repeat(2001)}</a>`), []);
		assert.deepEqual(anchors('<a href="https://a.example/">no end'), []);
	});

	it('pairs each link with the next "</a>", once', () => {
		// The first tag's "</a>" is too far; the second tag uses the same one.
		const html = `<a href="https://a.example/">${'x'.repeat(2001)}<a href="https://b.example/">b</a> <a href="https://c.example/">c</a>`;
		assert.deepEqual(anchors(html), [{href: 'https://b.example/', inner: 'b'}, {href: 'https://c.example/', inner: 'c'}]);
		// A "</a>" too far for one link, then a link after it.
		assert.deepEqual(anchors(`<a href="https://a.example/">${'x'.repeat(2001)}</a><a href="https://b.example/">b</a>`), [{href: 'https://b.example/', inner: 'b'}]);
		// No "</a>" after the first tag means none after later ones.
		assert.deepEqual(anchors('<a href="https://a.example/">a <a href="https://b.example/">b'), []);
		assert.equal(extractLinks('', '<a href="https://a.example/x">https://shown.example</a>')[0].text, 'https://shown.example');
	});
});

describe('reasoning and report fields', () => {
	it('removes closed <think> blocks only', () => {
		assert.equal(parseVerdict('<think>ham</think>{"verdict":"spam","confidence":0.9}').verdict, 'spam');
		assert.equal(parseVerdict('<THINK>a</THINK><think>b</think>{"verdict":"phishing","confidence":0.8}').verdict, 'phishing');
		// Unclosed: everything after it is kept.
		assert.equal(parseVerdict('<think>{"verdict":"scam","confidence":0.7}').verdict, 'scam');
		// (thinking of any length)
		assert.equal(parseVerdict(`<think>${'x'.repeat(30_000)}</think>{"verdict":"spam","confidence":0.9}`).verdict, 'spam');
	});

	it('reads report fields, skipping lines with a line break of their own', () => {
		assert.deepEqual(parseReportFields('Feedback-Type: abuse\nUser-Agent:\r\nSource-IP: \u2028 192.0.2.1\nBroken: a\rb'), {
			feedback_type: 'abuse', user_agent: '', source_ip: '192.0.2.1',
		});
	});
});
