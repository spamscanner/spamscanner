// Inputs that made earlier versions' regular expressions read the same text
// again from every position (quadratic time), each 100,000 characters: a run
// of letters with no "@", dotted labels with no "/", unclosed tags and so on.
// Run in-process (RE2) and in a child process without re2 (test/linear.test.js),
// it times the functions that read message content.
import {Buffer} from 'node:buffer';
import {parseReportFields} from '../../src/arf.js';
import {inspectAttachments} from '../../src/attachments.js';
import {isArbitrary} from '../../src/is-arbitrary.js';
import {usesRe2} from '../../src/linear.js';
import {describeMessage, parseVerdict, redact} from '../../src/llm.js';
import {
	decodeEntities, extractLinks, getFeatures, visibleText,
} from '../../src/tokenizer.js';
import {cpuTime} from './cpu-time.js';

const SIZE = 100_000;
const fill = unit => unit.repeat(Math.ceil(SIZE / unit.length)).slice(0, SIZE);

function time(run) {
	const started = cpuTime();
	run();
	return cpuTime() - started;
}

const from = name => ({value: [{name, address: 'sender@example.com'}], text: `${name} <sender@example.com>`});

/**
 * Milliseconds each function takes on its worst input.
 * @returns {{re2: boolean, times: Record<string, number>}}
 */
export function run() {
	const times = {};
	const letters = fill('a');
	const cyrillic = fill('а');
	const cases = {
		'text: letters with no @': () => getFeatures({text: letters}),
		'text: Cyrillic letters with no @': () => getFeatures({text: cyrillic}),
		'text: dotted labels with no /': () => getFeatures({text: fill('aa.')}),
		'text: link ending in punctuation': () => extractLinks(`http://example.com/${fill(')')}x`, ''),
		'html: unclosed <a href=': () => getFeatures({html: fill('<a href=')}),
		'html: unclosed <a': () => getFeatures({html: fill('<a ')}),
		'html: one long unclosed <a href=': () => getFeatures({html: `<a href=${fill('x')}`}),
		'html: <a> tags without </a>': () => extractLinks('', fill('<a href="http://a.example/">x ')),
		'html: unclosed <': () => getFeatures({html: fill('<')}),
		'html: unclosed <img': () => getFeatures({html: fill('<img ')}),
		'html: unclosed <script and <style': () => getFeatures({html: `${fill('<script ')}${fill('<style ')}`}),
		'html: <a> tags opening quotes': () => getFeatures({html: fill('<a "')}),
		'html: <a> tags inside an unclosed quote': () => getFeatures({html: `<a '${fill('<a "x" ')}`}),
		'html: <a> tags with both quotes unclosed': () => getFeatures({html: `<a '<a "${fill('<a x')}`}),
		'html: shown text of unclosed tags': () => visibleText(fill('<b>x')),
		'html: shown text of close tags with nothing open': () => visibleText(`${'<div>'.repeat(600)}${fill('</i>')}`),
		'html: shown text of hidden blocks and cells': () => visibleText(fill('<p style="display:none">a<td>')),
		'html: shown text of a lone <': () => visibleText(fill('<')),
		'html: shown text of unclosed comments': () => visibleText(fill('x<!--')),
		'html: shown text of many short comments': () => visibleText(fill('<!---->x')),
		'html: shown text of attributes opening quotes': () => visibleText(fill('<a x=\'')),
		'html: shown text of nested sizes': () => visibleText(fill('<span style="font-size:50%;display:/*">')),
		'html: references with no ;': () => decodeEntities(fill('&#1')),
		'display name: letters with no @': () => getFeatures({from: from(letters)}),
		'display name: rules': () => isArbitrary({from: from(letters), subject: '', text: ''}),
		'html: rules on attributes': () => isArbitrary({html: fill('<a title="x" data-a=\'y\'>')}),
		'html: rules on unclosed quotes of attributes': () => isArbitrary({html: fill('<a b="<a b=\'')}),
		'text: rules on amounts of money': () => isArbitrary({subject: 'You\'ve been hacked', text: fill('pay 1,')}),
		'text: rules on digits': () => isArbitrary({subject: 'You\'ve been hacked', text: fill('9')}),
		'llm: redact letters with no @': () => redact(letters),
		'llm: redact ? with no =': () => redact(fill('?')),
		'llm: describe unclosed html': () => describeMessage({html: fill('<script ')}),
		'llm: unclosed <think>': () => parseVerdict(fill('<think>')),
		'llm: braces with no object': () => parseVerdict(fill('{')),
		'llm: nested objects': () => parseVerdict(fill('{"a":')),
		'pdf: repeated /OpenAction <<': () => inspectAttachments([{filename: 'a.pdf', contentType: 'application/pdf', content: Buffer.from(`%PDF-1.7\n${fill('/OpenAction<<')}`, 'latin1')}]),
		'arf: field with spaces and a line break': () => parseReportFields(`a:${fill(' ')}\rb`),
	};
	for (const [name, call] of Object.entries(cases)) {
		times[name] = time(call);
	}

	return {re2: usesRe2, times};
}
