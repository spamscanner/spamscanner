#!/usr/bin/env node
// Checks the translations in i18n/ against the English site, after
// `npm run site:build` has written i18n/source/:
//
// * every interface string is translated, with the same {placeholders},
// * every translated page starts with the hash of the English file it was
//   translated from, so an edit to the English page shows up here,
// * a translated page keeps the English page's headings, code blocks, inline
//   code, links and front matter, which the build relies on.
//
//   node scripts/i18n-check.js            all languages
//   node scripts/i18n-check.js de fr      some
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {Lexer} from 'marked';
import {
	DEFAULT, DIR, LOCALES, ROOT, markdownHash,
} from './site-i18n.js';

const source = JSON.parse(fs.readFileSync(path.join(DIR, 'source', 'ui.json'), 'utf8'));
const hashes = JSON.parse(fs.readFileSync(path.join(DIR, 'source', 'hashes.json'), 'utf8'));
const wanted = process.argv.slice(2);
const locales = LOCALES.filter(locale => locale.code !== DEFAULT && (wanted.length === 0 || wanted.includes(locale.code)));
for (const code of wanted) {
	if (!LOCALES.some(locale => locale.code === code)) {
		console.error(`Unknown language: ${code}`);
		process.exit(2);
	}
}

const errors = [];
const fail = (file, message) => errors.push(`${path.relative(ROOT, file)}: ${message}`);

const placeholders = text => [...text.matchAll(/{(\w+)}/g)].map(match => match[1]).sort().join(',');
const sameList = (a, b) => a.length === b.length && a.every((item, index) => item === b[index]);
const counts = list => {
	const map = new Map();
	for (const item of list) {
		map.set(item, (map.get(item) || 0) + 1);
	}

	return map;
};

function difference(english, translated) {
	const missing = [];
	const theirs = counts(translated);
	for (const [item, count] of counts(english)) {
		if ((theirs.get(item) || 0) < count) {
			missing.push(item);
		}
	}

	return missing;
}

const HEADER = /^<!-- source: ([\da-f]{12}) -->\n+/;

function frontMatter(text) {
	const match = /^<!--\n([\s\S]*?)\n-->\n/.exec(text);
	const data = {};
	for (const line of match ? match[1].split('\n') : []) {
		const index = line.indexOf(':');
		if (index > 0) {
			data[line.slice(0, index).trim()] = line.slice(index + 1).trim();
		}
	}

	return {data, body: match ? text.slice(match[0].length) : text};
}

// What a translation has to keep: headings by level, code blocks verbatim,
// inline code, and link and image targets.
function structure(markdown) {
	const headings = [];
	const code = [];
	const inline = [];
	const links = [];
	const walk = tokens => {
		for (const token of tokens || []) {
			switch (token.type) {
				case 'heading': {
					headings.push(token.depth);
					break;
				}

				case 'code': {
					code.push(`${token.lang || ''}\n${token.text}`);
					break;
				}

				case 'codespan': {
					inline.push(token.text);
					break;
				}

				case 'link':
				case 'image': {
					links.push(token.href);
					break;
				}

				default:
			}

			walk(token.tokens);
			if (token.type === 'list') {
				walk(token.items);
			}

			if (token.type === 'table') {
				for (const cell of [...token.header, ...token.rows.flat()]) {
					walk(cell.tokens);
				}
			}
		}
	};

	walk(new Lexer({gfm: true}).lex(markdown));
	return {
		headings, code, inline, links,
	};
}

function checkStrings(code) {
	const file = path.join(DIR, code, 'ui.json');
	if (!fs.existsSync(file)) {
		fail(file, 'missing');
		return;
	}

	let strings;
	try {
		strings = JSON.parse(fs.readFileSync(file, 'utf8'));
	} catch (error) {
		fail(file, `not valid JSON: ${error.message}`);
		return;
	}

	for (const [english, translation] of Object.entries(strings)) {
		if (!Object.hasOwn(source, english)) {
			fail(file, `string no longer used: ${JSON.stringify(english)}`);
		} else if (typeof translation !== 'string' || translation.trim() === '') {
			fail(file, `empty translation: ${JSON.stringify(english)}`);
		} else if (placeholders(translation) !== placeholders(english)) {
			fail(file, `placeholders differ for ${JSON.stringify(english)}: ${JSON.stringify(translation)}`);
		}
	}

	for (const english of Object.keys(source)) {
		if (!Object.hasOwn(strings, english)) {
			fail(file, `not translated: ${JSON.stringify(english)}`);
		}
	}
}

function checkPage(code, name) {
	const [kind, base] = name.split('/');
	const file = path.join(DIR, code, kind, base);
	if (!fs.existsSync(file)) {
		fail(file, 'missing');
		return;
	}

	const text = fs.readFileSync(file, 'utf8');
	const englishFile = path.join(ROOT, kind === 'docs' ? 'docs' : 'site/pages', base);
	const englishText = fs.readFileSync(englishFile, 'utf8');
	const match = HEADER.exec(text);
	if (!match) {
		fail(file, `first line must be <!-- source: ${markdownHash(englishText)} -->`);
		return;
	}

	if (match[1] !== hashes[name]) {
		fail(file, `translated from an older ${path.relative(ROOT, englishFile)} (${match[1]}, now ${hashes[name]}): update the translation and its source line`);
	}

	const english = frontMatter(englishText);
	const translated = frontMatter(text.slice(match[0].length));
	const keys = object => Object.keys(object).sort().join(', ');
	if (keys(english.data) !== keys(translated.data)) {
		fail(file, `front matter keys differ: ${keys(translated.data) || 'none'}, expected ${keys(english.data) || 'none'}`);
	}

	for (const [key, value] of Object.entries(translated.data)) {
		if (!value) {
			fail(file, `front matter ${key} is empty`);
		}
	}

	const a = structure(english.body);
	const b = structure(translated.body);
	if (!sameList(a.headings, b.headings)) {
		fail(file, `headings differ: levels ${b.headings.join(' ')}, expected ${a.headings.join(' ')}`);
	}

	if (!sameList(a.code, b.code)) {
		const index = a.code.findIndex((block, i) => block !== b.code[i]);
		fail(file, `code blocks must stay as in English (${b.code.length} of ${a.code.length}; block ${index + 1} differs)`);
	}

	for (const item of difference(a.inline, b.inline)) {
		fail(file, `inline code missing or changed: \`${item}\``);
	}

	for (const item of difference(b.inline, a.inline)) {
		fail(file, `inline code not in English: \`${item}\``);
	}

	for (const item of difference(a.links, b.links)) {
		fail(file, `link missing or changed: ${item}`);
	}

	for (const item of difference(b.links, a.links)) {
		fail(file, `link not in English: ${item}`);
	}
}

for (const {code} of locales) {
	checkStrings(code);
	for (const name of Object.keys(hashes)) {
		checkPage(code, name);
	}

	for (const kind of ['docs', 'pages']) {
		const folder = path.join(DIR, code, kind);
		for (const base of fs.existsSync(folder) ? fs.readdirSync(folder) : []) {
			if (!Object.hasOwn(hashes, `${kind}/${base}`)) {
				fail(path.join(folder, base), 'no English page by this name');
			}
		}
	}
}

if (errors.length > 0) {
	console.error(errors.join('\n'));
	console.error(`\n${errors.length} problem${errors.length === 1 ? '' : 's'} in the translations.`);
	process.exit(1);
}

console.log(`Translations OK: ${locales.length} language${locales.length === 1 ? '' : 's'}, ${Object.keys(source).length} strings and ${Object.keys(hashes).length} pages each.`);
