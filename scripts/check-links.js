#!/usr/bin/env node
// Checks every link and fragment between pages of the built site (_site/),
// that every page the sitemap lists exists, and that every page has a title,
// a description and a canonical URL. External links are not fetched.
// Run after `npm run site:build`.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '_site');
const files = fs.readdirSync(OUT, {recursive: true}).map(String).filter(file => file.endsWith('.html'));
const ids = new Map();
const pageFor = file => `/${file.replace(/index\.html$/, '').replaceAll('\\', '/')}`;

for (const file of files) {
	const html = fs.readFileSync(path.join(OUT, file), 'utf8');
	ids.set(pageFor(file), new Set([...html.matchAll(/\sid="([^"]+)"/g)].map(match => match[1])));
}

// The page a link points to, null for a file that is not a page, or undefined if missing.
function resolve(target) {
	const clean = decodeURIComponent(target.split('#')[0].split('?')[0]);
	const file = path.join(OUT, clean.endsWith('/') ? `${clean}index.html` : clean);
	if (fs.existsSync(file) && fs.statSync(file).isFile()) {
		return clean.endsWith('/') ? clean : null;
	}

	return undefined;
}

const problems = [];
for (const file of files) {
	const html = fs.readFileSync(path.join(OUT, file), 'utf8');
	const from = pageFor(file);
	for (const tag of ['<title>', 'name="description"', 'rel="canonical"']) {
		if (!html.includes(tag)) {
			problems.push(`${from}: no ${tag}`);
		}
	}

	for (const match of html.matchAll(/\s(?:href|src|data-poster)="([^"]+)"/g)) {
		const href = match[1].replaceAll('&amp;', '&');
		if (/^(?:https?:|mailto:|sms:|data:)/.test(href)) {
			continue;
		}

		if (href.startsWith('#')) {
			if (href.length > 1 && !ids.get(from)?.has(href.slice(1))) {
				problems.push(`${from}: missing #${href.slice(1)}`);
			}

			continue;
		}

		if (!href.startsWith('/')) {
			problems.push(`${from}: relative link ${href}`);
			continue;
		}

		const page = resolve(href);
		if (page === undefined) {
			problems.push(`${from}: broken link ${href}`);
		} else if (href.includes('#') && page && !ids.get(page)?.has(href.split('#')[1])) {
			problems.push(`${from}: missing ${href}`);
		}
	}
}

const sitemap = fs.readFileSync(path.join(OUT, 'sitemap.xml'), 'utf8');
for (const [, loc] of sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)) {
	const {pathname} = new URL(loc);
	if (!fs.existsSync(path.join(OUT, pathname, 'index.html'))) {
		problems.push(`sitemap: ${loc} does not exist`);
	}
}

for (const [, link] of fs.readFileSync(path.join(OUT, 'llms.txt'), 'utf8').matchAll(/]\((https:\/\/spamscanner\.net[^)]+)\)/g)) {
	if (!fs.existsSync(path.join(OUT, new URL(link).pathname))) {
		problems.push(`llms.txt: ${link} does not exist`);
	}
}

if (problems.length > 0) {
	console.error(`${problems.length} link problem${problems.length === 1 ? '' : 's'}:\n${[...new Set(problems)].slice(0, 100).map(problem => `  ${problem}`).join('\n')}`);
	process.exitCode = 1;
} else {
	console.log(`Links OK: ${files.length} pages checked.`);
}
