// The website: scripts/build-site.js builds spamscanner.net into a temporary
// directory, and the files search engines, AI crawlers and browsers read are
// checked as they come out.
import assert from 'node:assert/strict';
import {existsSync, readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';
import {before, describe, it} from 'node:test';
import {build} from '../scripts/build-site.js';
import {temporaryDirectory} from './helpers/index.js';

const SITE = 'https://spamscanner.net';
let out;
let pages;

const read = file => readFileSync(path.join(out, file), 'utf8');
const attribute = (html, pattern) => pattern.exec(html)?.[1];
const meta = (html, key) => attribute(html, new RegExp(`<meta (?:name|property)="${key.replaceAll(':', String.raw`\:`)}" content="([^"]*)"`));
const jsonLd = html => JSON.parse(attribute(html, /<script type="application\/ld\+json">([\s\S]*?)<\/script>/));
const nodes = (html, type) => jsonLd(html)['@graph'].filter(node => [node['@type']].flat().includes(type));

describe('website', {timeout: 300_000}, () => {
	before(async () => {
		out = temporaryDirectory();
		await build({outDir: out});
		pages = readdirSync(out, {recursive: true}).map(String).filter(file => file.endsWith('.html'));
	});

	it('lets every crawler in, AI crawlers by name, and names the sitemap', () => {
		const robots = read('robots.txt');
		assert.match(robots, /^User-agent: \*\nAllow: \/$/m);
		assert.doesNotMatch(robots, /Disallow:\s*\//);
		for (const bot of ['GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'PerplexityBot', 'Perplexity-User', 'Google-Extended', 'Applebot-Extended', 'CCBot', 'Bingbot', 'DuckAssistBot', 'meta-externalagent']) {
			assert.match(robots, new RegExp(`^User-agent: ${bot}$`, 'm'), bot);
		}

		assert.match(robots, new RegExp(`^Sitemap: ${SITE}/sitemap.xml$`, 'm'));
	});

	it('lists every indexed page in the sitemap, with absolute URLs and dates', () => {
		const sitemap = read('sitemap.xml');
		assert.match(sitemap, /^<\?xml version="1.0" encoding="UTF-8"\?>\n<urlset xmlns="http:\/\/www.sitemaps.org\/schemas\/sitemap\/0.9">/);
		const entries = [...sitemap.matchAll(/<url><loc>([^<]+)<\/loc><lastmod>([^<]+)<\/lastmod><\/url>/g)];
		assert.equal(entries.length, (sitemap.match(/<url>/g) || []).length);
		const locs = entries.map(([, loc]) => loc);
		assert.equal(new Set(locs).size, locs.length);
		for (const [, loc, lastmod] of entries) {
			assert.ok(loc.startsWith(`${SITE}/`), loc);
			assert.ok(!Number.isNaN(Date.parse(lastmod)), lastmod);
			const html = read(path.join(new URL(loc).pathname, 'index.html'));
			assert.doesNotMatch(html, /<meta name="robots" content="noindex">/, loc);
		}

		for (const page of ['/', '/about/', '/glossary/', '/self-hosted-spam-filter/', '/faq/', '/de/about/', '/ja/glossary/', '/ar/self-hosted-spam-filter/']) {
			assert.ok(locs.includes(`${SITE}${page}`), page);
		}

		assert.ok(sitemap.length < 1_000_000, 'small enough to fetch in one request');
	});

	it('publishes llms.txt and llms-full.txt from the pages', () => {
		const llms = read('llms.txt');
		assert.match(llms, /^# Spam Scanner\n\n> \S/);
		for (const heading of ['## Documentation', '## Guides', '## About']) {
			assert.ok(llms.includes(`\n${heading}\n`), heading);
		}

		const links = [...llms.matchAll(/]\((https:\/\/spamscanner\.net\/[^)]*)\): \S/g)].map(([, link]) => link);
		assert.ok(links.length > 20);
		for (const link of links) {
			assert.ok(existsSync(path.join(out, new URL(link).pathname)), link);
		}

		for (const page of ['/index.md', '/about/index.md', '/glossary/index.md', '/self-hosted-spam-filter/index.md']) {
			assert.ok(links.includes(`${SITE}${page}`), page);
		}

		const full = read('llms-full.txt');
		for (const heading of ['# About Spam Scanner', '# Email spam filter glossary', '# Self-hosted spam filter', '## Features']) {
			assert.ok(full.includes(`\n${heading}\n`), heading);
		}
	});

	it('gives every page a title, description, canonical URL, social tags and valid structured data', () => {
		assert.ok(pages.length > 600);
		for (const file of pages) {
			const html = read(file);
			assert.match(html, /^<!doctype html>\n<html lang="[a-z]{2}(?:-[A-Z]{2})?"/, file);
			assert.equal((html.match(/<title>/g) || []).length, 1, file);
			assert.equal((html.match(/<h1[ >]/g) || []).length, 1, file);
			assert.ok(meta(html, 'description')?.length > 50, file);
			assert.match(html, /<meta name="referrer" content="strict-origin-when-cross-origin">/, file);
			const canonical = attribute(html, /<link rel="canonical" href="([^"]+)">/);
			assert.ok(canonical.startsWith(`${SITE}/`), file);
			assert.equal(meta(html, 'og:url'), canonical, file);
			assert.equal(meta(html, 'og:image'), `${SITE}/og.png`, file);
			assert.equal(meta(html, 'og:image:width'), '1200', file);
			assert.equal(meta(html, 'og:image:height'), '630', file);
			assert.equal(meta(html, 'twitter:card'), 'summary_large_image', file);
			// Readers that stop after a few tags still find the image and card.
			const social = [...html.matchAll(/<meta (?:name|property)="((?:og|twitter):[^"]+)"/g)].map(([, key]) => key);
			assert.ok(social.indexOf('og:image') < 20 && social.indexOf('twitter:card') < 20, file);
			const graph = jsonLd(html)['@graph'];
			const organization = graph.find(node => node['@type'] === 'Organization');
			assert.equal(organization.name, 'Forward Email', file);
			assert.ok(organization.sameAs.includes('https://github.com/forwardemail'), file);
			assert.ok(graph.some(node => node['@type'] === 'WebSite'), file);
		}
	});

	it('loads nothing from other sites', () => {
		for (const file of pages) {
			const html = read(file);
			for (const [, url] of html.matchAll(/<(?:img|script|source|video|audio|iframe)\b[^>]*\ssrcs?(?:et)?="([^"]+)"/g)) {
				assert.ok(!/^(?:https?:)?\/\//.test(url), `${file}: ${url}`);
			}

			for (const [, url] of html.matchAll(/<link rel="(?:stylesheet|icon|apple-touch-icon|manifest|preload)"[^>]*href="([^"]+)"/g)) {
				assert.ok(url.startsWith('/'), `${file}: ${url}`);
			}

			const csp = attribute(html, /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
			assert.match(csp, /img-src 'self';/, file);
		}
	});

	it('serves security.txt with a contact and a future expiry', () => {
		const text = read('.well-known/security.txt');
		assert.match(text, /^Contact: ht{2}ps:\/{2}github\.com(?:\/spamscan{2}er){2}\/security\/advisories\/new$/m);
		const expires = Date.parse(/^Expires: (.+)$/m.exec(text)[1]);
		assert.ok(expires > Date.now());
		assert.match(text, new RegExp(`^Canonical: ${SITE}/.well-known/security.txt$`, 'm'));
	});

	it('has a Markdown copy of the home page, linked from it', () => {
		const html = read('index.html');
		assert.match(html, /<link rel="alternate" type="text\/markdown" href="https:\/\/spamscanner\.net\/index\.md" title="Markdown">/);
		const markdown = read('index.md');
		assert.match(markdown, /^# Spam Scanner\n\n> /);
		assert.ok(markdown.includes('npm install --global spamscanner'));
		assert.doesNotMatch(markdown, /<h1|<img/);
		assert.ok(nodes(html, 'SoftwareApplication')[0].sameAs.includes('https://github.com/spamscanner/spamscanner'));
	});

	it('builds the about page with contact, license and privacy sections', () => {
		const html = read('about/index.html');
		assert.equal(nodes(html, 'AboutPage').length, 1);
		for (const id of ['contact', 'license-terms', 'privacy']) {
			assert.match(html, new RegExp(`<h2 id="${id}">`), id);
		}

		assert.ok(html.includes('https://github.com/spamscanner/spamscanner/security/advisories/new'));
		const [crumbs] = nodes(html, 'BreadcrumbList');
		assert.deepEqual(crumbs.itemListElement.map(item => item.item), [`${SITE}/`, `${SITE}/about/`]);
		// Every page links to it from the footer.
		assert.match(read('docs/cli/index.html'), /<a href="\/about\/#privacy">Privacy<\/a>/);
		assert.match(read('de/index.html'), /<a href="\/de\/about\/">/);
	});

	it('builds the glossary with an anchor and a definition for every term', () => {
		const html = read('glossary/index.html');
		const [set] = nodes(html, 'DefinedTermSet');
		assert.ok(set.hasDefinedTerm.length >= 17);
		for (const term of set.hasDefinedTerm) {
			const id = new URL(term.url).hash.slice(1);
			assert.match(html, new RegExp(`<dt id="${id}"><a href="/[^"]+">[^<]+</a></dt><dd>[^<]+</dd>`), term.name);
			assert.ok(term.description.length > 20, term.name);
		}

		assert.ok(set.hasDefinedTerm.some(term => term.name === 'DKIM'));
		const german = nodes(read('de/glossary/index.html'), 'DefinedTermSet')[0];
		assert.equal(german.inLanguage, 'de');
		assert.ok(german.hasDefinedTerm.some(term => term.name === 'Doppelgänger-Domain'));
	});

	it('builds the self-hosted guide as an article, in every language', () => {
		const html = read('self-hosted-spam-filter/index.html');
		const [article] = nodes(html, 'TechArticle');
		assert.equal(article.headline, 'Self-hosted spam filter');
		assert.ok(html.includes('npm install --global spamscanner'));
		assert.match(html, /<th scope="col">/);
		assert.match(read('index.html'), /<a href="\/self-hosted-spam-filter\/">/);
		for (const code of ['de', 'ja', 'ar']) {
			const translated = read(`${code}/self-hosted-spam-filter/index.html`);
			assert.match(translated, new RegExp(`<html lang="${code}"`), code);
			assert.doesNotMatch(translated, /<meta name="robots" content="noindex">/, code);
		}
	});

	it('keeps titles short enough for search results where the site name is added', () => {
		for (const file of ['index.html', 'docs/getting-started/index.html', 'about/index.html', 'glossary/index.html', 'phishing-detection/index.html']) {
			const title = attribute(read(file), /<title>([^<]+)<\/title>/);
			assert.ok(title.length <= 60, `${file}: ${title}`);
		}
	});
});
