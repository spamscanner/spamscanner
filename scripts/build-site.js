#!/usr/bin/env node
// Builds spamscanner.net into _site/: a hand-written landing page, one page
// per document in docs/, guides from site/pages/, and the files search engines
// and agents read (sitemap.xml, robots.txt, llms.txt, llms-full.txt, a
// Markdown copy of every page), in every language in i18n/locales.json.
// English is at the root and every other language under /<code>/.
// Plain HTML, one stylesheet (site/style.css) and one small script
// (site/site.js); no framework. The structure follows attestium.com's
// generator and the translations privacyratings.com's.
//
//   node scripts/build-site.js [--out _site]

import {execFileSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';
import {Marked} from 'marked';
import {PROVIDERS} from '../src/llm.js';
import {RECOMMENDED_MODELS} from '../src/models.js';
import {segmentWords} from '../src/tokenizer.js';
import {
	DEFAULT, DIR as I18N_DIR, LOCALES, byCode, has, isDefault, locale, markdownHash, prefix, setLocale, t, th, translatedMarkdown, usedStrings,
} from './site-i18n.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const siteDir = path.join(root, 'site');
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const BACKSLASH = String.fromCodePoint(92);

const SITE = {
	name: 'Spam Scanner',
	url: 'https://spamscanner.net',
	repo: 'https://github.com/spamscanner/spamscanner',
	branch: 'master',
	description: 'A spam filter for Node.js, the command line and mail servers. Catches spam, phishing, scams and malware in any language, explains every decision, and can ask a local or hosted language model about close calls.',
	keywords: 'spam filter, anti-spam, email spam filter, phishing detection, Postfix spam filter, milter, SpamAssassin alternative, spamd, self-hosted spam filter, AI spam filter, LLM spam detection, Ollama, multilingual spam filter, Node.js spam filter',
	themeLight: '#f7f7fa',
	themeDark: '#14121c',
	imageAlt: 'Spam Scanner: a spam filter that reads every language and explains every decision',
	share: 'Spam Scanner: a spam filter for Node.js and mail servers that reads every language and explains every decision',
	video: '/media/spam-scanner',
};

const PUBLISHER = {
	'@type': 'Organization',
	'@id': 'https://forwardemail.net/#organization',
	name: 'Forward Email',
	url: 'https://forwardemail.net',
	logo: 'https://forwardemail.net/img/logo-square.svg',
	sameAs: ['https://github.com/forwardemail'],
};

// Guides in site/pages/, in this order; faq.md is the FAQ page.
const GUIDES = ['postfix-spam-filter', 'spamassassin-alternative', 'ai-spam-filter', 'multilingual-spam-filter', 'phishing-detection', 'nodejs-spam-filter'];

const NAV = [
	{group: 'Start', pages: [['docs/README.md', 'Overview'], ['docs/getting-started.md'], ['docs/cli.md']]},
	{group: 'Mail servers', pages: [['docs/postfix.md'], ['docs/mail-servers.md'], ['docs/http-api.md']]},
	{group: 'How it works', pages: [['docs/how-it-works.md'], ['docs/scoring.md'], ['docs/languages.md'], ['docs/llm.md'], ['docs/training.md']]},
	{group: 'Reference', pages: [['docs/api.md', 'API reference'], ['docs/forward-email.md'], ['docs/security.md']]},
];

// Glossary: the first use of each term on a page gets a tooltip.
// [pattern, definition, regular expression flags]
const GLOSSARY = [
	['ham', 'Wanted mail: the opposite of spam.'],
	['milter', 'Mail filter: a protocol from Sendmail, also used by Postfix, that lets a separate program inspect each message during the SMTP session.', 'i'],
	['SPF', 'Sender Policy Framework: a DNS record listing the servers allowed to send mail for a domain.'],
	['DKIM', 'DomainKeys Identified Mail: a signature over a message, checked with a public key published in the sender\'s DNS.'],
	['DMARC', 'A DNS policy telling receivers what to do when mail claiming a domain fails SPF and DKIM alignment.'],
	['ARC', 'Authenticated Received Chain: signatures that carry authentication results across forwarding servers.'],
	['DNSBL', 'DNS blocklist: a list of IP addresses (or domains, for a URIBL) known for spam, queried over DNS.'],
	['GTUBE', 'Generic Test for Unsolicited Bulk Email: a fixed string every spam filter treats as spam, for testing.'],
	['ClamAV', 'An open-source antivirus engine. Its daemon, clamd, scans files sent over a socket.'],
	['spamd', 'SpamAssassin\'s daemon. Its protocol is spoken by spamc, Exim, Haraka and other SpamAssassin clients.'],
	['Ollama', 'A program that downloads and runs open language models on your own machine, with an HTTP API.'],
	['punycode', 'The ASCII form of an internationalized domain name, starting with xn--.', 'i'],
	['MTA', 'Mail transfer agent: the server software that sends and receives email, such as Postfix or Exim.'],
];

const LANGS = {
	js: 'JavaScript', javascript: 'JavaScript', ts: 'TypeScript', json: 'JSON', sh: 'Shell', bash: 'Shell', shell: 'Shell', console: 'Shell', python: 'Python', py: 'Python', yaml: 'YAML', yml: 'YAML', ini: 'INI', text: 'Text', txt: 'Text',
};

// ---------------------------------------------------------------------------
// Helpers

function esc(value) {
	return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

// JSON inside a <script> element: "<", U+2028 and U+2029 are written as
// Unicode escapes, so no value can end the element or open a comment.
const SCRIPT_UNSAFE = new RegExp(`[${['<', 0x20_28, 0x20_29].map(c => (typeof c === 'number' ? String.fromCodePoint(c) : c)).join('')}]`, 'g');
function jsonForScript(value) {
	return JSON.stringify(value).replaceAll(SCRIPT_UNSAFE, char => `${BACKSLASH}u${char.codePointAt(0).toString(16).padStart(4, '0')}`);
}

// The only inline script, run before the first paint. It applies the saved
// theme, and on a first visit to an English page sends visitors whose browser
// prefers another language to that language's version of the page (as
// privacyratings.com does). Choosing a language in the menu is remembered.
const HEAD_SCRIPT = [
	'try{var t=localStorage.getItem(\'theme\');if(t===\'light\'||t===\'dark\')document.documentElement.dataset.theme=t;',
	'if(document.documentElement.lang===\'en\'&&!localStorage.getItem(\'lang\')){var a={};',
	'document.querySelectorAll(\'link[rel=alternate][hreflang]\').forEach(function(l){a[l.hreflang]=l.getAttribute(\'href\')});',
	'var n=navigator.languages||[navigator.language];for(var i=0;i<n.length;i++){var c=String(n[i]).toLowerCase(),b=c.split(\'-\')[0];',
	'if(b===\'en\')break;if(b===\'zh\'&&/^zh-(tw|hk|mo|hant)/.test(c))break;if(b===\'nn\'||b===\'no\')b=\'nb\';',
	'if(a[b]){location.replace(a[b]+location.hash);break}}}}catch(e){}',
].join('');

// Content-Security-Policy: scripts from this site and the head script (by
// hash). Inline style attributes stay allowed (table alignment).
function contentSecurityPolicy() {
	const digest = crypto.createHash('sha256').update(HEAD_SCRIPT).digest('base64');
	return [
		'default-src \'none\'',
		`script-src 'self' 'sha256-${digest}'`,
		'style-src \'self\' \'unsafe-inline\'',
		'img-src \'self\' https://forwardemail.net',
		'media-src \'self\'',
		// Lighthouse and agents fetch /robots.txt and /llms.txt from the page.
		'connect-src \'self\'',
		'manifest-src \'self\'',
		'base-uri \'none\'',
		'form-action \'none\'',
		'upgrade-insecure-requests',
	].join('; ');
}

function stripTags(html) {
	return html.replaceAll(/<[^>]*>/g, '')
		.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&quot;', '"').replaceAll('&#39;', '\'').replaceAll('&amp;', '&');
}

// GitHub's heading id algorithm (github-slugger), so anchors match GitHub's.
function slugify(text) {
	return text.toLowerCase().trim().replaceAll(/[^\p{L}\p{M}\p{N}\p{Pc}\- ]/gu, '').replaceAll(' ', '-');
}

function createSlugger() {
	const occurrences = new Map();
	return text => {
		const original = slugify(text);
		let slug = original;
		while (occurrences.has(slug)) {
			occurrences.set(original, occurrences.get(original) + 1);
			slug = `${original}-${occurrences.get(original)}`;
		}

		occurrences.set(slug, 0);
		return slug;
	};
}

function hash(content) {
	return crypto.createHash('sha256').update(content).digest('hex').slice(0, 10);
}

function plain(markdown) {
	return markdown.replaceAll(/`([^`]*)`/g, '$1').replaceAll(/\[([^\]]*)]\([^)]*\)/g, '$1').replaceAll(/[*_]/g, '').replaceAll(/\s+/g, ' ').trim();
}

function truncate(text, max) {
	if (text.length <= max) {
		return text;
	}

	const cut = text.slice(0, max);
	const space = cut.lastIndexOf(' ');
	return `${(space > max / 2 ? cut.slice(0, space) : cut).replace(/[,;:.、，]$/, '')}…`;
}

// A locale-aware link to a page of the site.
const href = url => `${prefix()}${url}`;

// ---------------------------------------------------------------------------
// Syntax highlighting: comments, strings, keywords and numbers. Nothing more.

const KEYWORDS = {
	js: 'async|await|break|case|catch|class|const|continue|default|delete|else|export|extends|false|finally|for|from|function|if|import|in|instanceof|let|new|null|of|return|static|switch|this|throw|true|try|typeof|undefined|var|while',
	python: 'and|as|assert|async|await|break|class|continue|def|elif|else|except|False|finally|for|from|if|import|in|is|lambda|None|not|or|pass|raise|return|True|try|while|with|yield',
	json: 'true|false|null',
	sh: 'if|then|else|fi|for|do|done|case|esac|export|sudo|exec',
	yaml: 'true|false|null',
	ini: 'yes|no|true|false',
};

const COMMENTS = {
	js: String.raw`\/\/[^\n]*|\/\*[\s\S]*?\*\/`, python: String.raw`#[^\n]*`, json: '(?!)', sh: String.raw`(?<=^|\s)#[^\n]*`, yaml: String.raw`(?<=^|\s)#[^\n]*`, ini: String.raw`(?<=^|\s)[#;][^\n]*`,
};

const LEXERS = {};
for (const [lang, words] of Object.entries(KEYWORDS)) {
	const string = lang === 'js'
		? String.raw`'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|\x60(?:\\.|[^\x60\\])*\x60`
		: String.raw`'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"`;
	const key = lang === 'yaml' || lang === 'ini' ? String.raw`|(?<p>^[ \t-]*[\w.-]+(?=\s*[:=]))` : '';
	LEXERS[lang] = new RegExp(String.raw`(?<c>${COMMENTS[lang]})|(?<s>${string})|(?<k>\b(?:${words})\b)|(?<n>\b\d[\d_.]*\b)${key}`, 'gm');
}

Object.assign(LEXERS, {
	javascript: LEXERS.js, ts: LEXERS.js, py: LEXERS.python, bash: LEXERS.sh, shell: LEXERS.sh, yml: LEXERS.yaml,
});

function highlight(code, lang) {
	const lexer = LEXERS[lang];
	if (!lexer) {
		return esc(code);
	}

	let out = '';
	let last = 0;
	for (const match of code.matchAll(lexer)) {
		if (match[0] === '') {
			continue;
		}

		const kind = Object.keys(match.groups).find(name => match.groups[name] !== undefined);
		out += esc(code.slice(last, match.index)) + `<span class="t-${kind}">${esc(match[0])}</span>`;
		last = match.index + match[0].length;
	}

	return out + esc(code.slice(last));
}

function codeBlock(code, lang, label) {
	const name = label || LANGS[lang] || (lang ? lang.toUpperCase() : 'Text');
	return `<div class="code" dir="ltr"><div class="code-bar"><span>${esc(name)}</span><button class="copy" type="button" data-copied="${esc(t('Copied'))}">${th('Copy')}</button></div>`
		+ `<pre tabindex="0"><code${lang ? ` class="language-${esc(lang)}"` : ''}>${highlight(code.replace(/\n$/, ''), lang)}</code></pre></div>\n`;
}

// ---------------------------------------------------------------------------
// Pages and links

function urlFor(source) {
	if (source === 'README.md') {
		return '/';
	}

	return `/${source.replace(/(^|\/)README\.md$/, '$1').replace(/\.md$/, '/')}`;
}

// Guides live in site/pages/ but are published at the root.
function sourceUrl(source) {
	return source.startsWith('site/pages/') ? `/${path.posix.basename(source, '.md')}/` : urlFor(source);
}

function rewriteLink(link, source, pages) {
	if (!link || link.startsWith('#') || /^[a-z][a-z\d+.-]*:/i.test(link)) {
		return link;
	}

	if (link.startsWith('/')) {
		return href(link);
	}

	const [target, anchor] = link.split('#');
	const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(source), target)).replace(/^\.\//, '');
	const suffix = anchor === undefined ? '' : `#${anchor}`;
	if (pages.has(resolved)) {
		return href(sourceUrl(resolved)) + suffix;
	}

	const full = path.join(root, resolved);
	const kind = fs.existsSync(full) && fs.statSync(full).isDirectory() ? 'tree' : 'blob';
	return `${SITE.repo}/${kind}/${SITE.branch}/${resolved.replace(/\/$/, '')}${suffix}`;
}

// ---------------------------------------------------------------------------
// Markdown

// The heading ids and code blocks of an English document, in order. A
// translation keeps the English ids, so links to its sections work in every
// language, and the English code, so commands are never changed by accident.
function structureOf(markdown) {
	const slug = createSlugger();
	const ids = [];
	const codes = [];
	const marked = new Marked({gfm: true});
	marked.use({
		walkTokens(token) {
			if (token.type === 'heading') {
				ids.push(slug(stripTags(marked.parseInline(token.text))));
			} else if (token.type === 'code') {
				codes.push(token.text);
			}
		},
	});
	marked.parse(markdown);
	return {ids, codes};
}

function renderMarkdown(markdown, source, pages, english = null) {
	const slug = createSlugger();
	const toc = [];
	let headings = 0;
	let codes = 0;
	const structure = english ? structureOf(english) : null;
	const own = english ? structureOf(markdown) : null;
	const sameHeadings = structure && own.ids.length === structure.ids.length;
	const sameCode = structure && own.codes.length === structure.codes.length;
	const marked = new Marked({gfm: true});
	marked.use({
		renderer: {
			heading({tokens, depth}) {
				const inner = this.parser.parseInline(tokens);
				const translatedId = slug(stripTags(inner));
				const id = sameHeadings ? structure.ids[headings] : translatedId;
				headings++;
				if (depth === 2 || depth === 3) {
					toc.push({id, depth, html: inner.replaceAll(/<\/?a[^>]*>/g, '')});
				}

				return `<h${depth} id="${id}">${inner}<a class="h-anchor" href="#${id}" aria-label="${esc(t('Link to this section'))}">#</a></h${depth}>\n`;
			},
			link({href: link, title, tokens}) {
				const url = rewriteLink(link, source, pages);
				const external = /^https?:/.test(url) && !url.startsWith(SITE.url);
				return `<a href="${esc(url)}"${title ? ` title="${esc(title)}"` : ''}${external ? ' rel="noopener"' : ''}>${this.parser.parseInline(tokens)}</a>`;
			},
			image({href: link, text}) {
				return `<img src="${esc(rewriteLink(link, source, pages))}" alt="${esc(text)}" loading="lazy">`;
			},
			code({text, lang}) {
				const code = sameCode ? structure.codes[codes] : text;
				codes++;
				return codeBlock(code, (lang || '').split(/\s/)[0].toLowerCase());
			},
			table(token) {
				const cell = (c, tag) => `<${tag}${c.align ? ` style="text-align:${c.align}"` : ''}>${this.parser.parseInline(c.tokens)}</${tag}>`;
				const head = token.header.map(c => cell(c, 'th')).join('');
				const rows = token.rows.map(row => `<tr>${row.map(c => cell(c, 'td')).join('')}</tr>`).join('\n');
				return `<div class="table-wrap" tabindex="0"><table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>\n`;
			},
		},
	});
	return {html: marked.parse(markdown), toc};
}

// Wrap the first use of each glossary term in a tooltip, outside code, links,
// headings, tables and buttons.
function addGlossary(html, idPrefix) {
	const skip = new Set(['a', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'button', 'script', 'style', 'svg', 'th', 'td']);
	const remaining = new Map(GLOSSARY.map(([term, text, flags]) => [term, {text: t(text), pattern: new RegExp(String.raw`(?<![\p{L}\p{N}_-])${term}(?![\p{L}\p{N}_-])`, `u${flags || ''}`)}]));
	let depth = 0;
	let count = 0;
	return html.split(/(<[^>]+>)/).map(part => {
		if (part.startsWith('<')) {
			const match = /^<(\/?)([a-z\d]+)/i.exec(part);
			if (match && skip.has(match[2].toLowerCase())) {
				depth += match[1] ? -1 : 1;
			}

			return part;
		}

		if (depth > 0 || remaining.size === 0 || part.trim() === '') {
			return part;
		}

		const found = [];
		for (const [term, {text: definition, pattern}] of remaining) {
			const m = pattern.exec(part);
			if (!m || found.some(f => m.index < f.end && m.index + m[0].length > f.start)) {
				continue;
			}

			found.push({
				start: m.index, end: m.index + m[0].length, definition, word: m[0],
			});
			remaining.delete(term);
		}

		let text = part;
		for (const f of found.sort((a, b) => b.start - a.start)) {
			const id = `${idPrefix}-${++count}`;
			text = `${text.slice(0, f.start)}<span class="term" tabindex="0" aria-describedby="${id}">${f.word}<span class="tip" role="tooltip" id="${id}">${esc(f.definition)}</span></span>${text.slice(f.end)}`;
		}

		return text;
	}).join('');
}

// ---------------------------------------------------------------------------
// Templates

function svgInline(file, className) {
	return fs.readFileSync(path.join(siteDir, 'brand', file), 'utf8')
		.replace(/<title[^>]*>[^<]*<\/title>/, '')
		.replace(' role="img" aria-labelledby="t"', '')
		.replace('<svg ', `<svg class="${className}" aria-hidden="true" focusable="false" `)
		.replaceAll(/\n\s*/g, '')
		.trim();
}

const STROKE = 'fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"';
const ICONS = {
	theme: '<svg class="i-system" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 3.5a6.5 6.5 0 0 1 0 13z" fill="currentColor"/></svg>'
		+ '<svg class="i-light" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="3.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 1.5v2.5M10 16v2.5M1.5 10H4M16 10h2.5M4 4l1.8 1.8M14.2 14.2 16 16M4 16l1.8-1.8M14.2 5.8 16 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>'
		+ '<svg class="i-dark" viewBox="0 0 20 20" aria-hidden="true"><path d="M16.5 12.2A7 7 0 0 1 7.8 3.5a7 7 0 1 0 8.7 8.7z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
	menu: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 6h14M3 10h14M3 14h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
	github: '<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>',
	share: `<svg viewBox="0 0 24 24" aria-hidden="true"><path ${STROKE} d="M4 12v7a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-7M16 6l-4-4-4 4M12 2v13"/></svg>`,
	play: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle ${STROKE} cx="12" cy="12" r="10"/><path ${STROKE} d="m10 8.5 5.5 3.5-5.5 3.5z"/></svg>`,
	link: `<svg viewBox="0 0 24 24" aria-hidden="true"><path ${STROKE} d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/></svg>`,
	language: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle ${STROKE} cx="12" cy="12" r="9"/><path ${STROKE} d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>`,
	brain: `<svg viewBox="0 0 24 24" aria-hidden="true"><path ${STROKE} d="M9 4a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 6 1V5a3 3 0 0 0-3-1zM15 4a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-6 1"/></svg>`,
	globe: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle ${STROKE} cx="12" cy="12" r="9"/><path ${STROKE} d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>`,
	hook: `<svg viewBox="0 0 24 24" aria-hidden="true"><path ${STROKE} d="M8 3v6a4 4 0 0 0 8 0V7M5 21h14M12 13v8"/></svg>`,
	paperclip: `<svg viewBox="0 0 24 24" aria-hidden="true"><path ${STROKE} d="m21 11-8.5 8.5a5 5 0 0 1-7-7L14 4a3.5 3.5 0 0 1 5 5l-8.5 8.5a2 2 0 0 1-3-3L15 7"/></svg>`,
	key: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle ${STROKE} cx="8" cy="15" r="4"/><path ${STROKE} d="m11 12 9-9M17 6l3 3M14 9l2 2"/></svg>`,
	spark: `<svg viewBox="0 0 24 24" aria-hidden="true"><path ${STROKE} d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8z"/></svg>`,
};

function brandLink() {
	return `<a class="brand" href="${href('/')}">${svgInline('mark.svg', 'mark')}<span>${SITE.name}</span></a>`;
}

// Share popover for the current page: plain links to each network's own share
// page; no scripts, widgets or trackers from those sites are loaded.
function shareBox(url, text) {
	const u = encodeURIComponent(url);
	const tx = encodeURIComponent(text);
	const both = encodeURIComponent(`${text} ${url}`);
	const targets = [
		[t('Messages'), `sms:?&body=${both}`],
		[t('Email'), `mailto:?subject=${tx}&body=${both}`],
		['WhatsApp', `https://wa.me/?text=${both}`],
		['Telegram', `https://t.me/share/url?url=${u}&text=${tx}`],
		['Mastodon', `https://mastodon.social/share?text=${both}`],
		['Bluesky', `https://bsky.app/intent/compose?text=${both}`],
		['X', `https://x.com/intent/post?text=${tx}&url=${u}`],
		['Reddit', `https://www.reddit.com/submit?url=${u}&title=${tx}`],
		['Hacker News', `https://news.ycombinator.com/submitlink?u=${u}&t=${tx}`],
		['LinkedIn', `https://www.linkedin.com/sharing/share-offsite/?url=${u}`],
		['Facebook', `https://www.facebook.com/sharer/sharer.php?u=${u}`],
		['VK', `https://vk.com/share.php?url=${u}&title=${tx}`],
		['LINE', `https://social-plugins.line.me/lineit/share?url=${u}`],
		['Weibo', `https://service.weibo.com/share/share.php?url=${u}&title=${tx}`],
	];
	return `<div id="share" class="share-pop" popover role="dialog" aria-labelledby="share-h" data-share-pop data-url="${esc(url)}" data-text="${esc(text)}" data-copied="${esc(t('Link copied.'))}" data-no-app="${esc(t('No app opened, so the text and link were copied.'))}" data-bad-server="${esc(t('Enter a server name such as mastodon.social.'))}">
<div class="pop-head"><h2 id="share-h">${th('Share')}</h2><button class="icon-button" type="button" popovertarget="share" popovertargetaction="hide" aria-label="${esc(t('Close'))}">✕</button></div>
<p class="share-title">${esc(text)}</p>
<button class="button share-native" type="button" data-share-native hidden>${th('Share with an app on this device')}</button>
<div class="share-link"><label class="sr-only" for="share-url">${th('Link')}</label><input id="share-url" type="text" value="${esc(url)}" readonly data-share-url dir="ltr"><button class="button button-quiet" type="button" data-share-copy>${ICONS.link}${th('Copy link')}</button></div>
<ul class="share-grid">${targets.map(([name, link]) => `<li><a class="share-to" href="${esc(link)}"${/^(mailto|sms):/.test(link) ? '' : ' rel="nofollow noopener noreferrer" target="_blank"'}${name === 'Mastodon' ? ' data-mastodon' : ''}>${esc(name)}</a></li>`).join('')}</ul>
<form class="share-mastodon" data-mastodon-form hidden><label for="share-instance">${th('Your Mastodon server')}</label><div><input id="share-instance" type="text" inputmode="url" placeholder="mastodon.social" autocomplete="off" spellcheck="false" dir="ltr"><button class="button" type="submit">${th('Share')}</button></div></form>
<p class="muted small share-status" data-share-status role="status">${th('These are plain links. No share buttons, scripts or trackers from other sites are loaded.')}</p>
</div>`;
}

// The video, in a popover so it never loads or plays until someone asks for
// it. MP4 (H.264 and AAC) plays everywhere; WebM (VP9 and Opus) is offered for
// browsers without H.264. Captions are part of the picture.
function videoBox(video) {
	return `<div id="video" class="share-pop video-pop" popover role="dialog" aria-labelledby="video-h" data-video-pop>
<div class="pop-head"><h2 id="video-h">${th('Spam Scanner in {duration}', {duration: esc(video.duration)})}</h2><button class="icon-button" type="button" popovertarget="video" popovertargetaction="hide" aria-label="${esc(t('Close'))}">✕</button></div>
<video controls playsinline preload="none" width="1920" height="1080" data-poster="${SITE.video}.jpg" lang="en">
<source src="${SITE.video}.mp4" type='video/mp4; codecs="avc1.640028, mp4a.40.2"'>
<source src="${SITE.video}.webm" type='video/webm; codecs="vp9, opus"'>
<a href="${SITE.video}.mp4">${th('Download the video (MP4)')}</a>
</video>
<p class="muted small">${isDefault() ? '' : `${th('Narrated in English, with English captions.')} `}<a href="${SITE.video}.mp4" download>${th('Download the video (MP4, {size})', {size: esc(video.size)})}</a></p>
</div>`;
}

// The language menu: links to this page in every language.
function languageBox(page) {
	// The one 404 page, served for every missing address, links to each home page.
	const target = page.kind === 'error' ? '/' : page.path;
	const items = LOCALES.map(item => {
		const current = item.code === locale().code;
		return `<li><a href="${prefix(item.code)}${target}" hreflang="${item.hreflang}" lang="${item.hreflang}"${item.dir ? ` dir="${item.dir}"` : ''} data-lang="${item.code}"${current ? ' aria-current="true"' : ''}>${esc(item.name)}</a></li>`;
	}).join('');
	return `<div id="lang" class="share-pop lang-pop" popover role="dialog" aria-labelledby="lang-h">
<div class="pop-head"><h2 id="lang-h">${th('Language')}</h2><button class="icon-button" type="button" popovertarget="lang" popovertargetaction="hide" aria-label="${esc(t('Close'))}">✕</button></div>
<ul class="lang-list">${items}</ul>
<p class="muted small">${th('Translations follow the English documentation. Commands, code and output stay in English.')}</p>
</div>`;
}

// Structured data: the publisher and the site on every page, plus what the page is.
function structuredData(p, context) {
	const url = SITE.url + p.url;
	const image = `${SITE.url}/og.png`;
	const language = locale().hreflang;
	const website = {
		'@type': 'WebSite',
		'@id': `${SITE.url}/#website`,
		url: `${SITE.url}/`,
		name: SITE.name,
		description: SITE.description,
		inLanguage: LOCALES.map(item => item.hreflang),
		publisher: {'@id': PUBLISHER['@id']},
	};
	const graph = [PUBLISHER, website];
	const crumbs = p.crumbs
		? {
			'@type': 'BreadcrumbList',
			'@id': `${url}#breadcrumbs`,
			itemListElement: p.crumbs.map((crumb, index) => ({
				'@type': 'ListItem', position: index + 1, name: crumb.name, item: SITE.url + crumb.url,
			})),
		}
		: null;
	const article = type => ({
		'@type': type,
		'@id': `${url}#main`,
		url,
		name: p.title,
		headline: p.heading || p.title,
		description: p.description,
		inLanguage: language,
		isPartOf: {'@id': website['@id']},
		publisher: {'@id': PUBLISHER['@id']},
		author: {'@id': PUBLISHER['@id']},
		image,
		dateModified: p.lastmod,
		...(p.keywords ? {keywords: p.keywords} : {}),
		...(crumbs ? {breadcrumb: {'@id': crumbs['@id']}} : {}),
	});

	switch (p.kind) {
		case 'home': {
			graph.push({
				'@type': ['SoftwareApplication', 'SoftwareSourceCode'],
				'@id': `${SITE.url}/#software`,
				name: SITE.name,
				description: SITE.description,
				url: `${SITE.url}/`,
				image,
				applicationCategory: 'SecurityApplication',
				applicationSubCategory: 'Email spam filter',
				operatingSystem: 'Linux, macOS, Windows',
				runtimePlatform: 'Node.js 18 or later',
				programmingLanguage: 'JavaScript',
				codeRepository: SITE.repo,
				license: `${SITE.repo}/blob/${SITE.branch}/LICENSE`,
				softwareVersion: packageJson.version,
				downloadUrl: 'https://www.npmjs.com/package/spamscanner',
				isAccessibleForFree: true,
				offers: {'@type': 'Offer', price: '0', priceCurrency: 'USD'},
				publisher: {'@id': PUBLISHER['@id']},
				author: {'@id': PUBLISHER['@id']},
			}, {...article('WebPage'), about: {'@id': `${SITE.url}/#software`}});
			if (context.video) {
				graph.push({
					'@type': 'VideoObject',
					'@id': `${SITE.url}/#video`,
					name: `Spam Scanner in ${context.video.duration}`,
					description: context.video.description,
					thumbnailUrl: `${SITE.url}${SITE.video}.jpg`,
					contentUrl: `${SITE.url}${SITE.video}.mp4`,
					uploadDate: context.video.uploadDate,
					duration: context.video.iso,
					inLanguage: 'en',
					publisher: {'@id': PUBLISHER['@id']},
				});
			}

			break;
		}

		case 'doc':
		case 'guide': {
			graph.push(article('TechArticle'));
			break;
		}

		case 'faq': {
			graph.push({
				...article('FAQPage'),
				mainEntity: p.faq.map(item => ({
					'@type': 'Question', name: item.question, acceptedAnswer: {'@type': 'Answer', text: item.answer},
				})),
			});
			break;
		}

		default: {
			graph.push(article('WebPage'));
		}
	}

	if (crumbs) {
		graph.push(crumbs);
	}

	return jsonForScript({'@context': 'https://schema.org', '@graph': graph});
}

function head(p, context) {
	const url = SITE.url + p.url;
	const image = `${SITE.url}/og.png`;
	const current = locale();
	const meta = (name, content) => `<meta name="${name}" content="${esc(content)}">`;
	const property = (name, content) => `<meta property="${name}" content="${esc(content)}">`;
	// Every language of a page links to the others, so search engines show the right one.
	const alternates = p.alternates
		? `${p.alternates.map(code => `<link rel="alternate" hreflang="${byCode.get(code).hreflang}" href="${SITE.url}${prefix(code)}${p.path}">`).join('\n')}\n<link rel="alternate" hreflang="x-default" href="${SITE.url}${p.path}">`
		: '';
	return `<!doctype html>
<html lang="${current.hreflang}"${current.dir ? ` dir="${current.dir}"` : ''}>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${esc(contentSecurityPolicy())}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(p.title)}</title>
${meta('description', p.description)}
${p.keywords ? meta('keywords', p.keywords) : ''}
${p.noindex ? meta('robots', 'noindex') : ''}
<link rel="canonical" href="${url}">
${alternates}
${p.markdown ? `<link rel="alternate" type="text/markdown" href="${url}index.md" title="Markdown">` : ''}
${property('og:type', p.kind === 'home' ? 'website' : 'article')}
${property('og:site_name', SITE.name)}
${property('og:locale', current.og)}
${p.alternates ? p.alternates.filter(code => code !== current.code).map(code => property('og:locale:alternate', byCode.get(code).og)).join('\n') : ''}
${property('og:title', p.title)}
${property('og:description', p.description)}
${property('og:url', url)}
${property('og:image', image)}
${property('og:image:width', '1200')}
${property('og:image:height', '630')}
${property('og:image:alt', t(SITE.imageAlt))}
${p.kind === 'home' && context.video ? `${property('og:video', `${SITE.url}${SITE.video}.mp4`)}\n${property('og:video:type', 'video/mp4')}\n${property('og:video:width', '1920')}\n${property('og:video:height', '1080')}` : ''}
${meta('twitter:card', 'summary_large_image')}
${meta('twitter:title', p.title)}
${meta('twitter:description', p.description)}
${meta('twitter:image', image)}
${meta('twitter:image:alt', t(SITE.imageAlt))}
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="${SITE.themeLight}" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="${SITE.themeDark}" media="(prefers-color-scheme: dark)">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon-32.png" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<script>${HEAD_SCRIPT}</script>
<link rel="stylesheet" href="/style.css?v=${context.assets.css}">
<script src="/site.js?v=${context.assets.js}" defer></script>
<script type="application/ld+json">${structuredData(p, context)}</script>
</head>`.replaceAll(/\n{2,}/g, '\n');
}

function header(active) {
	const link = (url, label, key) => `<li><a href="${href(url)}"${active === key ? ' aria-current="page"' : ''}>${label}</a></li>`;
	return `<a class="skip" href="#main">${th('Skip to content')}</a>
<header class="site-header">
<div class="wrap header-row">
${brandLink()}
<nav class="site-nav" id="site-nav" aria-label="${esc(t('Main'))}">
<ul>
${link('/docs/getting-started/', th('Get started'), 'start')}
${link('/docs/', th('Docs'), 'docs')}
${link('/docs/postfix/', 'Postfix', 'postfix')}
${link('/docs/llm/', th('Language models'), 'llm')}
${link('/faq/', th('FAQ'), 'faq')}
<li><a href="${SITE.repo}" rel="noopener">${ICONS.github}<span>GitHub</span></a></li>
</ul>
</nav>
<div class="header-actions">
<button class="icon-button header-share" type="button" popovertarget="share" data-share aria-label="${esc(t('Share'))}" title="${esc(t('Share'))}">${ICONS.share}</button>
<button class="icon-button lang-toggle" type="button" popovertarget="lang" aria-label="${esc(t('Language: {name}', {name: locale().name}))}" title="${esc(t('Language'))}">${ICONS.language}<span class="lang-code">${locale().code.toUpperCase()}</span></button>
<button class="icon-button theme-toggle" type="button" aria-label="${esc(t('Theme'))}" title="${esc(t('Theme'))}" data-label="${esc(t('Theme'))}" data-labels="${esc(JSON.stringify({system: t('system'), light: t('light'), dark: t('dark')}))}">${ICONS.theme}</button>
<button class="icon-button menu-toggle" type="button" aria-expanded="false" aria-controls="site-nav" aria-label="${esc(t('Menu'))}">${ICONS.menu}</button>
</div>
</div>
</header>`;
}

function footer(guides) {
	const list = (id, title, links) => `<nav aria-labelledby="${id}"><h2 id="${id}">${title}</h2><ul>${links.map(([url, label]) => `<li><a href="${url}"${url.startsWith('http') ? ' rel="noopener"' : ''}>${label}</a></li>`).join('')}</ul></nav>`;
	return `<footer class="site-footer">
<div class="wrap footer-grid">
<div class="footer-brand">
${brandLink()}
<p>${th('A spam filter that reads every language and explains every decision.')} <a href="${SITE.repo}/blob/${SITE.branch}/LICENSE" rel="noopener">${th('License')}</a>. © Forward Email LLC.</p>
${isDefault() ? '' : `<p class="muted small">${th('This translation is provided for convenience. The English version is the reference.')}</p>`}
</div>
${list('f-docs', th('Documentation'), [[href('/docs/getting-started/'), th('Getting started')], [href('/docs/cli/'), th('Command line')], [href('/docs/how-it-works/'), th('How it works')], [href('/docs/api/'), th('API reference')], [href('/faq/'), th('FAQ')]])}
${list('f-guides', th('Guides'), guides.map(g => [href(g.url), esc(g.label)]))}
${list('f-project', th('Project'), [[SITE.repo, 'GitHub'], ['https://www.npmjs.com/package/spamscanner', 'npm'], [`${SITE.repo}/releases`, th('Releases')], [href('/docs/security/'), th('Security')], ['/llms.txt', 'llms.txt']])}
${list('f-related', th('Related'), [['https://forwardemail.net', 'Forward Email'], ['https://attestium.com/', 'Attestium'], ['https://terminalemail.com/', 'Terminal Email'], ['https://privacyratings.com/', 'Privacy Ratings']])}
</div>
</footer>`;
}

function render(p, context) {
	return `${head(p, context)}
<body class="page-${p.kind}">
${header(p.active)}
${p.body}
${footer(context.guides)}
${shareBox(SITE.url + p.url, p.share || (p.kind === 'home' ? t(SITE.share) : `${p.heading || p.title}: ${SITE.name}`))}
${languageBox(p)}
${p.kind === 'home' && context.video ? videoBox(context.video) : ''}
</body>
</html>
`;
}

const shareButton = label => `<button class="button button-quiet" type="button" popovertarget="share" data-share>${ICONS.share}${label}</button>`;

// ---------------------------------------------------------------------------
// Landing page

// Real output of `spamscanner scan` for the phishing example in docs/getting-started.md.
const TERMINAL = [
	['cmd', '$ spamscanner scan message.eml'],
	['verdict', 'SPAM', '  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en'],
	['test', '+6.3', 'BAYES_999', 'Classifier spam probability 99.9%'],
	['test', '+5.0', 'PHISHING_LOOKALIKE_DOMAIN', '"paypa1-secure.top" imitates paypal by swapping characters'],
	['test', '+3.0', 'DECEPTIVE_LINK', 'A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top'],
	['test', '+2.0', 'FROM_NAME_BRAND', 'Display name says "paypal" but the message is from paypa1-secure.top'],
	['cmd', '$ echo $?'],
	['dim', '1'],
];

function terminal() {
	const lines = TERMINAL.map(([kind, ...parts]) => {
		switch (kind) {
			case 'cmd': {
				return `<span class="cmd">${esc(parts[0])}</span>`;
			}

			case 'verdict': {
				return `<span class="v-spam">${parts[0]}</span>${esc(parts[1])}`;
			}

			case 'test': {
				return `<span class="pts">${parts[0].padStart(7)}</span>  <span class="name">${esc(parts[1].padEnd(28))}</span> <span class="dim">${esc(parts[2])}</span>`;
			}

			default: {
				return `<span class="dim">${esc(parts[0])}</span>`;
			}
		}
	});
	return `<figure class="terminal" dir="ltr" aria-label="${esc(t('A phishing message scanned from the command line'))}">
<div class="terminal-bar" aria-hidden="true"><span></span><span></span><span></span><b>spamscanner</b></div>
<pre tabindex="0">${lines.join('\n')}</pre>
</figure>`;
}

const CARDS = [
	['brain', 'A classifier for every script', 'Words, word pairs, links, senders, HTML and attachments, counted and combined the way SpamBayes does, with an honest "unsure" when the clues disagree.', '/docs/how-it-works/#the-classifier', 'How it decides'],
	['globe', 'Every language, carefully', 'Unicode word segmentation for Chinese, Japanese and Thai, disguises undone, and no penalty for a language the model saw little ham in.', '/docs/languages/', 'Languages'],
	['hook', 'Phishing', 'Lookalike domains with Cyrillic or swapped letters, links whose text shows another address, brands in display names, and Cloudflare\'s malware resolver.', '/docs/how-it-works/#phishing', 'Phishing checks'],
	['paperclip', 'Attachments', 'Executables found by their bytes, also renamed to .pdf; double extensions; programs in ZIP files; Office macros; active PDFs; ClamAV.', '/docs/how-it-works/#attachments', 'Attachment checks'],
	['key', 'Authentication', 'SPF, DKIM, DMARC and ARC, DNS blocklists, allow and deny lists, and a rule for mail that spoofs your own domain.', '/docs/how-it-works/#authentication', 'Authentication'],
	['spark', 'Language models', 'Close calls go to a model: Ollama on your own machine, or Claude, ChatGPT, Gemini and any OpenAI-compatible server.', '/docs/llm/', 'Language models'],
];

function cards() {
	return CARDS.map(([icon, title, text, url, more]) => `<li class="card"><span class="card-icon">${ICONS[icon]}</span><h3>${th(title)}</h3><p>${th(text)}</p><a href="${href(url)}">${th(more)}</a></li>`).join('\n');
}

const STEPS = [
	['Read', 'The message is parsed and its text normalized: styled letters, invisible characters and lookalike alphabets are undone.'],
	['Check', 'The classifier, link, attachment, authentication, blocklist and rule checks run at the same time, each with a timeout.'],
	['Score', 'Each test adds or removes points. At 5 a message is spam; at 15 a mail server should refuse it.'],
	['Ask', 'Close calls can go to a language model, which adds up to 6 points or removes up to 3.'],
];

// Real tokenizer output, computed at build time.
const ZWSP = String.fromCodePoint(0x20_0B);
function wordsDemo() {
	const samples = [
		['Disguised English', `Claim your fr${ZWSP}ee pr${String.fromCodePoint(0x4_56)}ze: V1agra ${String.fromCodePoint(0x1_D4_05, 0x1_D4_11, 0x1_D4_04, 0x1_D4_04)}`, 'en', 'A zero-width space, a Cyrillic і, a digit for a letter and mathematical bold letters'],
		['Chinese, no spaces', '恭喜您获得一百万元大奖', 'zh', 'Segmented with a dictionary'],
		['Thai, no spaces', 'ยินดีด้วยคุณได้รับรางวัลหนึ่งล้านบาท', 'th', 'Segmented with a dictionary'],
		['Russian', 'Поздравляем! Вы выиграли миллион', 'ru', 'Lowercased by Unicode rules'],
	];
	return samples.map(([label, text, language, note]) => {
		const {words} = segmentWords(text, {locale: language});
		const shown = text.replaceAll(ZWSP, String.fromCodePoint(0x24_23));
		return `<div class="word-sample"><span class="label">${th(label)}</span><p lang="${language}" dir="ltr">${esc(shown)}</p><ul class="chips" lang="${language}" dir="ltr" aria-label="${esc(t('Words counted'))}">${words.map(word => `<li>${esc(word)}</li>`).join('')}</ul><p class="note">${th(note)}</p></div>`;
	}).join('\n');
}

const INTEGRATIONS = [
	['postfix', 'Postfix', 'A milter checks mail during the SMTP session, so spam at the reject threshold is refused before it is accepted.', 'spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"\n\n# /etc/postfix/main.cf\nsmtpd_milters = inet:127.0.0.1:7831\nmilter_default_action = accept', 'sh', '/docs/postfix/', 'Postfix guide'],
	['spamd', 'Exim, Haraka, spamc', 'A SpamAssassin-compatible spamd server: stop spamd, start Spam Scanner on the same port, and SpamAssassin clients keep working.', 'spamscanner spamd --port 783 --auth\n\nspamc -c < message.eml     # prints 16.3/5.0 and exits 1', 'sh', '/docs/mail-servers/#a-drop-in-for-spamassassins-spamd', 'spamd guide'],
	['node', 'Node.js', 'The library, for smtp-server, Haraka plugins or any service that handles mail.', 'import SpamScanner from \'spamscanner\';\n\nconst scanner = new SpamScanner({authentication: true});\nconst result = await scanner.scan(stream, {session});\n\nif (result.action === \'reject\') {\n  // refuse with a 4xx or 5xx reply\n}', 'js', '/docs/api/', 'API reference'],
	['http', 'HTTP API', 'For any language and any server that can make an HTTP request.', 'spamscanner http --port 7832 --token "$TOKEN"\n\ncurl -s -X POST -H "Authorization: Bearer $TOKEN" \\\n  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5"', 'sh', '/docs/http-api/', 'HTTP API guide'],
];

function tabs() {
	const list = INTEGRATIONS.map(([id, label], index) => `<button role="tab" type="button" id="tab-${id}" aria-controls="panel-${id}" aria-selected="${index === 0}"${index === 0 ? '' : ' tabindex="-1"'}>${esc(label)}</button>`).join('');
	const panels = INTEGRATIONS.map(([id, , text, code, lang, url, more], index) => `<div role="tabpanel" id="panel-${id}" aria-labelledby="tab-${id}"${index === 0 ? '' : ' hidden'}>
${codeBlock(code, lang)}<p>${th(text)} <a href="${href(url)}">${th(more)}</a></p>
</div>`).join('\n');
	return `<div class="tabs"><div role="tablist" aria-label="${esc(t('Mail servers'))}">${list}</div>\n${panels}</div>`;
}

function providers() {
	return Object.entries(PROVIDERS).filter(([key]) => !['openai-compatible', 'huggingface-classifier', 'tei'].includes(key)).map(([, preset]) => `<li${preset.local ? ' class="local"' : ''}>${esc(preset.name)}</li>`).join('');
}

function modelsTable() {
	const rows = RECOMMENDED_MODELS.filter(model => ['qwen3.5:4b', 'gemma4:e2b', 'qwen3.5:0.8b', 'qwen3.5:9b', 'gpt-oss-safeguard:20b'].includes(model.ollama)).map(model => `<tr><td dir="ltr"><code>${esc(model.ollama)}</code></td><td class="hide-small" dir="ltr"><a href="https://huggingface.co/${esc(model.huggingface)}" rel="noopener">${esc(model.huggingface)}</a></td><td dir="ltr">${esc(model.license)}</td><td class="num">${esc(model.size)}</td></tr>`).join('');
	return `<div class="table-wrap" tabindex="0"><table class="data-table"><thead><tr><th>Ollama</th><th class="hide-small">Hugging Face</th><th>${th('License')}</th><th class="num">${th('Size')}</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function metricsTable(model) {
	const metrics = model?.metadata?.metrics;
	if (!metrics) {
		return '';
	}

	const language = locale().hreflang;
	const percent = new Intl.NumberFormat(language, {style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1});
	const count = new Intl.NumberFormat(language);
	const names = new Intl.DisplayNames([language], {type: 'language'});
	const rows = Object.entries(metrics.byLanguage).filter(([code]) => ['en', 'ru', 'it', 'de', 'es'].includes(code)).map(([code, m]) => `<tr><td>${esc(names.of(code))}</td><td class="num">${count.format(m.messages)}</td><td class="num">${percent.format(m.precision)}</td><td class="num">${percent.format(m.recall)}</td><td class="num">${percent.format(m.falsePositiveRate)}</td></tr>`).join('');
	return `<div class="table-wrap" tabindex="0"><table class="data-table"><thead><tr><th>${th('Held-out messages')}</th><th class="num">${th('Messages')}</th><th class="num">${th('Precision')}</th><th class="num">${th('Recall')}</th><th class="num">${th('False positives')}</th></tr></thead><tbody>${rows}<tr><td><strong>${th('All')}</strong></td><td class="num">${count.format(metrics.messages)}</td><td class="num">${percent.format(metrics.precision)}</td><td class="num">${percent.format(metrics.recall)}</td><td class="num">${percent.format(metrics.falsePositiveRate)}</td></tr></tbody></table></div>
<p class="note">${th('The classifier alone, on every tenth message of its public training data, held out. Unsure messages count as missed. German, Italian and Spanish come from synthetic datasets with noisy labels.')} <a href="${href('/docs/training/#the-bundled-model')}">${th('About the bundled model')}</a></p>`;
}

// The video on the home page: its poster, which opens the video.
function videoFeature(video) {
	if (!video) {
		return '';
	}

	return `<section class="section video-section" id="video-section" aria-labelledby="video-section-h">
<div class="wrap split">
<div class="section-head">
<h2 id="video-section-h">${th('See it in {duration}', {duration: esc(video.duration)})}</h2>
<p>${th('How a message is scored, how every language is read, when a language model is asked, and how it plugs into Postfix, Exim, Haraka and Node.js.')}</p>
${isDefault() ? '' : `<p class="muted small">${th('Narrated in English, with English captions.')}</p>`}
<p class="hero-links"><a class="button" href="${SITE.video}.mp4" data-video-open>${ICONS.play}${th('Watch the video')}</a>${shareButton(th('Share'))}</p>
</div>
<a class="video-poster" href="${SITE.video}.mp4" data-video-open aria-label="${esc(t('Watch the video ({duration})', {duration: video.duration}))}"><img src="${SITE.video}-cover.jpg" width="1280" height="720" alt="${esc(t('The video\'s title frame: the Spam Scanner logo.'))}" loading="lazy" decoding="async"><span class="play" aria-hidden="true"><svg viewBox="0 0 24 24"><path fill="currentColor" d="M7 4.5v15l12.5-7.5z"/></svg></span><span class="duration" aria-hidden="true">${esc(video.duration)}</span></a>
</div>
</section>`;
}

function landing(context) {
	const watch = context.video
		? `<a class="button button-quiet" href="${SITE.video}.mp4" data-video-open>${ICONS.play}${th('Watch the video ({duration})', {duration: esc(context.video.duration)})}</a>`
		: '';
	const body = `<main id="main">
<section class="hero">
<div class="wrap hero-grid">
<div class="hero-text">
<h1>${th('A spam filter that reads {highlight} and explains every decision.', {highlight: `<em>${th('every language')}</em>`})}</h1>
<p class="lede">${th('Spam Scanner catches spam, phishing, scams and malware for Node.js, the command line and mail servers such as Postfix, Exim and Haraka. Every result lists the tests that fired and why.')}</p>
<div class="install" id="install" dir="ltr">
<code><span class="prompt" aria-hidden="true">$ </span>npm install -g spamscanner</code>
<button class="copy" type="button" data-copy="npm install -g spamscanner" data-copied="${esc(t('Copied'))}">${th('Copy')}</button>
</div>
<p class="hero-links"><a class="button" href="${href('/docs/getting-started/')}">${th('Get started')}</a>${watch}${shareButton(th('Share'))}</p>
<ul class="facts"><li>Node.js 18+</li><li>${th('Milter, spamd, HTTP')}</li><li>Ollama, Claude, ChatGPT</li><li>${th('No telemetry')}</li></ul>
</div>
${terminal()}
</div>
</section>

<section class="section" id="how-it-works" aria-labelledby="how-h">
<div class="wrap">
<div class="section-head">
<h2 id="how-h">${th('How a message is judged')}</h2>
<p>${th('Every check adds or removes points, and the total decides. Thresholds and points can be changed, and nothing is a black box: the result names each test.')}</p>
</div>
<ol class="pipeline">
${STEPS.map(([title, text]) => `<li><h3>${th(title)}</h3><p>${th(text)}</p></li>`).join('\n')}
</ol>
<figure class="scale">
<div class="scale-bar" aria-hidden="true"><span></span><span></span><span></span></div>
<figcaption><ul class="scale-marks"><li><strong>${th('below 5')}</strong><span>${th('accept')}</span></li><li><strong>${th('5 to 15')}</strong><span>${th('tag as spam')}</span></li><li><strong>${th('15 and up')}</strong><span>${th('reject')}</span></li></ul></figcaption>
</figure>
</div>
</section>

${videoFeature(context.video)}

<section class="section" id="checks" aria-labelledby="checks-h">
<div class="wrap">
<div class="section-head">
<h2 id="checks-h">${th('What it checks')}</h2>
<p>${th('Words are one signal. Links, senders, attachments and authentication say as much, and none of them depend on the language of the message.')}</p>
</div>
<ul class="cards">
${cards()}
</ul>
<p class="more"><a href="${href('/docs/scoring/')}">${th('Every test and its points')}</a><a href="${href('/docs/how-it-works/')}">${th('How it works')}</a></p>
</div>
</section>

<section class="section" id="languages" aria-labelledby="languages-h">
<div class="wrap">
<div class="section-head">
<h2 id="languages-h">${th('Every language, without guessing')}</h2>
<p>${th('Words are found with the Unicode rules, so languages written without spaces work, and disguises are undone before counting. These are the words the classifier counts, computed when this page was built.')}</p>
<p>${th('A language the bundled model saw little ham in gets "unsure" instead of "spam", so ordinary mail in Arabic or Korean is never flagged for its script.')} <a href="${href('/docs/languages/')}">${th('Languages')}</a></p>
</div>
<div class="words">
${wordsDemo()}
</div>
</div>
</section>

<section class="section" id="mail-servers" aria-labelledby="servers-h">
<div class="wrap split">
<div class="section-head">
<h2 id="servers-h">${th('Plugs into your mail server')}</h2>
<p>${th('A milter for Postfix and Sendmail, a SpamAssassin-compatible spamd server for spamc, Exim and Haraka, a content filter, an HTTP API, a TCP server, and the library.')}</p>
<p>${th('All of them add {headers} headers, and remove any a sender forged.', {headers: '<code>X-Spam-Flag</code>, <code>X-Spam-Score</code>, <code>X-Spam-Status</code>'})}</p>
</div>
${tabs()}
</div>
</section>

<section class="section" id="language-models" aria-labelledby="llm-h">
<div class="wrap">
<div class="section-head">
<h2 id="llm-h">${th('A language model for the close calls')}</h2>
<p>${th('Clear spam and clear ham never reach it. When the score is close or the classifier is unsure, a model reads the message and answers spam, phishing, scam, malware or ham. Run one on your own machine, or use a hosted one, on any URL, port and authentication.')}</p>
<p>${th('Instructions hidden in a message for AI filters are scored as spam, and the model is told the message is data. The end-to-end tests check it against a real model through Ollama.')}</p>
</div>
<ul class="providers" aria-label="${esc(t('Preconfigured providers'))}">${providers()}</ul>
<div class="split">
<div>${codeBlock('ollama pull qwen3.5:4b\nspamscanner llm-test --llm ollama --llm-model qwen3.5:4b\nspamscanner milter --llm ollama --llm-model qwen3.5:4b', 'sh')}<p class="note">${th('Outlined: runs on your own machine. Personal data is removed before a message goes to a hosted provider.')}</p></div>
<div>${modelsTable()}<p class="note">${th('Recommended open models.')} <a href="${href('/docs/llm/#recommended-open-models')}">${th('All recommendations')}</a></p></div>
</div>
</div>
</section>

<section class="section" id="measured" aria-labelledby="measured-h">
<div class="wrap split">
<div class="section-head">
<h2 id="measured-h">${th('Measured, and trainable')}</h2>
<p>${th('The bundled model is trained on public datasets and tested on messages it did not see. A model trained on your own mail does better: train it from mbox files, Maildirs or datasets, measure it, and teach it from "report spam" buttons.')}</p>
<p><a href="${href('/docs/training/')}">${th('Training')}</a></p>
</div>
<div>${metricsTable(context.model)}</div>
</div>
</section>

<section class="section" id="forward-email" aria-labelledby="fe-h">
<div class="wrap">
<div class="section-head">
<h2 id="fe-h">${th('Built for Forward Email')}</h2>
<p>${th('Forward Email keeps no logs of message content, so it could not send mail to an outside filtering service. Spam Scanner runs on your own servers, sends nothing anywhere unless configured to, and explains every decision without a person reading the mail.')} <a href="${href('/docs/forward-email/')}">${th('Forward Email and upgrading')}</a></p>
</div>
<div class="credit">
<a class="credit-logo" href="https://forwardemail.net"><img src="https://forwardemail.net/img/logo-square.svg" width="44" height="44" alt="Forward Email"></a>
<p>${th('A project by {link}, the privacy-focused email service.', {link: '<a href="https://forwardemail.net">Forward Email</a>'})}</p>
</div>
</div>
</section>
</main>`;

	return {
		path: '/',
		kind: 'home',
		title: t('Spam Scanner: a spam filter for every language, with explained decisions'),
		description: t(SITE.description),
		keywords: t(SITE.keywords),
		sources: ['README.md', 'scripts/build-site.js', 'model/classifier.json'],
		body,
		markdown: null,
	};
}

// ---------------------------------------------------------------------------
// Docs pages

function sidebar(nav, current) {
	return nav.map(({group, pages}) => `<div class="side-group"><h2>${th(group)}</h2><ul>${pages.map(p => `<li><a href="${href(p.url)}"${p.source === current ? ' aria-current="page"' : ''}>${esc(p.label)}</a></li>`).join('')}</ul></div>`).join('\n');
}

function tocNav(toc) {
	return toc.length > 1
		? `<nav class="toc" aria-labelledby="toc-h"><h2 id="toc-h">${th('On this page')}</h2><ul>${toc.map(item => `<li class="toc-${item.depth}"><a href="#${item.id}">${item.html}</a></li>`).join('')}</ul></nav>`
		: '<div class="toc toc-empty"></div>';
}

// The note on a page whose translation is missing or out of date.
function untranslatedNote() {
	return `<p class="untranslated">${th('This page is not translated yet, so it is shown in English.')}</p>`;
}

function docPage(doc, nav, order, pages) {
	const index = order.indexOf(doc);
	const previous = order[index - 1];
	const next = order[index + 1];
	const {html, toc} = renderMarkdown(doc.body, doc.source, pages, doc.englishBody);
	const note = untranslatedNote();
	const pager = `<nav class="pager" aria-label="${esc(t('Previous and next page'))}">${previous ? `<a class="prev" href="${href(previous.url)}"><span>${th('Previous')}</span>${esc(previous.label)}</a>` : '<span></span>'}${next ? `<a class="next" href="${href(next.url)}"><span>${th('Next')}</span>${esc(next.label)}</a>` : ''}</nav>`;
	const active = {'/docs/getting-started/': 'start', '/docs/postfix/': 'postfix', '/docs/llm/': 'llm'}[doc.url] || 'docs';
	const body = `<div class="wrap docs">
<aside class="sidebar">
<button class="side-toggle" type="button" aria-expanded="false" aria-controls="side-nav"><span><span class="muted">${th('Docs')} /</span> ${esc(doc.label)}</span><svg viewBox="0 0 20 20" aria-hidden="true"><path d="m6 8 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
<nav id="side-nav" class="side-nav" aria-label="${esc(t('Documentation'))}">
${sidebar(nav, doc.source)}
</nav>
</aside>
<main id="main" class="doc"${doc.translated || isDefault() ? '' : ' lang="en" dir="ltr"'}>
${doc.translated || isDefault() ? '' : note}
<article class="prose">
<h1>${doc.titleHtml}</h1>
${addGlossary(html, 'g')}
</article>
<p class="edit"><a href="${SITE.repo}/blob/${SITE.branch}/${doc.file}" rel="noopener">${th('Edit this page on GitHub')}</a> · <a href="${href(doc.url)}index.md">Markdown</a> · ${shareButton(th('Share this page'))}</p>
${pager}
</main>
${tocNav(toc)}
</div>`;
	const docsLabel = t('Documentation');
	return {
		path: doc.url,
		kind: 'doc',
		active,
		translated: doc.translated,
		title: doc.title.includes(SITE.name) ? doc.title : `${doc.title}: ${SITE.name}`,
		heading: doc.title,
		description: doc.description,
		sources: [doc.file],
		crumbs: doc.url === '/docs/'
			? [{name: SITE.name, url: href('/')}, {name: docsLabel, url: href(doc.url)}]
			: [{name: SITE.name, url: href('/')}, {name: docsLabel, url: href('/docs/')}, {name: doc.label, url: href(doc.url)}],
		markdown: markdownCopy(doc.title, doc.body, {source: doc.source, pages, url: href(doc.url)}),
		group: 'Documentation',
		body,
	};
}

function parseDoc(markdown) {
	const titleMatch = /^# (.+)$/m.exec(markdown);
	const body = titleMatch ? markdown.slice(titleMatch.index + titleMatch[0].length) : markdown;
	const paragraph = body.split(/\n\s*\n/).map(s => s.trim()).find(s => s && !/^[#|`>\-*!<\d]/.test(s)) || t(SITE.description);
	return {titleMatch, body, paragraph};
}

function loadDoc(source, label) {
	const english = fs.readFileSync(path.join(root, source), 'utf8');
	const name = path.basename(source);
	const translation = translatedMarkdown('docs', name, english);
	const markdown = translation ?? english;
	const {titleMatch, body, paragraph} = parseDoc(markdown);
	const title = titleMatch ? plain(titleMatch[1]) : path.basename(source, '.md');
	const titleHtml = titleMatch ? new Marked().parseInline(titleMatch[1]) : esc(title);
	// Labels in the navigation: a set label (Overview, API reference) is a UI string; otherwise the page's own title.
	// t() is called either way, so the string is listed for translators.
	const translatedLabel = label ? t(label) : null;
	const navLabel = label ? (translation ? translatedLabel : label) : title;
	return {
		source,
		file: translation ? path.relative(root, path.join(I18N_DIR, locale().code, 'docs', name)) : source,
		url: urlFor(source),
		title,
		titleHtml,
		label: navLabel,
		description: truncate(plain(paragraph), 158),
		body,
		englishBody: translation ? parseDoc(english).body : null,
		translated: isDefault() || Boolean(translation),
	};
}

// A document as Markdown for agents: links made absolute, nothing else changed.
function markdownCopy(title, body, {source, pages, url}) {
	const absolute = link => {
		const target = rewriteLink(link, source, pages);
		if (target.startsWith('#')) {
			return `${SITE.url}${url}${target}`;
		}

		return target.startsWith('/') ? SITE.url + target : target;
	};

	const text = body.split(/(```[\s\S]*?```)/).map(part => (part.startsWith('```')
		? part
		: part.replaceAll(/(!?\[[^\]]*])\(([^)\s]+)((?:\s+"[^"]*")?)\)/g, (match, label, link, linkTitle) => `${label}(${absolute(link)}${linkTitle})`))).join('');
	return `# ${title}\n\n${text.trim()}\n`;
}

// ---------------------------------------------------------------------------
// Guides and FAQ

function frontMatter(text) {
	// Page metadata sits in an HTML comment at the top, which Markdown tools leave alone.
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

function withoutTitle(markdown) {
	const match = /^# (.+)$/m.exec(markdown);
	return match ? markdown.slice(match.index + match[0].length) : markdown;
}

function loadGuide(slug) {
	const source = `site/pages/${slug}.md`;
	const english = fs.readFileSync(path.join(root, source), 'utf8');
	const translation = translatedMarkdown('pages', `${slug}.md`, english);
	const {data, body: markdown} = frontMatter(translation ?? english);
	const titleMatch = /^# (.+)$/m.exec(markdown);
	return {
		slug,
		source,
		file: translation ? path.relative(root, path.join(I18N_DIR, locale().code, 'pages', `${slug}.md`)) : source,
		data,
		heading: titleMatch ? plain(titleMatch[1]) : data.title,
		body: titleMatch ? markdown.slice(titleMatch.index + titleMatch[0].length) : markdown,
		englishBody: translation ? withoutTitle(frontMatter(english).body) : null,
		translated: isDefault() || Boolean(translation),
	};
}

function guidePage(guide, pages, guides) {
	const {slug, source, data, heading, body} = guide;
	const url = `/${slug}/`;
	const {html, toc} = renderMarkdown(body, source, pages, guide.englishBody);
	const note = untranslatedNote();
	const faq = slug === 'faq'
		? body.split(/^## /m).slice(1).map(section => {
			const [question, ...rest] = section.split('\n');
			return {question: question.trim(), answer: stripTags(new Marked().parse(rest.join('\n').replaceAll(/```[\s\S]*?```/g, ''))).replaceAll(/\s+/g, ' ').trim()};
		})
		: null;
	const related = guides.filter(g => g.url !== url);
	const aside = `<aside class="related" aria-labelledby="related-h"><h2 id="related-h">${slug === 'faq' ? th('Guides') : th('More guides')}</h2><ul>${related.map(g => `<li><a href="${href(g.url)}">${esc(g.label)}</a><span>${esc(g.description)}</span></li>`).join('')}</ul></aside>`;
	const label = data.label || heading;
	const bodyHtml = `<div class="wrap guide">
<main id="main" class="doc"${guide.translated ? '' : ' lang="en" dir="ltr"'}>
${guide.translated ? '' : note}
<nav class="crumbs" aria-label="${esc(t('Breadcrumb'))}"><ol><li><a href="${href('/')}">${SITE.name}</a></li><li><span aria-current="page">${esc(label)}</span></li></ol></nav>
<article class="prose">
<h1>${esc(heading)}</h1>
${addGlossary(html, 'g')}
</article>
<p class="edit"><a href="${SITE.repo}/blob/${SITE.branch}/${guide.file}" rel="noopener">${th('Edit this page on GitHub')}</a> · <a href="${href(url)}index.md">Markdown</a> · ${shareButton(th('Share this page'))}</p>
${aside}
</main>
${tocNav(toc)}
</div>`;
	return {
		path: url,
		kind: slug === 'faq' ? 'faq' : 'guide',
		active: slug === 'faq' ? 'faq' : 'guide',
		translated: guide.translated,
		title: `${data.title || heading}: ${SITE.name}`,
		heading,
		label,
		description: data.description,
		keywords: data.keywords,
		sources: [guide.file],
		crumbs: [{name: SITE.name, url: href('/')}, {name: label, url: href(url)}],
		markdown: markdownCopy(heading, body, {source, pages, url: href(url)}),
		group: slug === 'faq' ? 'FAQ' : 'Guides',
		faq,
		body: bodyHtml,
	};
}

function notFound() {
	return {
		path: '/404.html',
		kind: 'error',
		noindex: true,
		title: `Page not found: ${SITE.name}`,
		description: 'Nothing is published at this address. The documentation and the guides are linked from the home page.',
		sources: [],
		markdown: null,
		body: `<main id="main" class="wrap not-found">
<p class="code-404">404</p>
<h1>Page not found</h1>
<p>Nothing is published at this address.</p>
<p class="hero-links"><a class="button" href="/">Home</a><a class="button button-quiet" href="/docs/">Documentation</a></p>
</main>`,
	};
}

// ---------------------------------------------------------------------------
// Files for search engines and agents

const lastModified = new Map();
function lastmod(sources, fallback) {
	const dates = sources.map(source => {
		if (!lastModified.has(source)) {
			let date = '';
			try {
				date = execFileSync('git', ['-C', root, 'log', '-1', '--format=%cI', '--', source], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim();
			} catch {}

			lastModified.set(source, date);
		}

		return lastModified.get(source);
	}).filter(Boolean).sort();
	return dates.length > 0 ? dates.at(-1) : fallback;
}

function robots() {
	return `# Everything on this site is public. Search engines, crawlers and AI agents are welcome;\n# /llms.txt lists the pages for language models.\nUser-agent: *\nAllow: /\n\nSitemap: ${SITE.url}/sitemap.xml\n`;
}

// One entry per page and language, with links to the page's other languages.
function sitemap(pages) {
	const entries = pages.filter(p => !p.noindex).map(p => {
		const links = (p.alternates || []).map(code => `<xhtml:link rel="alternate" hreflang="${byCode.get(code).hreflang}" href="${SITE.url}${prefix(code)}${p.path}"/>`).join('');
		return `<url><loc>${SITE.url}${p.url}</loc><lastmod>${p.lastmod}</lastmod>${links}</url>`;
	});
	return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n${entries.join('\n')}\n</urlset>\n`;
}

function llms(pages) {
	const link = p => `- [${p.heading || p.title}](${SITE.url}${p.url}index.md): ${p.description}`;
	const group = name => pages.filter(p => p.group === name && p.markdown).map(p => link(p)).join('\n');
	const languages = LOCALES.filter(item => item.code !== DEFAULT).map(item => `[${item.name}](${SITE.url}/${item.code}/)`).join(', ');
	return `# ${SITE.name}

> ${SITE.description}

Spam Scanner is an npm package (\`spamscanner\`) and command-line tool. It scores a raw email message with a classifier, phishing, attachment, authentication, blocklist and rule checks, and optionally a language model, and runs as a library, a Postfix or Sendmail milter, a Postfix content filter, a SpamAssassin-compatible spamd server, an HTTP API or a TCP server. Each link below is the Markdown source of a page.

## Documentation

${group('Documentation')}

## Guides

${group('Guides')}
${group('FAQ')}

## Optional

- [All documentation in one file](${SITE.url}/llms-full.txt): every page above, concatenated
- Translations: ${languages}; each page has a Markdown copy at the same address followed by index.md
- [Source code](${SITE.repo}): the library, command line, tests and training script
- [npm package](https://www.npmjs.com/package/spamscanner)
`;
}

function llmsFull(pages) {
	return pages.filter(p => p.markdown).map(p => `<!-- ${SITE.url}${p.url} -->\n\n${p.markdown}`).join('\n\n');
}

function manifest() {
	return `${JSON.stringify({
		name: SITE.name,
		short_name: SITE.name, // eslint-disable-line camelcase
		description: SITE.description,
		start_url: '/', // eslint-disable-line camelcase
		scope: '/',
		display: 'browser',
		background_color: SITE.themeLight, // eslint-disable-line camelcase
		theme_color: SITE.themeDark, // eslint-disable-line camelcase
		icons: [
			{src: '/icon-192.png', sizes: '192x192', type: 'image/png'},
			{src: '/icon-512.png', sizes: '512x512', type: 'image/png'},
			{src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml'},
		],
	}, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Build

function write(outDir, url, content) {
	const file = url.endsWith('/') ? path.join(outDir, url, 'index.html') : path.join(outDir, url);
	fs.mkdirSync(path.dirname(file), {recursive: true});
	fs.writeFileSync(file, content);
}

function copy(from, outDir, url) {
	const target = path.join(outDir, url);
	fs.mkdirSync(path.dirname(target), {recursive: true});
	fs.copyFileSync(from, target);
}

// The video's length and size, from site/media/spam-scanner.json, written when
// the video is made.
function videoInfo() {
	const file = path.join(siteDir, 'media', 'spam-scanner.json');
	if (!fs.existsSync(file) || !fs.existsSync(path.join(siteDir, 'media', 'spam-scanner.mp4'))) {
		return null;
	}

	const info = JSON.parse(fs.readFileSync(file, 'utf8'));
	const seconds = Math.round(info.seconds);
	const megabytes = fs.statSync(path.join(siteDir, 'media', 'spam-scanner.mp4')).size / 1024 / 1024;
	return {
		duration: `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`,
		iso: `PT${Math.floor(seconds / 60)}M${seconds % 60}S`,
		size: `${megabytes.toFixed(1)} MB`,
		description: info.description,
		uploadDate: info.uploadDate,
	};
}

// All pages of one language.
function buildLocale(context) {
	const nav = NAV.map(({group, pages}) => ({group, pages: pages.map(([source, label]) => loadDoc(source, label))}));
	const order = nav.flatMap(g => g.pages);
	const sources = new Set(['README.md', ...order.map(p => p.source), ...[...GUIDES, 'faq'].map(slug => `site/pages/${slug}.md`)]);
	const guides = GUIDES.map(slug => loadGuide(slug));
	const faq = loadGuide('faq');
	const guideSummaries = guides.map(g => ({url: `/${g.slug}/`, label: g.data.label, description: g.data.description}));
	context.guides = guideSummaries;
	const home = landing(context);
	// The home page counts as translated when its interface strings are.
	home.translated = isDefault() || [SITE.description, 'How a message is judged', 'What it checks', 'Built for Forward Email'].every(english => has(english));
	return [
		home,
		...order.map(doc => docPage(doc, nav, order, sources)),
		...guides.map(guide => guidePage(guide, sources, guideSummaries)),
		guidePage(faq, sources, guideSummaries),
	];
}

export async function build({outDir = path.join(root, '_site')} = {}) {
	fs.rmSync(outDir, {recursive: true, force: true});
	fs.mkdirSync(outDir, {recursive: true});
	const buildTime = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

	const css = fs.readFileSync(path.join(siteDir, 'style.css'), 'utf8');
	const js = fs.readFileSync(path.join(siteDir, 'site.js'), 'utf8');
	const assets = {css: hash(css), js: hash(js)};
	fs.writeFileSync(path.join(outDir, 'style.css'), css);
	fs.writeFileSync(path.join(outDir, 'site.js'), js);
	for (const file of ['favicon-32.png', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png', 'og.png']) {
		copy(path.join(siteDir, file), outDir, file);
	}

	copy(path.join(siteDir, 'brand', 'favicon.svg'), outDir, 'favicon.svg');
	copy(path.join(siteDir, 'brand', 'mark.svg'), outDir, 'brand/mark.svg');
	const video = videoInfo();
	if (video) {
		for (const file of ['spam-scanner.mp4', 'spam-scanner.webm', 'spam-scanner.jpg', 'spam-scanner-cover.jpg']) {
			copy(path.join(siteDir, 'media', file), outDir, `media/${file}`);
		}
	}

	const model = JSON.parse(fs.readFileSync(path.join(root, 'model', 'classifier.json'), 'utf8'));
	const context = {assets, video, model};
	const byLocale = new Map();
	for (const item of LOCALES) {
		setLocale(item.code);
		byLocale.set(item.code, buildLocale(context));
	}

	// A page links to the languages it is translated into; untranslated copies
	// stay out of search engines.
	const all = [];
	for (const [code, pages] of byLocale) {
		for (const p of pages) {
			p.locale = code;
			p.url = `${prefix(code)}${p.path}`;
			p.noindex = !p.translated;
			p.alternates = LOCALES.map(item => item.code).filter(other => byLocale.get(other).find(q => q.path === p.path)?.translated);
			all.push(p);
		}
	}

	for (const p of all) {
		setLocale(p.locale);
		p.lastmod = lastmod(p.sources, buildTime);
		// Rendering needs the current locale for the shared chrome.
		context.guides = byLocale.get(p.locale).filter(q => q.kind === 'guide').map(q => ({url: q.path, label: q.label, description: q.description}));
		write(outDir, p.url, render(p, context));
		if (p.markdown) {
			write(outDir, `${p.url}index.md`, p.markdown);
		}
	}

	setLocale(DEFAULT);
	const errorPage = notFound();
	errorPage.url = errorPage.path;
	errorPage.lastmod = buildTime;
	context.guides = byLocale.get(DEFAULT).filter(q => q.kind === 'guide').map(q => ({url: q.path, label: q.label, description: q.description}));
	write(outDir, errorPage.url, render(errorPage, context));

	const english = byLocale.get(DEFAULT);
	fs.writeFileSync(path.join(outDir, 'sitemap.xml'), sitemap(all));
	fs.writeFileSync(path.join(outDir, 'robots.txt'), robots());
	fs.writeFileSync(path.join(outDir, 'llms.txt'), llms(english));
	fs.writeFileSync(path.join(outDir, 'llms-full.txt'), llmsFull(english));
	fs.writeFileSync(path.join(outDir, 'manifest.webmanifest'), manifest());
	fs.writeFileSync(path.join(outDir, '.nojekyll'), '');
	copy(path.join(root, 'CNAME'), outDir, 'CNAME');

	// The English interface strings, for translators.
	fs.mkdirSync(path.join(I18N_DIR, 'source'), {recursive: true});
	fs.writeFileSync(path.join(I18N_DIR, 'source', 'ui.json'), `${JSON.stringify(Object.fromEntries(usedStrings().map(english => [english, english])), null, '\t')}\n`);
	const sourceHashes = {};
	for (const file of fs.readdirSync(path.join(root, 'docs')).filter(name => name.endsWith('.md'))) {
		sourceHashes[`docs/${file}`] = markdownHash(fs.readFileSync(path.join(root, 'docs', file), 'utf8'));
	}

	for (const slug of [...GUIDES, 'faq']) {
		sourceHashes[`pages/${slug}.md`] = markdownHash(fs.readFileSync(path.join(siteDir, 'pages', `${slug}.md`), 'utf8'));
	}

	fs.writeFileSync(path.join(I18N_DIR, 'source', 'hashes.json'), `${JSON.stringify(sourceHashes, null, '\t')}\n`);
	const indexed = all.filter(p => !p.noindex);
	return {outDir, pages: indexed.map(p => p.url), total: all.length};
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	const outArg = process.argv.indexOf('--out');
	const {outDir, pages, total} = await build(outArg === -1 ? {} : {outDir: path.resolve(process.argv[outArg + 1])});
	console.log(`Built ${total} pages (${pages.length} translated and indexed) into ${path.relative(process.cwd(), outDir) || '.'}`);
}
