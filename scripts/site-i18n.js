// Translations for spamscanner.net, in the style of privacyratings.com.
//
//   i18n/locales.json            the languages; English is the source
//   i18n/source/ui.json          every English interface string, written by the build
//   i18n/<code>/ui.json          English string -> translation
//   i18n/<code>/docs/<name>.md   a translated docs/<name>.md
//   i18n/<code>/pages/<name>.md  a translated site/pages/<name>.md
//
// English text is the key, so when the English changes the old translation
// stops matching and the English shows until it is translated again. A
// translated document starts with "<!-- source: <hash> -->", the hash of the
// English file it was made from; when the English file changes, the
// translation is set aside the same way. Nothing out of date is shown.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DIR = path.join(ROOT, 'i18n');
export const LOCALES = JSON.parse(fs.readFileSync(path.join(DIR, 'locales.json'), 'utf8'));
export const DEFAULT = 'en';
const CODE = /^[a-z]{2,3}(?:-[a-z\d]{2,8})?$/;
for (const locale of LOCALES) {
	if (!CODE.test(locale.code)) {
		throw new Error(`i18n/locales.json: invalid code ${JSON.stringify(locale.code)}`);
	}
}

export const byCode = new Map(LOCALES.map(locale => [locale.code, locale]));
const catalogs = new Map();
const used = new Set();
let current = DEFAULT;

export function catalog(code) {
	if (!catalogs.has(code)) {
		const file = path.join(DIR, code, 'ui.json');
		const data = code !== DEFAULT && fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
		catalogs.set(code, new Map(Object.entries(data)));
	}

	return catalogs.get(code);
}

export function setLocale(code) {
	if (!byCode.has(code)) {
		throw new Error(`Unknown locale ${code}`);
	}

	current = code;
}

export const locale = () => byCode.get(current);
export const isDefault = () => current === DEFAULT;
export const prefix = (code = current) => (code === DEFAULT ? '' : `/${code}`);

function escapeHtml(value) {
	return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

// Only the caller's own values fill placeholders.
function fill(text, values) {
	return values ? text.replaceAll(/{(\w+)}/g, (match, key) => (Object.hasOwn(values, key) ? String(values[key]) : match)) : text;
}

function lookup(english) {
	used.add(english);
	const hit = catalog(current).get(english);
	return typeof hit === 'string' && hit.trim() ? hit : english;
}

/** Plain text. */
export const t = (english, values) => fill(lookup(english), values);

/** HTML: the translation is escaped, then placeholders are filled with HTML. */
export const th = (english, values) => fill(escapeHtml(lookup(english)), values);

/** Whether a string has a translation in the current language. */
export const has = english => isDefault() || Boolean(catalog(current).get(english)?.trim());

/** Every English string looked up so far: the list translators work from. */
export const usedStrings = () => [...used].sort();

export const markdownHash = text => crypto.createHash('sha256').update(text).digest('hex').slice(0, 12);

const HEADER = /^<!-- source: ([\da-f]{12}) -->\n+/;

/**
 * The current language's translation of an English Markdown file, if there is
 * one and it was made from this version of the English.
 * @param {'docs'|'pages'} kind
 * @param {string} name - file name, such as cli.md
 * @param {string} english - the English file's content
 * @returns {string|null}
 */
export function translatedMarkdown(kind, name, english) {
	if (isDefault()) {
		return null;
	}

	const file = path.join(DIR, current, kind, name);
	if (!fs.existsSync(file)) {
		return null;
	}

	const text = fs.readFileSync(file, 'utf8');
	const match = HEADER.exec(text);
	return match && match[1] === markdownHash(english) ? text.slice(match[0].length) : null;
}
