// The plain files search engines and crawlers read: robots.txt, sitemap.xml
// and /.well-known/security.txt. Used by build-site.js.

// Search engines and AI crawlers, named so a rule for one of them elsewhere
// never shuts it out by accident.
export const CRAWLERS = ['Googlebot', 'Bingbot', 'DuckDuckBot', 'DuckAssistBot', 'Applebot', 'Applebot-Extended', 'Google-Extended', 'GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'PerplexityBot', 'Perplexity-User', 'CCBot', 'meta-externalagent', 'Amazonbot', 'MistralAI-User'];

export function robots(url) {
	return `# Everything on this site is public. Search engines, crawlers and AI agents are welcome;\n# /llms.txt lists the pages for language models.\nUser-agent: *\nAllow: /\n\n${CRAWLERS.map(name => `User-agent: ${name}`).join('\n')}\nAllow: /\n\nSitemap: ${url}/sitemap.xml\n`;
}

// RFC 9116: where to report a vulnerability. It expires a year after the build.
export function securityTxt({url, repo, buildTime}) {
	const expires = new Date(Date.parse(buildTime) + (365 * 24 * 60 * 60 * 1000)).toISOString().replace(/\.\d+Z$/, 'Z');
	return `Contact: ${repo}/security/advisories/new\nExpires: ${expires}\nPolicy: ${url}/docs/security/#reporting-a-vulnerability\nPreferred-Languages: en\nCanonical: ${url}/.well-known/security.txt\n`;
}

// One entry per page and language. Each page names its other languages in
// its own <head>, so the sitemap stays small enough for every crawler to read.
export function sitemap(url, pages) {
	const entries = pages.filter(p => !p.noindex).map(p => `<url><loc>${url}${p.url}</loc><lastmod>${p.lastmod}</lastmod></url>`);
	return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries.join('\n')}\n</urlset>\n`;
}
