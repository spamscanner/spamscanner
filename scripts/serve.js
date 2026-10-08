#!/usr/bin/env node
// A small static server for previewing _site/: npm run site:serve
// Text files are gzip-compressed and byte ranges are served, as GitHub Pages
// does, so Lighthouse measures what visitors get and Safari plays the video.
// Listens on 127.0.0.1; set HOST (for example 0.0.0.0) and PORT to change it.

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';
import zlib from 'node:zlib';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '_site');
const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const TYPES = {
	'.html': 'text/html; charset=utf-8',
	'.css': 'text/css; charset=utf-8',
	'.js': 'text/javascript; charset=utf-8',
	'.json': 'application/json',
	'.svg': 'image/svg+xml',
	'.xml': 'application/xml',
	'.txt': 'text/plain; charset=utf-8',
	'.md': 'text/markdown; charset=utf-8',
	'.png': 'image/png',
	'.jpg': 'image/jpeg',
	'.mp4': 'video/mp4',
	'.webm': 'video/webm',
	'.webmanifest': 'application/manifest+json',
};

function notFound(request, response) {
	const page = path.join(ROOT, '404.html');
	response.writeHead(404, {'content-type': TYPES['.html']});
	response.end(request.method === 'HEAD' ? undefined : (fs.existsSync(page) ? fs.readFileSync(page) : 'Not found'));
}

// A URL path to a file inside ROOT, a redirect for a folder without its
// trailing slash, or null.
function resolve(url) {
	let pathname;
	try {
		pathname = decodeURIComponent(new URL(url, 'http://localhost').pathname);
	} catch {
		return null;
	}

	if (pathname.includes('\0')) {
		return null;
	}

	if (pathname.endsWith('/')) {
		pathname += 'index.html';
	}

	const file = path.resolve(ROOT, `.${path.posix.normalize(pathname)}`);
	let real;
	try {
		real = fs.realpathSync(file);
	} catch {
		return null;
	}

	const realRoot = fs.realpathSync(ROOT);
	if (!real.startsWith(realRoot + path.sep)) {
		return null;
	}

	const stat = fs.statSync(real);
	if (stat.isFile()) {
		return real;
	}

	// The location comes from the folder's own path, never from the request.
	if (stat.isDirectory() && fs.existsSync(path.join(real, 'index.html'))) {
		return {redirect: `/${path.relative(realRoot, real).split(path.sep).map(part => encodeURIComponent(part)).join('/')}/`};
	}

	return null;
}

http.createServer((request, response) => {
	if (request.method !== 'GET' && request.method !== 'HEAD') {
		response.writeHead(405, {allow: 'GET, HEAD'});
		response.end();
		return;
	}

	const file = resolve(request.url);
	if (!file) {
		notFound(request, response);
		return;
	}

	if (file.redirect) {
		response.writeHead(301, {location: file.redirect});
		response.end();
		return;
	}

	const type = TYPES[path.extname(file)] || 'application/octet-stream';
	const body = fs.readFileSync(file);
	const headers = {'content-type': type, 'x-content-type-options': 'nosniff'};
	if (/gzip/.test(request.headers['accept-encoding'] || '') && /text|json|xml|svg|javascript/.test(type)) {
		response.writeHead(200, {...headers, 'content-encoding': 'gzip', vary: 'Accept-Encoding'});
		response.end(request.method === 'HEAD' ? undefined : zlib.gzipSync(body));
		return;
	}

	headers['accept-ranges'] = 'bytes';
	const range = /^bytes=(\d*)-(\d*)$/.exec(request.headers.range || '');
	if (range && (range[1] || range[2])) {
		const size = body.length;
		const start = Math.max(0, range[1] ? Number(range[1]) : size - Number(range[2]));
		const end = range[1] && range[2] ? Math.min(Number(range[2]), size - 1) : size - 1;
		if (start >= size || start > end) {
			response.writeHead(416, {...headers, 'content-range': `bytes */${size}`});
			response.end();
			return;
		}

		response.writeHead(206, {...headers, 'content-range': `bytes ${start}-${end}/${size}`, 'content-length': end - start + 1});
		response.end(request.method === 'HEAD' ? undefined : body.subarray(start, end + 1));
		return;
	}

	response.writeHead(200, {...headers, 'content-length': body.length});
	response.end(request.method === 'HEAD' ? undefined : body);
}).listen(PORT, HOST, () => {
	console.log(`Preview at http://${HOST === '127.0.0.1' ? 'localhost' : HOST}:${PORT}`);
});
