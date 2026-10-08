// Builds dist/: ESM and CommonJS bundles of the library and the ARF parser,
// the command line tool, and a standalone CLI for single executable binaries.
import {readFileSync, rmSync} from 'node:fs';
import {build} from 'esbuild';

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));

// Dependencies stay external in the library builds.
const external = [...Object.keys(pkg.dependencies || {}), 'node:*'];
const commonJs = ['mailauth', 'mailparser', 'tldts'];

// CommonJS has no import.meta.url: give it one from __filename.
const cjsShim = {
	banner: {js: 'const __importMetaUrl = require("node:url").pathToFileURL(__filename).href;'},
	define: {'import.meta.url': '__importMetaUrl'},
};

rmSync('dist', {recursive: true, force: true});

const library = {
	bundle: true, platform: 'node', target: 'node18', external, sourcemap: true, logLevel: 'warning',
};

for (const [entry, name] of [['src/index.js', 'index'], ['src/arf.js', 'arf']]) {
	// eslint-disable-next-line no-await-in-loop
	await build({
		...library, entryPoints: [entry], format: 'esm', outfile: `dist/esm/${name}.js`,
	});
}

// CommonJS: require('spamscanner') returns the SpamScanner class, with every
// other export as a property, as earlier versions did. Node.js 18 cannot
// require() ES modules, so the dependencies published only as ES modules
// (franc) are bundled.
const cjs = {
	...library, ...cjsShim, external: [...commonJs, 'node:*'], format: 'cjs',
};
await build({
	...cjs,
	stdin: {contents: 'const m = require(\'./src/index.js\');\nmodule.exports = Object.assign(m.SpamScanner, m);\n', resolveDir: '.', sourcefile: 'index.cjs'},
	outfile: 'dist/cjs/index.cjs',
});
await build({...cjs, entryPoints: ['src/arf.js'], outfile: 'dist/cjs/arf.cjs'});

await build({
	...library, entryPoints: ['src/bin.js'], format: 'esm', outfile: 'dist/esm/cli.js',
});

// The standalone CLI bundles every dependency, for `node --experimental-sea-config`.
await build({
	...cjsShim,
	entryPoints: ['src/bin.js'],
	bundle: true,
	platform: 'node',
	target: 'node20',
	format: 'cjs',
	outfile: 'dist/standalone/cli.cjs',
	minify: true,
	logLevel: 'warning',
});

console.log(`Built spamscanner ${pkg.version} into dist/`);
