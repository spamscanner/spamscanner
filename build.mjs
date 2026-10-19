// Builds dist/: ESM and CommonJS bundles of the library and the ARF parser,
// the command line tool, a standalone CLI for single executable binaries, and
// type declarations for ESM and CommonJS consumers.
import {execFileSync} from 'node:child_process';
import {
	copyFileSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import {createRequire} from 'node:module';
import process from 'node:process';
import {build} from 'esbuild';
import ts from 'typescript';

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

// Type declarations. tsc writes them for ESM, and in a "type": "module"
// package TypeScript reads those as ES modules, so CommonJS consumers get a
// .d.cts for each export that describes what require() returns.
execFileSync(process.execPath, [createRequire(import.meta.url).resolve('typescript/bin/tsc'), '--project', 'tsconfig.json'], {stdio: 'inherit'});
// (written by hand: tsc reads it but does not copy it)
copyFileSync('src/legacy.d.ts', 'dist/types/legacy.d.ts');

// TypeScript symbol flags are bit fields.
// eslint-disable-next-line no-bitwise
const hasFlag = (symbol, flag) => (symbol.flags & flag) !== 0;

/**
 * The exports of a declaration file, split into types and values.
 * @param {string} file
 * @returns {{types: string[], values: string[]}}
 */
function exportsOf(file) {
	const program = ts.createProgram([file], {module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, noEmit: true});
	const checker = program.getTypeChecker();
	const types = [];
	const values = [];
	for (const symbol of checker.getExportsOfModule(checker.getSymbolAtLocation(program.getSourceFile(file)))) {
		const target = hasFlag(symbol, ts.SymbolFlags.Alias) ? checker.getAliasedSymbol(symbol) : symbol;
		if (hasFlag(target, ts.SymbolFlags.Value)) {
			values.push(symbol.name);
		}

		if (hasFlag(target, ts.SymbolFlags.Type) && symbol.name !== 'default') {
			if (checker.getDeclaredTypeOfSymbol(target).typeParameters) {
				throw new Error(`${file}: generic type ${symbol.name} needs a hand-written alias in build.mjs`);
			}

			types.push(symbol.name);
		}
	}

	return {types, values};
}

const typeAliases = types => types.map(name => `\texport type ${name} = m.${name};\n`).join('');

// In CommonJS, require('spamscanner') is the SpamScanner class with every export as a property.
const index = exportsOf('dist/types/index.d.ts');
writeFileSync('dist/types/index.d.cts', `import type * as m from './index.js' with {'resolution-mode': 'import'};
type SpamScanner = m.SpamScanner;
declare const SpamScanner: typeof m.SpamScanner & Omit<typeof m, 'default'> & {default: typeof m.SpamScanner};
declare namespace SpamScanner {
${typeAliases(index.types)}}
export = SpamScanner;
`);

// In CommonJS, require('spamscanner/arf') is the module object, default export included.
const arf = exportsOf('dist/types/arf.d.ts');
writeFileSync('dist/types/arf.d.cts', [
	'import type * as m from \'./arf.js\' with {\'resolution-mode\': \'import\'};',
	...arf.values.map(name => name === 'default'
		? 'declare const _default: typeof m.default;\nexport {_default as default};'
		: `export declare const ${name}: typeof m.${name};`),
	...arf.types.map(name => `export type ${name} = m.${name};`),
	'',
].join('\n'));

console.log(`Built spamscanner ${pkg.version} into dist/`);
