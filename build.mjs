import {copyFileSync, mkdirSync, readFileSync} from 'node:fs';
import {build} from 'esbuild';

const packageJson = JSON.parse(readFileSync('package.json', 'utf8'));

// Get all dependencies to mark as external
const externals = [
	...Object.keys(packageJson.dependencies || {}),
	...Object.keys(packageJson.peerDependencies || {}),
	'node:*',
];

const baseConfig = {
	bundle: true,
	platform: 'node',
	target: 'node18',
	external: externals,
	sourcemap: true,
	minify: false,
};

// Build ESM - main index
await build({
	...baseConfig,
	entryPoints: ['src/index.js'],
	format: 'esm',
	outfile: 'dist/esm/index.js',
});

// Build CJS - main index (suppress import.meta warning)
await build({
	...baseConfig,
	entryPoints: ['src/index.js'],
	format: 'cjs',
	outfile: 'dist/cjs/index.cjs',
	logOverride: {
		'empty-import-meta': 'silent',
	},
});

// Build ESM - ARF parser
await build({
	...baseConfig,
	entryPoints: ['src/arf.js'],
	format: 'esm',
	outfile: 'dist/esm/arf.js',
});

// Build CJS - ARF parser
await build({
	...baseConfig,
	entryPoints: ['src/arf.js'],
	format: 'cjs',
	outfile: 'dist/cjs/arf.cjs',
	logOverride: {
		'empty-import-meta': 'silent',
	},
});

// Build ESM - CLI
await build({
	...baseConfig,
	entryPoints: ['src/cli.js'],
	format: 'esm',
	outfile: 'dist/esm/cli.js',
	banner: {
		js: '#!/usr/bin/env node',
	},
});

// Build CJS - CLI
await build({
	...baseConfig,
	entryPoints: ['src/cli.js'],
	format: 'cjs',
	outfile: 'dist/cjs/cli.cjs',
	banner: {
		js: '#!/usr/bin/env node',
	},
	logOverride: {
		'empty-import-meta': 'silent',
	},
});

// Copy TypeScript declaration files
mkdirSync('dist/types', {recursive: true});
copyFileSync('src/index.d.ts', 'dist/types/index.d.ts');
copyFileSync('src/enhanced-idn-detector.d.ts', 'dist/types/enhanced-idn-detector.d.ts');
copyFileSync('src/arf.d.ts', 'dist/types/arf.d.ts');
copyFileSync('src/auth.d.ts', 'dist/types/auth.d.ts');
copyFileSync('src/reputation.d.ts', 'dist/types/reputation.d.ts');
copyFileSync('src/is-arbitrary.d.ts', 'dist/types/is-arbitrary.d.ts');
copyFileSync('src/get-attributes.d.ts', 'dist/types/get-attributes.d.ts');

console.log('Build completed successfully!');
