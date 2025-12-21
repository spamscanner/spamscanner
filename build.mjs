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
	entryPoints: ['src/index.js'],
	bundle: true, // Enable bundling
	platform: 'node',
	target: 'node18',
	external: externals,
	sourcemap: true,
	minify: false,
};

// Build ESM
await build({
	...baseConfig,
	format: 'esm',
	outfile: 'dist/esm/index.js',
});

// Build CJS - suppress the import.meta warning since CJS has __filename/__dirname natively
await build({
	...baseConfig,
	format: 'cjs',
	outfile: 'dist/cjs/index.js',
	logOverride: {
		'empty-import-meta': 'silent',
	},
});

// Copy TypeScript declaration files
mkdirSync('dist/types', {recursive: true});
copyFileSync('src/index.d.ts', 'dist/types/index.d.ts');
copyFileSync('src/enhanced-idn-detector.d.ts', 'dist/types/enhanced-idn-detector.d.ts');

console.log('Build completed successfully!');
