import {readFileSync} from 'node:fs';
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

// Build CJS
await build({
	...baseConfig,
	format: 'cjs',
	outfile: 'dist/cjs/index.js',
});

console.log('Build completed successfully!');

