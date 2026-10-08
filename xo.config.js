/** @type {import('xo').FlatXoConfig} */
const xoConfig = [
	{
		ignores: ['**/*.d.ts', 'dist/**', 'coverage/**', '_site/**', 'data/**', 'model/**'],
	},
	{
		rules: {
			// Parsers and protocol code are long by nature; warnings only.
			// Rule tables (scoring, settings) branch once per rule.
			complexity: ['warn', 70],
			'max-depth': ['warn', 6],
			'@stylistic/max-len': 'off',
			// Node.js servers and sockets are EventEmitters.
			'unicorn/prefer-event-target': 'off',
		},
	},
	{
		// Hashing and the milter protocol work on bits.
		files: ['src/classifier.js', 'src/milter.js', 'src/attachments.js', 'test/**/*.js'],
		rules: {
			'no-bitwise': 'off',
		},
	},
	{
		// Reading sources and messages one at a time is the point.
		files: ['src/train.js', 'src/sources.js', 'scripts/**/*.js', 'test/**/*.js'],
		rules: {
			'no-await-in-loop': 'off',
		},
	},
	{
		files: ['test/**/*.js'],
		rules: {
			// Assertions read best as assert.equal((await x()).y, z).
			'unicorn/no-await-expression-member': 'off',
			// Test data mirrors outside formats (ARF fields, dataset columns).
			camelcase: 'off',
		},
	},
];

export default xoConfig;
