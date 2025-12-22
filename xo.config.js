/** @type {import('xo').FlatXoConfig} */
const xoConfig = [
	{
		ignores: ['**/*.d.ts'],
	},
	{
		// CLI needs to use async main() pattern for CJS compatibility
		// and process.exit() for proper exit codes
		files: ['src/cli.js'],
		rules: {
			'unicorn/prefer-top-level-await': 'off',
			'unicorn/no-process-exit': 'off',
			complexity: 'off',
		},
	},
	{
		// Main index.js has complex methods that are necessary
		files: ['src/index.js'],
		rules: {
			complexity: 'off',
			'max-lines': 'off',
			'max-depth': 'off',
		},
	},
	{
		// Helper modules have complex extraction logic
		files: ['src/is-arbitrary.js', 'src/get-attributes.js'],
		rules: {
			complexity: 'off',
			'max-depth': 'off',
		},
	},
	{
		// Test files can have long lines for test data
		files: ['test/**/*.js'],
		rules: {
			'@stylistic/max-len': 'off',
		},
	},
];

export default xoConfig;
