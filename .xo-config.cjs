module.exports = {
	prettier: true,
	space: true,
	rules: {
		'unicorn/prefer-logical-operator-over-ternary': 'off',
		'no-await-in-loop': 'off',
		'promise/param-names': 'off',
		'no-promise-executor-return': 'off',
		'no-warning-comments': 'off',
		'import-x/order': 'off',
		'camelcase': 'off',
		'unicorn/prevent-abbreviations': 'off',
		'logical-assignment-operators': 'off',
		'unicorn/prefer-string-replace-all': 'off',
		'curly': 'off',
		'@stylistic/operator-linebreak': 'off'
	},
	ignores: [
		'dist/',
		'build/',
		'coverage/',
		'node_modules/',
		'*.min.js',
		'test/fixtures/',
		'*.config.js',
		'*.config.cjs',
		'*.config.mjs'
	]
};

