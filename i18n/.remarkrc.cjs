// Translations: the GitHub preset without its English prose checks (quotes,
// articles, contractions), which do not apply to other languages.
module.exports = {
	plugins: [
		'preset-github',
		['remark-retext', false],
		['lint-no-heading-punctuation', '.,;:!'],
	],
};
