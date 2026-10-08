module.exports = {
	'*.{js,mjs,cjs}': ['xo --fix'],
	// One remark run for all staged files; starting one per file takes minutes.
	'*.md': ['remark -qfo --silently-ignore'],
	'package.json': ['fixpack'],
};
