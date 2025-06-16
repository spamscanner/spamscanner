module.exports = [
	'**/Summary.txt',
	'**/cmds',
	'**/cmd',
	'**/index',
	'**/.*', // ignore dotfiles
	'**/*.',
	'**/current', // Mbox we can't parse
	'**/current.old', // Mbox we can't parse
	'**/*.z', // Binary file not for parsing
	'**/.current.map', // Binary file not for parsing
];
