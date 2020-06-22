module.exports = [
  '**/Summary.txt',
  '**/cmds',
  '**/cmd',
  '**/index',
  '**/.*', // ignore dotfiles
  '**/*.',
  '**/current', // mbox we can't parse
  '**/current.old', // mbox we can't parse
  '**/*.z', // binary file not for parsing
  '**/.current.map' // binary file not for parsing
];
