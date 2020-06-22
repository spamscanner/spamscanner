const numeral = require('numeral');

const patterns = [
  '.mbox',
  '*.mbox.*',
  '.mail',
  '*.mail.*',
  '*.mail',
  '*.mbox',
  '*.orig'
];

const arr = [];

for (let i = 0; i <= 99; i++) {
  for (let z = 0; z <= 99; z++) {
    arr.push(`*.19${numeral(i).format('00')}.${numeral(z).format('00')}`);
    arr.push(`*.20${numeral(i).format('00')}.${numeral(z).format('00')}`);
    arr.push(`19${numeral(i).format('00')}-${numeral(z).format('00')}`);
    arr.push(`20${numeral(i).format('00')}-${numeral(z).format('00')}`);
  }
}

for (const pattern of patterns) {
  arr.push(pattern);
  arr.push(`*/${pattern}`);
  arr.push(`*/**/${pattern}`);
  arr.push(`*/**/**/${pattern}`);
}

module.exports = arr;
