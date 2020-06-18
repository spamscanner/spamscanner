const cryptoRandomString = require('crypto-random-string');
const debug = require('debug')('spamscanner');

const REPLACEMENT_WORDS = require('./replacement-words.json');

const randomOptions = {
  length: 10,
  characters: 'abcdefghijklmnopqrstuvwxyz'
};

// simply delete the replacements.json to generate new replacements
let replacements = {};
try {
  replacements = require('./replacements.json');
} catch (err) {
  debug(err);
  for (const replacement of REPLACEMENT_WORDS) {
    replacements[replacement] = `${replacement}${cryptoRandomString(
      randomOptions
    )}`;
  }
}

module.exports = replacements;
