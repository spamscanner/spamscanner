const { debuglog } = require('node:util');
const NaiveBayes = require('@ladjs/naivebayes');

const debug = debuglog('spamscanner');

let classifier = new NaiveBayes().toJsonObject();

try {
  classifier = require('./classifier.json');
} catch (err) {
  debug(err);
}

module.exports = classifier;
