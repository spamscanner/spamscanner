// TODO: equal 50/50 ham vs. spam dataset
// TODO: test classifier.json against dataset to determine percentage accuracy

const fs = require('fs');
const os = require('os');
const path = require('path');

const NaiveBayes = require('naivebayes');
const cryptoRandomString = require('crypto-random-string');
const pMap = require('p-map');
const { readDirDeep } = require('read-dir-deep');

const SpamScanner = require('.');

const concurrency = os.cpus().length * 4;
const randomOptions = {
  length: 10,
  characters: 'abcdefghijklmnopqrstuvwxyz'
};
const replacements = {
  url: `url_${cryptoRandomString(randomOptions)}`,
  email: `email_${cryptoRandomString(randomOptions)}`,
  number: `number_${cryptoRandomString(randomOptions)}`,
  currency: `currency_${cryptoRandomString(randomOptions)}`
};

const scanner = new SpamScanner({
  replacements,
  classifier: true
});

let json;

// simply delete the classifier.json to retrain from scratch
try {
  json = require('./classifier.json');
} catch (err) {
  console.error(err);
}

function tokenizer(tokens) {
  return tokens;
}

let classifier;
if (json) {
  classifier = NaiveBayes.fromJson(json);
  classifier.tokenizer = tokenizer;
} else {
  classifier = new NaiveBayes({ tokenizer });
}

if (
  typeof process.env.SPAM_CATEGORY !== 'string' ||
  !['ham', 'spam'].includes(process.env.SPAM_CATEGORY)
)
  throw new Error('SPAM_CATEGORY environment variable missing');

if (typeof process.env.SCAN_DIRECTORY !== 'string')
  throw new Error('SCAN_DIRECTORY environment variable missing');

const category = process.env.SPAM_CATEGORY;

async function mapper(source) {
  try {
    console.log('source', source);
    const { tokens } = scanner.getTokensAndMailFromSource(source);

    // to bias against false positives we can (at least for now)
    // take the token count for ham and double it (duplicate it)
    if (tokens.length > 0) {
      if (category === 'ham') {
        const { length } = tokens;
        // NOTE: concat is slower than push so we use push
        for (let i = 0; i < length; i++) {
          tokens.push(tokens[i]);
        }
      }

      classifier.learn(tokens, category);
    }
  } catch (err) {
    console.log('source error', source);
    console.error(err);
  }
}

(async () => {
  try {
    // read directory for all files (i/o)
    console.time('sources');
    const dir = path.resolve(process.env.SCAN_DIRECTORY);

    const sources = await readDirDeep(dir, {
      ignore: [
        '**/Summary.txt',
        '**/cmds',
        '**/cmd',
        '**/index',
        '**/.DS_Store',
        '**/*.mbox'
      ]
    });
    console.timeEnd('sources');

    // process all token sets, this is an array of arrays
    // for each source it returns an array of stemmed tokens
    console.time('tokenSets');
    await pMap(sources, mapper, { concurrency });

    /*
    for (const source of sources) {
      try {
        console.log('source', source);
        // eslint-disable-next-line no-await-in-loop
        const { tokens } = await scanner.getTokensAndMailFromSource(source);
        console.log('tokens.length', tokens.length);
        console.log('tokens', tokens);
        const category = source.startsWith('data/spam') ? 'spam' : 'ham';
        console.log('category', category);
        if (tokens.length > 0) classifier.learn(tokens.join(' '), category);
      } catch (err) {
        console.log('source error', source);
        console.error(err);
      }
    }
    */

    console.timeEnd('tokenSets');

    console.log('done training');

    fs.writeFileSync(
      path.join(__dirname, 'classifier.json'),
      classifier.toJson()
    );

    fs.writeFileSync(
      path.join(__dirname, 'replacements.json'),
      JSON.stringify(replacements)
    );
  } catch (err) {
    throw err;
  }
})();
