const path = require('path');
const fs = require('fs');
const os = require('os');
const readline = require('readline');

const del = require('del');
const pMap = require('p-map');
const shell = require('shelljs');
const { GaussianNB } = require('ml-naivebayes');
const { readDirDeep } = require('read-dir-deep');

const SpamScanner = require('.');

const concurrency = os.cpus().length * 2;
const scanner = new SpamScanner();
const model = new GaussianNB();

(async () => {
  try {
    // delete dictionary since we're writing a new one
    await del(path.join(__dirname, 'dictionary.txt'));
    await del(path.join(__dirname, 'token-sets.txt'));
    await del(path.join(__dirname, 'classifier.json'));

    const dictionary = fs.createWriteStream(
      path.join(__dirname, 'dictionary.txt'),
      {
        flags: 'a'
      }
    );

    const tokenSets = fs.createWriteStream(
      path.join(__dirname, 'token-sets.txt'),
      {
        flags: 'a'
      }
    );

    const getTokens = async source => {
      try {
        const { tokens } = await scanner.getTokensAndMailFromSource(source);
        if (tokens.length > 0) {
          const kind = source.startsWith(path.join(__dirname, 'data', 'spam'))
            ? 'spam'
            : 'ham';
          tokenSets.write(`${kind} `);
          for (let i = 0; i < tokens.length; i++) {
            tokenSets.write(
              `${tokens[i]}${i === tokens.length - 1 ? '\n' : ' '}`
            );
            dictionary.write(`${tokens[i]}\n`);
          }
        }
      } catch (err) {
        console.log('source of error', source);
        console.error(err);
      }
    };

    // read directory for all files (i/o)
    console.time('sources');
    const sources = await readDirDeep(path.join(__dirname, 'data'));
    console.timeEnd('sources');

    // process all token sets, this is an array of arrays
    // for each source it returns an array of stemmed tokens
    console.time('tokenSets');
    await pMap(sources, getTokens, { concurrency });
    tokenSets.end();
    dictionary.end();
    console.timeEnd('tokenSets');

    // get the X most common words
    // <https://unix.stackexchange.com/a/263849>
    // <https://www.linuxquestions.org/questions/programming-9/%5Bbash%5D-read-file-line-by-line-and-split-on-whitespace-738143/#post3598846>
    console.time('get most common bag of words');
    // <https://arxiv.org/pdf/1806.06407.pdf>
    const count = 3000;
    const { stdout } = shell.exec(
      `cat dictionary.txt | sort | uniq -c | sort -nr | head -n ${count} | while read one two; do echo $two; done`
    );
    console.timeEnd('get most common bag of words');

    // stdout is the dictionary, split it by line break
    console.time('get dictionary');
    const bagOfWords = stdout.trim().split('\n');
    console.timeEnd('get dictionary');

    // read the `token-sets.txt` file
    // <https://nodejs.org/api/readline.html#readline_example_read_file_stream_line_by_line>
    const input = fs.createReadStream(path.join(__dirname, 'token-sets.txt'));

    // for each line in the `token-sets.txt`
    // we need to create a dictionary mapping to word counts
    const cases = [];
    const predictions = [];
    const rl = readline.createInterface({ input });

    rl.on('line', line => {
      const tokens = line.trim().split(' ');
      const kind = tokens.shift();
      const data = new Array(bagOfWords.length).fill(0);
      for (const token of tokens) {
        const idx = bagOfWords.indexOf(token);
        if (idx !== -1) data[idx]++;
      }

      cases.push(data);
      predictions.push(kind === 'spam' ? 1 : 0);
      // if (kind === 'spam')
    });

    rl.on('close', () => {
      model.train(cases, predictions);
      // spawn workers to parse tokensets.txt (each line is a space delimited arr)
      fs.writeFileSync(
        path.join(__dirname, 'classifier.json'),
        JSON.stringify(model.toJSON())
      );
      fs.writeFileSync(
        path.join(__dirname, 'bag-of-words.json'),
        JSON.stringify(bagOfWords)
      );
    });
  } catch (err) {
    throw err;
  }
})();
