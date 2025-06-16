const process = require('node:process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {Worker} = require('node:worker_threads');
const NaiveBayes = require('@ladjs/naivebayes');
const pMap = require('p-map');
const {readDirDeep} = require('read-dir-deep');
const CLASSIFIER_IGNORES = require('./classifier-ignores.js');
const MBOX_PATTERNS = require('./mbox-patterns.js');
const VOCABULARY_LIMIT = require('./vocabulary-limit.js');
const replacements = require('./replacements.js');

const concurrency = os.cpus().length;

const classifierWorker = path.join(__dirname, 'classifier-worker.js');

// Simply delete the classifier.json to retrain from scratch
let json;
try {
	json = require('./classifier.json');
	console.log('re-training with existing classifier');
} catch (error) {
	console.error(error);
	console.log('training new classifier');
}

function tokenizer(tokens) {
	return tokens;
}

let classifier;
if (json) {
	classifier = NaiveBayes.fromJson(json, VOCABULARY_LIMIT);
	classifier.tokenizer = tokenizer;
} else {
	classifier = new NaiveBayes({tokenizer, vocabularyLimit: VOCABULARY_LIMIT});
}

if (
	typeof process.env.SPAM_CATEGORY !== 'string'
	|| !['ham', 'spam'].includes(process.env.SPAM_CATEGORY)
) {
	throw new Error('SPAM_CATEGORY environment variable missing');
}

if (typeof process.env.SCAN_DIRECTORY !== 'string') {
	throw new TypeError('SCAN_DIRECTORY environment variable missing');
}

async function mapper(source) {
	try {
		console.log('source', source);
		const worker = new Worker(classifierWorker, {
			workerData: {
				replacements,
				source,
			},
		});
		const tokens = await new Promise((resolve, reject) => {
			worker.on('message', resolve);
			worker.on('error', reject);
			worker.on('exit', code => {
				if (code !== 0) {
					return reject(new Error(`Worker stopped with exit code ${code}`));
				}
			});
		});
		if (tokens.length > 0) {
			classifier.learn(tokens, process.env.SPAM_CATEGORY);
		}
	} catch (error) {
		console.log('source error', source);
		console.error(error);
	}
}

(async () => {
	// Read directory for all files (i/o)
	console.time('sources');
	const dir = path.resolve(process.env.SCAN_DIRECTORY);

	const sources = await readDirDeep(dir, {
		ignore: [...CLASSIFIER_IGNORES, ...MBOX_PATTERNS],
	});
	console.timeEnd('sources');

	// Process all token sets, this is an array of arrays
	// for each source it returns an array of stemmed tokens
	console.time('tokenSets');
	await pMap(sources, mapper, {concurrency});
	console.timeEnd('tokenSets');

	console.time('writing classifier.json');
	fs.writeFileSync(
		path.join(__dirname, 'classifier.json'),
		classifier.toJson(),
	);
	console.timeEnd('writing classifier.json');

	console.time('writing replacements.json');
	fs.writeFileSync(
		path.join(__dirname, 'replacements.json'),
		JSON.stringify(replacements, null, 2),
	);
	console.timeEnd('writing replacements.json');

	process.exit(0);
})();
