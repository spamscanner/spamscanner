import {debuglog} from 'node:util';
import {readFileSync} from 'node:fs';
import NaiveBayes from '@ladjs/naivebayes';

const debug = debuglog('spamscanner');

let classifier = new NaiveBayes().toJsonObject();

try {
	classifier = JSON.parse(readFileSync('./classifier.json', 'utf8'));
} catch (error) {
	debug(error);
}

export default classifier;
