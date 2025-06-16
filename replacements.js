import {debuglog} from 'node:util';
import {readFileSync} from 'node:fs';
import cryptoRandomString from 'crypto-random-string';
import REPLACEMENT_WORDS from './replacement-words.json' with { type: 'json' };

const debug = debuglog('spamscanner');

const randomOptions = {
	length: 10,
	characters: 'abcdefghijklmnopqrstuvwxyz',
};

// Simply delete the replacements.json to generate new replacements
let replacements = {};
try {
	replacements = JSON.parse(readFileSync('./replacements.json', 'utf8'));
} catch (error) {
	debug(error);
	for (const replacement of REPLACEMENT_WORDS) {
		replacements[replacement] = `${replacement}${cryptoRandomString(randomOptions)}`;
	}
}

export default replacements;
