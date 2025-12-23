import {debuglog} from 'node:util';
import cryptoRandomString from 'crypto-random-string';
import REPLACEMENT_WORDS from './replacement-words.json' with { type: 'json' };

const debug = debuglog('spamscanner');

const randomOptions = {
	length: 10,
	characters: 'abcdefghijklmnopqrstuvwxyz',
};

// Generate replacements dynamically for each word
// This ensures the standalone binary works without external files
const replacements = {};
for (const replacement of REPLACEMENT_WORDS) {
	replacements[replacement] = `${replacement}${cryptoRandomString(randomOptions)}`;
}

debug('Generated replacements for %d words', REPLACEMENT_WORDS.length);

export default replacements;
