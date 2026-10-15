// Preload (node --require): makes the re2 package fail to load, as when it is
// not installed, so the JavaScript regular expressions are used.
const Module = require('node:module');

const load = Module._load;
Module._load = function (request, ...rest) {
	if (request === 're2') {
		throw new Error('Cannot find module \'re2\'');
	}

	return load.call(this, request, ...rest);
};
