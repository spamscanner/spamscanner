#!/usr/bin/env node
import process from 'node:process';
import {main} from './cli.js';

// eslint-disable-next-line unicorn/prefer-top-level-await -- the standalone binary is CommonJS
main(process.argv.slice(2)).then(code => {
	process.exitCode = code;
});
