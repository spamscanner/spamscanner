import {
	existsSync, readFileSync, writeFileSync, mkdirSync,
} from 'node:fs';
import {createRequire} from 'node:module';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';
import {Classifier} from './classifier.js';

const loaded = new Map();

/**
 * Directory of this module, in the source tree and in the built bundles.
 * @returns {string}
 */
export function moduleDirectory() {
	return path.dirname(fileURLToPath(import.meta.url));
}

/**
 * Path of the model shipped with the package (model/classifier.json), or the
 * one named by the SPAMSCANNER_MODEL environment variable.
 * @param {string} [here] - directory to look from (default: this module's)
 * @returns {string|null}
 */
export function defaultModelPath(here = moduleDirectory()) {
	if (process.env.SPAMSCANNER_MODEL) {
		return path.resolve(process.env.SPAMSCANNER_MODEL);
	}

	const candidates = [path.join(here, '..', 'model', 'classifier.json'), path.join(here, '..', '..', 'model', 'classifier.json')];
	return candidates.find(candidate => existsSync(candidate)) || null;
}

/**
 * The model embedded in a standalone binary (a Node.js single executable
 * application), or null when not running as one.
 * @param {object} [sea] - the node:sea module
 * @returns {string|null}
 */
export function embeddedModel(sea = loadSea()) {
	if (!sea?.isSea()) {
		return null;
	}

	try {
		return sea.getAsset('classifier.json', 'utf8');
	} catch {
		return null;
	}
}

/**
 * The node:sea module, or null on Node.js versions without it (before 20.12).
 * @param {Function} [load] - require, for tests
 * @returns {object|null}
 */
export function loadSea(load = createRequire(import.meta.url)) {
	try {
		return load('node:sea');
	} catch {
		return null;
	}
}

/**
 * The bundled model as a classifier: from the package's model file, or from
 * the standalone binary.
 * @param {object} [options] - classifier options
 * @param {object} [where] - for tests: file (the model path, null for none) and sea (the node:sea module)
 * @returns {Classifier} an empty classifier when no model is found
 */
export function loadDefaultModel(options = {}, {file = defaultModelPath(), sea} = {}) {
	if (file) {
		return loadModel(file, options);
	}

	const embedded = embeddedModel(sea);
	if (embedded) {
		if (!loaded.has('embedded')) {
			loaded.set('embedded', Classifier.fromJSON(embedded));
		}

		return copy(loaded.get('embedded'), options);
	}

	return new Classifier(options);
}

function copy(base, options) {
	const classifier = new Classifier({...base.options, ...options});
	classifier.nspam = base.nspam;
	classifier.nham = base.nham;
	classifier.frozen = base.frozen;
	classifier.metadata = base.metadata;
	return classifier;
}

/**
 * Load a model file written by saveModel or `spamscanner train`. Files are
 * read once per process; every classifier made from the same file shares its
 * counts, and learning goes into the classifier's own copy.
 * @param {string} file
 * @param {object} [options] - classifier options that override the model's
 * @returns {Classifier}
 */
export function loadModel(file, options = {}) {
	const resolved = path.resolve(file);
	if (!loaded.has(resolved)) {
		loaded.set(resolved, Classifier.fromJSON(readFileSync(resolved, 'utf8')));
	}

	return copy(loaded.get(resolved), options);
}

/**
 * Write a classifier to a file, creating its directory.
 * @param {Classifier} classifier
 * @param {string} file
 * @param {object} [options] - see Classifier#toJSON
 */
export function saveModel(classifier, file, options = {}) {
	const resolved = path.resolve(file);
	mkdirSync(path.dirname(resolved), {recursive: true});
	writeFileSync(resolved, `${JSON.stringify(classifier.toJSON(options))}\n`);
	loaded.delete(resolved);
}
