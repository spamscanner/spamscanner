import assert from 'node:assert/strict';
import {existsSync, readFileSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {describe, it} from 'node:test';
import {Classifier} from '../src/classifier.js';
import {
	defaultModelPath, embeddedModel, loadDefaultModel, loadModel, loadSea, moduleDirectory, saveModel,
} from '../src/model.js';
import {CLASSIFIER_MODELS, DECISION_MODELS, RECOMMENDED_MODELS} from '../src/models.js';
import {PROVIDERS} from '../src/llm.js';
import {VERSION} from '../src/version.js';
import {temporaryDirectory} from './helpers/index.js';

function trained() {
	const classifier = new Classifier();
	classifier.learn(['prize', 'winner'], 'spam');
	classifier.learn(['meeting', 'agenda'], 'ham');
	return classifier;
}

function fakeSea(asset) {
	return {
		isSea: () => asset !== undefined,
		getAsset(name, encoding) {
			assert.equal(name, 'classifier.json');
			assert.equal(encoding, 'utf8');
			if (asset instanceof Error) {
				throw asset;
			}

			return asset;
		},
	};
}

describe('model files', () => {
	it('finds the bundled model next to the package, or the one in SPAMSCANNER_MODEL', () => {
		assert.equal(moduleDirectory(), path.resolve('src'));
		assert.equal(defaultModelPath(), path.resolve('model/classifier.json'));
		assert.equal(defaultModelPath(path.resolve('dist/esm')), path.resolve('model/classifier.json'));
		assert.equal(defaultModelPath(temporaryDirectory()), null);
		process.env.SPAMSCANNER_MODEL = 'custom/model.json';
		try {
			assert.equal(defaultModelPath(), path.resolve('custom/model.json'));
		} finally {
			delete process.env.SPAMSCANNER_MODEL;
		}
	});

	it('loads the bundled model once and gives each caller its own classifier', () => {
		const first = loadDefaultModel();
		const second = loadDefaultModel({spamCutoff: 0.95});
		assert.ok(first.nspam > 1000 && first.nham > 1000);
		assert.equal(first.frozen, second.frozen);
		assert.equal(second.options.spamCutoff, 0.95);
		assert.ok(first.metadata.trainedOn.length > 0);
		first.learn(['only-in-first'], 'spam');
		assert.equal(second.nspam, first.nspam - 1);
	});

	it('saves and reloads models, reading a file again after it is saved', () => {
		const file = path.join(temporaryDirectory(), 'nested', 'model.json');
		saveModel(trained(), file, {metadata: {note: 'test'}});
		assert.ok(existsSync(file));
		const loaded = loadModel(file);
		assert.equal(loaded.metadata.note, 'test');
		assert.equal(loaded.classify(['prize']).probability > 0.5, true);
		const more = trained();
		more.learn(['third'], 'spam');
		saveModel(more, file);
		assert.equal(loadModel(file).nspam, 2);
		assert.equal(JSON.parse(readFileSync(file, 'utf8')).type, 'spamscanner-classifier');
	});

	it('uses the model embedded in a standalone binary', () => {
		const json = JSON.stringify(trained().toJSON());
		assert.equal(embeddedModel(fakeSea(json)), json);
		assert.equal(embeddedModel(fakeSea()), null);
		assert.equal(embeddedModel(fakeSea(new Error('no asset'))), null);
		assert.equal(embeddedModel(null), null);
		assert.equal(embeddedModel(), null);
		const fromBinary = loadDefaultModel({}, {file: null, sea: fakeSea(json)});
		assert.equal(fromBinary.nspam, 1);
		assert.equal(loadDefaultModel({hamCutoff: 0.1}, {file: null, sea: fakeSea(json)}).options.hamCutoff, 0.1);
		const empty = loadDefaultModel({}, {file: null, sea: fakeSea()});
		assert.equal(empty.nspam, 0);
		assert.equal(loadSea(() => {
			throw new Error('No such built-in module: node:sea');
		}), null);
		assert.equal(typeof loadSea(name => ({name})).name, 'string');
	});

	it('rejects a broken model file', () => {
		const file = path.join(temporaryDirectory(), 'broken.json');
		writeFileSync(file, '{"type":"something-else"}');
		assert.throws(() => loadModel(file), /Not a Spam Scanner classifier model/);
	});
});

describe('recommended models', () => {
	it('lists open models with an Ollama tag, a Hugging Face repository and a license', () => {
		assert.ok(RECOMMENDED_MODELS.some(model => model.ollama === PROVIDERS.ollama.model), 'the default Ollama model is recommended');
		for (const model of [...RECOMMENDED_MODELS, ...CLASSIFIER_MODELS]) {
			assert.match(model.huggingface, /^[\w.-]+\/[\w.-]+$/);
			assert.match(model.license, /^(?:Apache-2\.0|MIT)$/);
		}

		for (const model of RECOMMENDED_MODELS) {
			assert.match(model.ollama, /^[\w.-]+:[\w.]+$/);
			assert.match(model.size, /^\d+(?:\.\d)? GB$/);
		}

		assert.match(VERSION, /^\d+\.\d+\.\d+/);
	});

	it('lists hosted decision models that have a provider preset', () => {
		for (const model of DECISION_MODELS) {
			assert.equal(PROVIDERS[model.provider].api, 'decision', model.provider);
			assert.equal(PROVIDERS[model.provider].name, model.name);
			assert.ok(model.weights === null || /^[\w.-]+\/[\w.-]+$/.test(model.weights));
			assert.ok(model.notes.length > 20);
		}
	});
});
