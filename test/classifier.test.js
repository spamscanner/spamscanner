import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import {
	Classifier, MODEL_VERSION, chi2Q, hashFeature,
} from '../src/classifier.js';

function trained(options) {
	const classifier = new Classifier(options);
	for (let i = 0; i < 20; i++) {
		classifier.learn(['free', 'prize', 'winner', `spam${i}`], 'spam');
		classifier.learn(['meeting', 'report', 'thanks', `ham${i}`], 'ham');
	}

	return classifier;
}

describe('hashFeature and chi2Q', () => {
	it('hashes strings to stable 32-bit numbers', () => {
		assert.equal(hashFeature('free'), hashFeature('free'));
		assert.notEqual(hashFeature('free'), hashFeature('frее'));
		assert.ok(hashFeature('日本') >= 0 && hashFeature('日本') <= 0xFF_FF_FF_FF);
	});

	it('computes the chi-squared upper tail', () => {
		assert.ok(Math.abs(chi2Q(2, 2) - Math.exp(-1)) < 1e-12);
		assert.equal(chi2Q(0, 4), 1);
		assert.ok(chi2Q(100, 4) < 1e-10);
	});
});

describe('Classifier', () => {
	it('separates spam from ham and explains why', () => {
		const classifier = trained();
		const spam = classifier.classify(['free', 'prize', 'winner']);
		assert.equal(spam.category, 'spam');
		assert.ok(spam.probability > 0.9);
		assert.equal(spam.clues[0].probability > 0.5, true);
		const ham = classifier.classify(['meeting', 'report', 'thanks']);
		assert.equal(ham.category, 'ham');
		assert.ok(ham.probability < 0.2);
	});

	it('is unsure about unknown, mixed or neutral words, and before it has learned both classes', () => {
		const classifier = trained();
		assert.equal(classifier.classify(['never', 'seen']).category, 'unsure');
		assert.equal(classifier.classify(['free', 'meeting']).category, 'unsure');
		assert.equal(new Classifier().classify(['free']).category, 'unsure');
		const lonely = new Classifier();
		lonely.learn(['free'], 'spam');
		assert.equal(lonely.classify(['free']).category, 'unsure');
	});

	it('gives a feature probability by Robinson\'s method', () => {
		const classifier = trained();
		assert.equal(classifier.probability('unknown-word'), 0.5);
		assert.ok(classifier.probability('free') > 0.95);
		assert.ok(classifier.probability('meeting') < 0.05);
	});

	it('rejects unknown categories', () => {
		assert.throws(() => new Classifier().learn(['x'], 'maybe'), /spam" or "ham/);
	});

	it('unlearns, never going below zero', () => {
		const classifier = new Classifier();
		classifier.learn(['a'], 'spam');
		classifier.unlearn(['a'], 'spam');
		classifier.unlearn(['a', 'b'], 'spam');
		classifier.unlearn(['a'], 'ham');
		assert.equal(classifier.nspam, 0);
		assert.equal(classifier.nham, 0);
		assert.equal(classifier.probability('a'), 0.5);
	});

	it('honours custom cutoffs and clue limits', () => {
		const classifier = trained({spamCutoff: 0.999_999, maxClues: 1});
		const result = classifier.classify(['free', 'prize', 'winner']);
		assert.equal(result.clues.length, 1);
		assert.equal(result.category, 'unsure');
	});

	it('round-trips through JSON, keeping options and metadata', () => {
		const classifier = trained({strength: 0.5});
		const json = classifier.toJSON({metadata: {source: 'test'}});
		assert.equal(json.type, 'spamscanner-classifier');
		assert.equal(json.version, MODEL_VERSION);
		const copy = Classifier.fromJSON(JSON.stringify(json));
		assert.deepEqual(copy.metadata, {source: 'test'});
		assert.equal(copy.options.strength, 0.5);
		assert.equal(copy.size, classifier.size);
		for (const word of ['free', 'meeting', 'spam3', 'missing']) {
			assert.equal(copy.probability(word), classifier.probability(word));
		}

		assert.equal(Classifier.fromJSON(classifier.toJSON()).metadata, null);
		assert.equal(Classifier.fromJSON(json, {spamCutoff: 0.5}).options.spamCutoff, 0.5);
	});

	it('drops rare features and keeps the most frequent when asked', () => {
		const classifier = trained();
		assert.equal(classifier.toJSON({minCount: 2}).features, 6);
		assert.equal(classifier.toJSON({maxFeatures: 3}).features, 3);
	});

	it('keeps learning on top of a loaded model without changing the model', () => {
		const base = Classifier.fromJSON(trained().toJSON());
		const before = base.probability('free');
		base.learn(['free', 'newword'], 'ham');
		base.learn(['newword'], 'ham');
		assert.ok(base.probability('free') < before);
		assert.equal(base.size, 47);
		const again = Classifier.fromJSON(base.toJSON());
		assert.equal(again.probability('free'), base.probability('free'));
		assert.equal(again.probability('newword'), base.probability('newword'));
	});

	it('merges two classifiers', () => {
		const a = trained();
		const b = new Classifier();
		b.learn(['free', 'other'], 'ham');
		a.merge(Classifier.fromJSON(b.toJSON()));
		assert.equal(a.nham, 21);
		assert.ok(a.probability('other') < 0.5);
		const frozen = Classifier.fromJSON(trained().toJSON());
		frozen.merge(b);
		assert.equal(frozen.nham, 21);
	});

	it('rejects files that are not models', () => {
		assert.throws(() => Classifier.fromJSON({type: 'other'}), /Not a Spam Scanner classifier/);
		assert.throws(() => Classifier.fromJSON(null), /Not a Spam Scanner classifier/);
		assert.throws(() => Classifier.fromJSON({type: 'spamscanner-classifier', version: 1}), /Unsupported classifier model version 1/);
		const json = trained().toJSON();
		assert.throws(() => Classifier.fromJSON({...json, spam: Buffer.alloc(4).toString('base64')}), /Corrupt classifier model/);
	});

	it('sorts clues of equal strength by name, so results are stable', () => {
		const classifier = new Classifier();
		classifier.learn(['b', 'a'], 'spam');
		classifier.learn(['c'], 'ham');
		const {clues} = classifier.classify(['b', 'a']);
		assert.deepEqual(clues.map(clue => clue.feature), ['a', 'b']);
	});

	it('is less sure about languages it has seen little spam or ham in', () => {
		const classifier = new Classifier({minLanguageExamples: 10});
		for (let i = 0; i < 100; i++) {
			classifier.learn(['lang:en', 'script:Latin', 'prize', `spam${i}`], 'spam');
			classifier.learn(['lang:en', 'script:Latin', 'meeting', `ham${i}`], 'ham');
		}

		// Arabic seen only in spam: its words say spam, but nothing says what
		// Arabic ham looks like, so the result stays unsure.
		for (let i = 0; i < 20; i++) {
			classifier.learn(['lang:ar', 'script:Arabic', 'في'], 'spam');
		}

		const english = classifier.classify(['lang:en', 'script:Latin', 'prize']);
		assert.equal(english.category, 'spam');
		assert.deepEqual(english.coverage, {
			feature: 'lang:en', spam: 100, ham: 100, confidence: 1,
		});
		assert.ok(english.clues.every(clue => !clue.feature.startsWith('lang:')));
		const arabic = classifier.classify(['lang:ar', 'script:Arabic', 'في']);
		assert.equal(arabic.probability, 0.5);
		assert.equal(arabic.category, 'unsure');
		assert.equal(arabic.coverage.confidence, 0);
		// Without a language, the script decides; mixed scripts remain a clue.
		classifier.learn(['script:mixed', 'prize'], 'spam');
		const mixed = classifier.classify(['script:Latin', 'script:mixed', 'prize']);
		assert.equal(mixed.coverage.feature, 'script:Latin');
		assert.ok(mixed.clues.some(clue => clue.feature === 'script:mixed'));
		assert.equal(classifier.classify(['prize']).coverage.feature, null);
		// A small classifier needs only a share of its examples per language.
		const small = new Classifier();
		small.learn(['lang:fr', 'gratuit'], 'spam');
		small.learn(['lang:fr', 'réunion'], 'ham');
		assert.equal(small.classify(['lang:fr', 'gratuit']).coverage.confidence, 1);
		assert.equal(Classifier.fromJSON(classifier.toJSON()).options.minLanguageExamples, 10);
	});
});
