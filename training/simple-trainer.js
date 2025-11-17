#!/usr/bin/env node
/**
 * Simple Classifier Training Script
 * Uses smaller batches and simpler processing to avoid memory issues
 */

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import NaiveBayes from '@ladjs/naivebayes';
import SpamScanner from '../spamscanner-fresh/src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Simple training with smaller batches
async function trainSimple() {
	console.log('🚀 Starting simple classifier training...');

	// Load dataset
	const data = JSON.parse(fs.readFileSync('./enron_dataset.json', 'utf8'));
	console.log(`📊 Loaded ${data.length} emails`);

	// Initialize classifier with configurable hashing
	const useHashing = process.env.HASH_TOKENS !== 'false';
	const classifier = new NaiveBayes({
		tokenizer: useHashing
			? tokens => tokens.map(token =>
				createHash('sha256').update(token).digest('hex').slice(0, 16))
			: tokens => tokens,
		vocabularyLimit: 20_000, // Increased vocabulary limit
	});

	// Initialize scanner
	const scanner = new SpamScanner({classifier: true});

	let processed = 0;
	let hamCount = 0;
	let spamCount = 0;

	// Process emails in smaller chunks
	const chunkSize = 100;
	for (let i = 0; i < data.length; i += chunkSize) {
		const chunk = data.slice(i, i + chunkSize);

		for (const email of chunk) {
			try {
				// Simple text processing
				const text = `${email.subject || ''} ${email.message || ''}`.trim();
				if (!text) {
					continue;
				}

				// Get tokens with simpler approach
				const tokens = text
					.toLowerCase()
					.replaceAll(/[^a-z\d\s]/g, ' ')
					.split(/\s+/)
					.filter(token => token.length > 2 && token.length < 20);

				if (tokens.length === 0) {
					continue;
				}

				const label = email.label === 0 ? 'ham' : 'spam';

				// Apply ham bias
				if (label === 'ham') {
					const originalLength = tokens.length;
					for (let j = 0; j < originalLength; j++) {
						tokens.push(tokens[j]);
					}

					hamCount++;
				} else {
					spamCount++;
				}

				classifier.learn(tokens, label);
				processed++;
			} catch (error) {
				console.error(`Error processing email ${email.id}:`, error.message);
			}
		}

		// Progress update
		const progress = ((i + chunkSize) / data.length * 100).toFixed(1);
		console.log(`📈 Progress: ${progress}% - Processed: ${processed} emails (${hamCount} ham, ${spamCount} spam)`);
	}

	// Save classifier
	console.log('💾 Saving classifier...');
	const classifierJson = classifier.toJson();
	fs.writeFileSync('./classifier.json', classifierJson);

	// Save metadata
	const metadata = {
		totalEmails: processed,
		hamEmails: hamCount,
		spamEmails: spamCount,
		vocabularySize: Object.keys(classifier.vocabulary).length,
		timestamp: new Date().toISOString(),
		version: 'simple-v1',
	};

	fs.writeFileSync('./classifier_metadata.json', JSON.stringify(metadata, null, 2));

	const size = (fs.statSync('./classifier.json').size / 1024 / 1024).toFixed(2);

	console.log('\n🎉 Training completed!');
	console.log('📊 Summary:');
	console.log(`   - Processed: ${processed} emails`);
	console.log(`   - Ham: ${hamCount}, Spam: ${spamCount}`);
	console.log(`   - Vocabulary: ${metadata.vocabularySize} tokens`);
	console.log(`   - File size: ${size} MB`);

	return './classifier.json';
}

// Run training
trainSimple().catch(console.error);

