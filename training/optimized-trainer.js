#!/usr/bin/env node
/**
 * Optimized Classifier Training Script for Enron Dataset
 * Modern ES modules version with enhanced features
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import NaiveBayes from '@ladjs/naivebayes';
import SpamScanner from '../spamscanner-fresh/src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const VOCABULARY_LIMIT = 20_000;
const BATCH_SIZE = 1000;
const HASH_TOKENS = true; // Enable token hashing for privacy

class OptimizedTrainer {
	constructor(options = {}) {
		this.vocabularyLimit = options.vocabularyLimit || VOCABULARY_LIMIT;
		this.batchSize = options.batchSize || BATCH_SIZE;
		this.hashTokens = options.hashTokens !== false;
		this.verbose = options.verbose !== false;

		// Initialize classifier
		this.classifier = new NaiveBayes({
			tokenizer: this.tokenizer.bind(this),
			vocabularyLimit: this.vocabularyLimit,
		});

		// Initialize scanner
		this.scanner = new SpamScanner({
			classifier: true,
		});

		// Training statistics
		this.stats = {
			totalEmails: 0,
			hamEmails: 0,
			spamEmails: 0,
			totalTokens: 0,
			uniqueTokens: 0,
			startTime: null,
			endTime: null,
		};
	}

	tokenizer(tokens) {
		if (this.hashTokens) {
			return tokens.map(token => createHash('sha256').update(token).digest('hex').slice(0, 16));
		}

		return tokens;
	}

	async loadDataset(datasetPath) {
		if (this.verbose) {
			console.log(`Loading dataset from ${datasetPath}...`);
		}

		const data = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));

		if (this.verbose) {
			console.log(`Loaded ${data.length} emails`);
		}

		return data;
	}

	async processEmail(email) {
		try {
			// Combine subject and message
			const subject = email.subject || '';
			const message = email.message || '';
			const fullText = `Subject: ${subject}\n\n${message}`;

			// Create mail object for scanner
			const mail = {
				text: fullText,
				subject,
				html: message,
			};

			// Get tokens using scanner
			const tokens = await this.scanner.getTokens(fullText, 'en');

			if (tokens.length === 0) {
				return null;
			}

			// Apply ham bias (double ham tokens to reduce false positives)
			if (email.label === 0) { // Ham
				const originalLength = tokens.length;
				for (let i = 0; i < originalLength; i++) {
					tokens.push(tokens[i]);
				}
			}

			return {
				tokens,
				label: email.label === 0 ? 'ham' : 'spam',
				id: email.id,
			};
		} catch (error) {
			if (this.verbose) {
				console.error(`Error processing email ${email.id}:`, error.message);
			}

			return null;
		}
	}

	async trainBatch(emails) {
		const processed = [];

		for (const email of emails) {
			const result = await this.processEmail(email);
			if (result) {
				processed.push(result);
			}
		}

		// Train classifier with batch
		for (const item of processed) {
			this.classifier.learn(item.tokens, item.label);

			// Update statistics
			this.stats.totalTokens += item.tokens.length;
			if (item.label === 'ham') {
				this.stats.hamEmails++;
			} else {
				this.stats.spamEmails++;
			}
		}

		return processed.length;
	}

	async train(datasetPath, outputPath = './classifier.json') {
		this.stats.startTime = Date.now();

		if (this.verbose) {
			console.log('🚀 Starting optimized classifier training...');
			console.log('📊 Configuration:');
			console.log(`   - Vocabulary limit: ${this.vocabularyLimit}`);
			console.log(`   - Batch size: ${this.batchSize}`);
			console.log(`   - Token hashing: ${this.hashTokens ? 'enabled' : 'disabled'}`);
		}

		// Load dataset
		const emails = await this.loadDataset(datasetPath);
		this.stats.totalEmails = emails.length;

		// Process in batches
		const totalBatches = Math.ceil(emails.length / this.batchSize);
		let processedEmails = 0;

		for (let i = 0; i < totalBatches; i++) {
			const start = i * this.batchSize;
			const end = Math.min(start + this.batchSize, emails.length);
			const batch = emails.slice(start, end);

			const batchProcessed = await this.trainBatch(batch);
			processedEmails += batchProcessed;

			if (this.verbose) {
				const progress = ((i + 1) / totalBatches * 100).toFixed(1);
				console.log(`📈 Batch ${i + 1}/${totalBatches} (${progress}%) - Processed: ${batchProcessed}/${batch.length} emails`);
			}
		}

		// Calculate final statistics
		this.stats.endTime = Date.now();
		this.stats.uniqueTokens = Object.keys(this.classifier.vocabulary).length;

		// Save classifier
		if (this.verbose) {
			console.log('💾 Saving classifier...');
		}

		const classifierJson = this.classifier.toJson();
		fs.writeFileSync(outputPath, classifierJson);

		// Save training metadata
		const metadataPath = outputPath.replace('.json', '_metadata.json');
		const metadata = {
			...this.stats,
			trainingDuration: this.stats.endTime - this.stats.startTime,
			hashTokens: this.hashTokens,
			vocabularyLimit: this.vocabularyLimit,
			version: '6.0.0-optimized',
			timestamp: new Date().toISOString(),
		};

		fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));

		if (this.verbose) {
			this.printSummary(outputPath, metadataPath);
		}

		return {
			classifierPath: outputPath,
			metadataPath,
			stats: this.stats,
		};
	}

	printSummary(classifierPath, metadataPath) {
		const duration = (this.stats.endTime - this.stats.startTime) / 1000;
		const emailsPerSecond = (this.stats.totalEmails / duration).toFixed(1);

		console.log('\n🎉 Training completed successfully!');
		console.log('📊 Training Summary:');
		console.log(`   - Total emails: ${this.stats.totalEmails}`);
		console.log(`   - Ham emails: ${this.stats.hamEmails}`);
		console.log(`   - Spam emails: ${this.stats.spamEmails}`);
		console.log(`   - Total tokens: ${this.stats.totalTokens.toLocaleString()}`);
		console.log(`   - Unique tokens: ${this.stats.uniqueTokens.toLocaleString()}`);
		console.log(`   - Training time: ${duration.toFixed(2)} seconds`);
		console.log(`   - Processing speed: ${emailsPerSecond} emails/second`);
		console.log(`   - Token hashing: ${this.hashTokens ? 'enabled' : 'disabled'}`);
		console.log('\n📁 Output files:');
		console.log(`   - Classifier: ${classifierPath}`);
		console.log(`   - Metadata: ${metadataPath}`);

		// File sizes
		const classifierSize = (fs.statSync(classifierPath).size / 1024 / 1024).toFixed(2);
		console.log(`   - Classifier size: ${classifierSize} MB`);
	}

	async validateClassifier(testEmails = 100) {
		if (this.verbose) {
			console.log(`\n🧪 Running validation with ${testEmails} emails...`);
		}

		// This would implement cross-validation
		// For now, just return basic stats
		return {
			accuracy: 'Not implemented yet',
			precision: 'Not implemented yet',
			recall: 'Not implemented yet',
		};
	}
}

// CLI interface
async function main() {
	const datasetPath = process.argv[2] || './enron_dataset.json';
	const outputPath = process.argv[3] || './classifier.json';

	if (!fs.existsSync(datasetPath)) {
		console.error(`❌ Dataset file not found: ${datasetPath}`);
		console.log('Usage: node optimized_trainer.js <dataset.json> [output.json]');
		process.exit(1);
	}

	try {
		const trainer = new OptimizedTrainer({
			vocabularyLimit: 20_000,
			batchSize: 1000,
			hashTokens: true,
			verbose: true,
		});

		const result = await trainer.train(datasetPath, outputPath);

		console.log('\n✅ Training pipeline completed successfully!');
	} catch (error) {
		console.error('❌ Training failed:', error);
		process.exit(1);
	}
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
	main();
}

export default OptimizedTrainer;

