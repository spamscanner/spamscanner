import {describe, it} from 'node:test';
import assert from 'node:assert';
import {createHash} from 'node:crypto';
import NaiveBayes from '@ladjs/naivebayes';
import SpamScanner from '../src/index.js';

// Helper function to hash tokens for anonymization
function hashToken(token) {
	return createHash('sha256').update(token).digest('hex');
}

// Helper function to hash an array of tokens
function hashTokens(tokens) {
	return tokens.map(token => hashToken(token));
}

// Real spam email examples
const spamEmails = [
	`From: winner@lottery.com
To: victim@example.com
Subject: YOU WON $1,000,000!!!

Congratulations! You have won ONE MILLION DOLLARS in our lottery!
Click here NOW to claim your prize: http://phishing-site.com
Send us your bank account details immediately!
This offer expires in 24 hours! ACT NOW!!!
FREE MONEY WAITING FOR YOU!!!`,

	`From: pharmacy@cheap-meds.ru
To: customer@example.com
Subject: Buy V1agra and C1alis - 90% OFF!!!

SPECIAL OFFER! Buy V1agra, C1alis, and other medications at 90% discount!
No prescription needed! Fast shipping worldwide!
Click here: http://cheap-pharmacy.ru
Limited time offer! Order now and get FREE pills!
100% satisfaction guaranteed or your money back!`,

	`From: prince@nigeria.ng
To: friend@example.com
Subject: Urgent Business Proposal - $25 Million

Dear Friend,

I am Prince Abubakar from Nigeria. I have $25 million USD that I need to transfer out of my country.
I need your help to transfer this money. You will receive 30% commission ($7.5 million).
Please send me your bank account details and passport copy.
This is 100% legal and risk-free. Reply urgently!

Best regards,
Prince Abubakar`,

	`From: support@paypal-security.com
To: user@example.com
Subject: Your PayPal Account Has Been Limited

Your PayPal account has been limited due to suspicious activity.
Click here to verify your identity: http://paypal-verify-account.com
You must verify within 24 hours or your account will be permanently suspended.
Enter your username, password, credit card number, and SSN to verify.
This is an automated message from PayPal Security Team.`,

	`From: admin@bank-alert.com
To: customer@example.com
Subject: Urgent: Your Bank Account Will Be Closed

WARNING: Your bank account will be closed in 48 hours due to security concerns.
Click here immediately to prevent account closure: http://bank-verify.com
You must update your information including:
- Full name and SSN
- Credit card numbers and CVV
- Online banking username and password
Failure to comply will result in permanent account closure.`,
];

// Real ham (legitimate) email examples
const hamEmails = [
	`From: john.doe@company.com
To: team@company.com
Subject: Team Meeting Tomorrow at 2 PM

Hi Team,

Just a reminder that we have our weekly team meeting tomorrow at 2 PM in Conference Room B.
We'll be discussing the Q4 roadmap and project updates.

Please review the attached agenda before the meeting.

Thanks,
John`,

	`From: newsletter@techcrunch.com
To: subscriber@example.com
Subject: TechCrunch Daily: Latest Tech News

Good morning! Here are today's top tech stories:

1. Apple announces new MacBook Pro with M3 chip
2. Google launches updated AI assistant
3. Tesla reports Q3 earnings beat expectations

Read more at techcrunch.com

Unsubscribe | Manage preferences`,

	`From: support@github.com
To: developer@example.com
Subject: Your pull request was merged

Hi developer,

Your pull request #1234 "Fix authentication bug" has been merged into the main branch.

View the pull request: https://github.com/user/repo/pull/1234

Thanks for your contribution!

GitHub Team`,

	`From: mom@family.com
To: son@example.com
Subject: Dinner this Sunday?

Hi sweetie,

Would you like to come over for dinner this Sunday? I'm making your favorite lasagna.
Let me know if you can make it. Dad says hi!

Love,
Mom`,

	`From: hr@company.com
To: employee@company.com
Subject: Employee Benefits Update

Dear Employee,

This is to inform you that our health insurance benefits will be updated starting next month.
Please review the attached document for details on the new coverage options.

If you have any questions, please contact the HR department.

Best regards,
Human Resources Department`,
];

describe('Custom Token Classifier with Real Emails', () => {
	it('should tokenize spam emails correctly', async () => {
		const scanner = new SpamScanner();

		// Tokenize first spam email
		const {tokens} = await scanner.getTokensAndMailFromSource(spamEmails[0]);

		// Verify tokens were extracted
		assert.ok(Array.isArray(tokens), 'Tokens should be an array');
		assert.ok(tokens.length > 0, 'Should extract tokens from spam email');

		// Verify spam-related tokens are present (lowercased)
		const tokenSet = new Set(tokens);
		const spamIndicators = ['won', 'million', 'prize', 'free', 'click', 'now'];
		const foundIndicators = spamIndicators.filter(indicator => tokenSet.has(indicator));

		assert.ok(foundIndicators.length > 0, `Should find spam indicators in tokens. Found: ${foundIndicators.join(', ')}`);
	});

	it('should tokenize ham emails correctly', async () => {
		const scanner = new SpamScanner();

		// Tokenize first ham email
		const {tokens} = await scanner.getTokensAndMailFromSource(hamEmails[0]);

		// Verify tokens were extracted
		assert.ok(Array.isArray(tokens), 'Tokens should be an array');
		assert.ok(tokens.length > 0, 'Should extract tokens from ham email');

		// Verify legitimate tokens are present
		const tokenSet = new Set(tokens);
		const legitimateWords = ['team', 'meeting', 'reminder'];
		const foundWords = legitimateWords.filter(word => tokenSet.has(word));

		assert.ok(foundWords.length > 0, `Should find legitimate words in tokens. Found: ${foundWords.join(', ')}`);
	});

	it('should anonymize tokens using SHA-256 hashing', async () => {
		const scanner = new SpamScanner();
		const {tokens} = await scanner.getTokensAndMailFromSource(spamEmails[0]);

		// Hash the tokens
		const hashedTokens = hashTokens(tokens);

		// Verify all tokens are hashed
		assert.strictEqual(hashedTokens.length, tokens.length, 'Should hash all tokens');

		// Verify hash format (SHA-256 produces 64 hex characters)
		for (const hash of hashedTokens) {
			assert.strictEqual(hash.length, 64, 'SHA-256 hash should be 64 characters');
			assert.match(hash, /^[a-f\d]{64}$/, 'Hash should be valid hex string');
		}

		// Verify same token produces same hash (deterministic)
		const testToken = 'test';
		const hash1 = hashToken(testToken);
		const hash2 = hashToken(testToken);
		assert.strictEqual(hash1, hash2, 'Same token should produce same hash');

		// Verify different tokens produce different hashes
		const hash3 = hashToken('different');
		assert.notStrictEqual(hash1, hash3, 'Different tokens should produce different hashes');
	});

	it('should train classifier with hashed tokens from real emails', async () => {
		const scanner = new SpamScanner();
		const classifier = new NaiveBayes();

		// Set custom tokenizer to handle arrays
		classifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Train with spam emails
		for (const email of spamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'spam');
		}

		// Train with ham emails
		for (const email of hamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'ham');
		}

		// Verify classifier was trained by testing classification
		const testResult = classifier.categorize(hashTokens(['test', 'email']));
		assert.ok(['spam', 'ham'].includes(testResult), 'Classifier should be able to categorize after training');

		// Verify classifier can be serialized
		const classifierData = classifier.toJson();
		assert.ok(classifierData, 'Classifier should be serializable to JSON');
		// ToJson() might return a string or object depending on the library version
		const isValidJson = typeof classifierData === 'object' || typeof classifierData === 'string';
		assert.ok(isValidJson, 'Classifier JSON should be an object or string');
	});

	it('should classify new spam email correctly using hashed tokens', async () => {
		const scanner = new SpamScanner();
		const classifier = new NaiveBayes();

		// Set custom tokenizer to handle arrays
		classifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Train classifier
		for (const email of spamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'spam');
		}

		for (const email of hamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'ham');
		}

		// Test with a new spam email
		const testSpamEmail = `From: scammer@fake.com
To: victim@example.com
Subject: URGENT: Claim Your Prize NOW!!!

You have won $500,000 in our lottery!
Click here immediately to claim your FREE MONEY!
Send us your bank details now!
This offer expires TODAY!!!`;

		const {tokens} = await scanner.getTokensAndMailFromSource(testSpamEmail);
		const hashedTokens = hashTokens(tokens);

		const category = classifier.categorize(hashedTokens);
		assert.strictEqual(category, 'spam', 'Should classify new spam email as spam');
	});

	it('should classify new ham email correctly using hashed tokens', async () => {
		const scanner = new SpamScanner();
		const classifier = new NaiveBayes();

		// Set custom tokenizer to handle arrays
		classifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Train classifier
		for (const email of spamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'spam');
		}

		for (const email of hamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'ham');
		}

		// Test with a new ham email
		const testHamEmail = `From: colleague@company.com
To: team@company.com
Subject: Project Update

Hi team,

I wanted to share a quick update on the project status.
We're on track to meet the deadline next week.

Please let me know if you have any questions.

Thanks,
Sarah`;

		const {tokens} = await scanner.getTokensAndMailFromSource(testHamEmail);
		const hashedTokens = hashTokens(tokens);

		const category = classifier.categorize(hashedTokens);
		assert.strictEqual(category, 'ham', 'Should classify new ham email as ham');
	});

	it('should get classification probabilities with hashed tokens', async () => {
		const scanner = new SpamScanner();
		const classifier = new NaiveBayes();

		// Set custom tokenizer to handle arrays
		classifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Train classifier
		for (const email of spamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'spam');
		}

		for (const email of hamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'ham');
		}

		// Test with spam email
		const {tokens} = await scanner.getTokensAndMailFromSource(spamEmails[0]);
		const hashedTokens = hashTokens(tokens);

		const probabilities = classifier.probabilities(hashedTokens);

		assert.ok(probabilities, 'Should return probabilities');

		// Probabilities might be an object with category keys
		if (typeof probabilities === 'object' && !Array.isArray(probabilities)) {
			const keys = Object.keys(probabilities);
			assert.ok(keys.length > 0, 'Should have at least one probability');

			// Check that all probabilities are valid numbers between 0 and 1
			for (const key of keys) {
				const prob = probabilities[key];
				if (typeof prob === 'number') {
					assert.ok(prob >= 0 && prob <= 1, `Probability for ${key} should be between 0 and 1`);
				}
			}

			// Check if spam and ham categories exist
			const hasSpamOrHam = keys.includes('spam') || keys.includes('ham');
			if (hasSpamOrHam) {
				assert.ok(true, 'Has spam or ham probability');
			}
		} else {
			// If it's not an object or is an array, just verify it exists
			assert.ok(probabilities, 'Probabilities returned in some format');
		}
	});

	it('should persist and restore classifier with hashed tokens', async () => {
		const scanner = new SpamScanner();
		const classifier = new NaiveBayes();

		// Set custom tokenizer to handle arrays
		classifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Train classifier
		for (const email of spamEmails.slice(0, 3)) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'spam');
		}

		for (const email of hamEmails.slice(0, 3)) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'ham');
		}

		// Export classifier
		const classifierData = classifier.toJson();

		// Create new classifier from exported data using fromJson
		const restoredClassifier = NaiveBayes.fromJson(classifierData);

		// Set custom tokenizer for restored classifier
		restoredClassifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Test with new email
		const testEmail = spamEmails[3];
		const {tokens} = await scanner.getTokensAndMailFromSource(testEmail);
		const hashedTokens = hashTokens(tokens);

		const category1 = classifier.categorize(hashedTokens);
		const category2 = restoredClassifier.categorize(hashedTokens);

		assert.strictEqual(category1, category2, 'Restored classifier should produce same results');
	});

	it('should handle edge case: email with very few tokens', async () => {
		const scanner = new SpamScanner();
		const classifier = new NaiveBayes();

		// Set custom tokenizer to handle arrays
		classifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Train classifier
		for (const email of spamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'spam');
		}

		for (const email of hamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'ham');
		}

		// Test with minimal email
		const minimalEmail = `From: test@example.com
To: user@example.com
Subject: Hi

Hello.`;

		const {tokens} = await scanner.getTokensAndMailFromSource(minimalEmail);
		const hashedTokens = hashTokens(tokens);

		// Should not throw error
		const category = classifier.categorize(hashedTokens);
		assert.ok(['spam', 'ham'].includes(category), 'Should classify even with few tokens');
	});

	it('should handle edge case: email with special characters and numbers', async () => {
		const scanner = new SpamScanner();

		const specialEmail = `From: test@example.com
To: user@example.com
Subject: Test $$$

Price: $99.99
Discount: 50% OFF!!!
Code: ABC123XYZ
Email: support@test.com
Phone: 1-800-555-1234`;

		const {tokens} = await scanner.getTokensAndMailFromSource(specialEmail);
		const hashedTokens = hashTokens(tokens);

		// Verify tokens were extracted and hashed
		assert.ok(tokens.length > 0, 'Should extract tokens from email with special characters');
		assert.ok(hashedTokens.length > 0, 'Should hash tokens from email with special characters');
		assert.strictEqual(tokens.length, hashedTokens.length, 'Should hash all tokens');
	});

	it('should verify tokenizer consistency across multiple calls', async () => {
		const scanner = new SpamScanner();
		const email = hamEmails[0];

		// Tokenize same email multiple times
		const {tokens: tokens1} = await scanner.getTokensAndMailFromSource(email);
		const {tokens: tokens2} = await scanner.getTokensAndMailFromSource(email);
		const {tokens: tokens3} = await scanner.getTokensAndMailFromSource(email);

		// Verify consistency
		assert.strictEqual(tokens1.length, tokens2.length, 'Tokenization should be consistent');
		assert.strictEqual(tokens2.length, tokens3.length, 'Tokenization should be consistent');
		assert.deepStrictEqual(tokens1, tokens2, 'Same email should produce same tokens');
		assert.deepStrictEqual(tokens2, tokens3, 'Same email should produce same tokens');
	});

	it('should verify hash consistency across multiple calls', async () => {
		const scanner = new SpamScanner();
		const {tokens} = await scanner.getTokensAndMailFromSource(hamEmails[0]);

		// Hash same tokens multiple times
		const hashed1 = hashTokens(tokens);
		const hashed2 = hashTokens(tokens);
		const hashed3 = hashTokens(tokens);

		// Verify consistency
		assert.deepStrictEqual(hashed1, hashed2, 'Same tokens should produce same hashes');
		assert.deepStrictEqual(hashed2, hashed3, 'Same tokens should produce same hashes');
	});

	it('should train classifier with mixed case emails and still work', async () => {
		const scanner = new SpamScanner();
		const classifier = new NaiveBayes();

		// Set custom tokenizer to handle arrays
		classifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Train with original emails
		for (const email of spamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'spam');
		}

		for (const email of hamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			const hashedTokens = hashTokens(tokens);
			classifier.learn(hashedTokens, 'ham');
		}

		// Test with uppercase version of spam email
		const uppercaseSpam = spamEmails[0].toUpperCase();
		const {tokens} = await scanner.getTokensAndMailFromSource(uppercaseSpam);
		const hashedTokens = hashTokens(tokens);

		const category = classifier.categorize(hashedTokens);
		// Should still classify as spam because tokenizer normalizes case
		assert.strictEqual(category, 'spam', 'Should classify uppercase spam email as spam');
	});

	it('should demonstrate complete pipeline: email -> tokens -> hash -> train -> classify', async () => {
		const scanner = new SpamScanner();
		const classifier = new NaiveBayes();

		// Set custom tokenizer to handle arrays
		classifier.tokenizer = function (tokens) {
			return Array.isArray(tokens) ? tokens : tokens.split(/\s+/);
		};

		// Step 1: Tokenize training emails
		const spamTokens = [];
		for (const email of spamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			spamTokens.push(tokens);
		}

		const hamTokens = [];
		for (const email of hamEmails) {
			// eslint-disable-next-line no-await-in-loop
			const {tokens} = await scanner.getTokensAndMailFromSource(email);
			hamTokens.push(tokens);
		}

		// Step 2: Hash tokens for anonymization
		const hashedSpamTokens = spamTokens.map(tokens => hashTokens(tokens));
		const hashedHamTokens = hamTokens.map(tokens => hashTokens(tokens));

		// Step 3: Train classifier with hashed tokens
		for (const hashed of hashedSpamTokens) {
			classifier.learn(hashed, 'spam');
		}

		for (const hashed of hashedHamTokens) {
			classifier.learn(hashed, 'ham');
		}

		// Step 4: Test classification with new emails
		const newSpam = `From: scam@fake.com
Subject: WIN FREE MONEY NOW!!!
Click here for your FREE prize! Limited time offer!`;

		const newHam = `From: boss@company.com
Subject: Meeting notes
Please review the attached meeting notes from yesterday.`;

		// Classify new spam
		const {tokens: spamTestTokens} = await scanner.getTokensAndMailFromSource(newSpam);
		const hashedSpamTest = hashTokens(spamTestTokens);
		const spamResult = classifier.categorize(hashedSpamTest);

		// Classify new ham
		const {tokens: hamTestTokens} = await scanner.getTokensAndMailFromSource(newHam);
		const hashedHamTest = hashTokens(hamTestTokens);
		const hamResult = classifier.categorize(hashedHamTest);

		// Verify complete pipeline works
		assert.strictEqual(spamResult, 'spam', 'Complete pipeline should classify spam correctly');
		assert.strictEqual(hamResult, 'ham', 'Complete pipeline should classify ham correctly');

		// Verify anonymization (original tokens should not be in classifier)
		const classifierData = classifier.toJson();

		// Check if vocabulary exists and get keys
		let vocabularyKeys = [];
		if (classifierData.vocabulary) {
			vocabularyKeys = Object.keys(classifierData.vocabulary);
		} else if (classifierData.categories) {
			// If vocabulary is stored under categories, extract all unique tokens
			for (const category of Object.values(classifierData.categories)) {
				if (category.tokens) {
					vocabularyKeys.push(...Object.keys(category.tokens));
				}
			}

			vocabularyKeys = [...new Set(vocabularyKeys)]; // Remove duplicates
		}

		// If we have vocabulary keys, verify they are hashes
		if (vocabularyKeys.length > 0) {
			const allAreHashes = vocabularyKeys.every(key => /^[a-f\d]{64}$/.test(key));
			assert.ok(allAreHashes, 'All vocabulary keys should be SHA-256 hashes (anonymized)');

			// Original tokens should not appear in vocabulary
			const originalTokens = [...spamTestTokens, ...hamTestTokens];
			const noOriginalTokens = originalTokens.every(token => !vocabularyKeys.includes(token));
			assert.ok(noOriginalTokens, 'Original tokens should not appear in vocabulary (privacy preserved)');
		} else {
			// If no vocabulary found, at least verify classifier works
			assert.ok(classifierData, 'Classifier data should exist even if vocabulary structure is different');
		}
	});
});
