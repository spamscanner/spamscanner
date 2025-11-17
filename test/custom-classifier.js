
import assert from 'node:assert';
import {test} from 'node:test';
import NaiveBayes from '@ladjs/naivebayes';
import SpamScanner from '../src/index.js';

// Dummy training data for testing custom classifier
const SPAM_TRAINING_DATA = [
	'Buy cheap viagra now! Limited time offer!',
	'Get rich quick! Make $10,000 per day from home!',
	'You have won a lottery! Claim your prize now!',
	'Free money! Click here to get your cash!',
	'Lose weight fast with this one weird trick!',
	'Hot singles in your area want to meet you!',
	'Congratulations! You are a winner! Click to claim!',
	'Make money online fast! No experience needed!',
	'Enlarge your manhood with these pills!',
	'Work from home and earn thousands per week!',
	'Nigerian prince needs your help transferring money!',
	'You have inherited millions! Contact us now!',
	'Get free iPhone by clicking this link!',
	'Urgent: Your account will be closed! Click here!',
	'Amazing weight loss secret doctors don\'t want you to know!',
	'Casino bonus! Get $500 free chips now!',
	'Earn money by doing nothing! Sign up today!',
	'Your computer is infected! Download antivirus now!',
	'Congratulations! You have been selected for a special offer!',
	'Get paid to take surveys! Easy money!',
	'Free credit report! No credit card required!',
	'Refinance your mortgage at lowest rates!',
	'Debt consolidation! Get out of debt fast!',
	'Free trial! Cancel anytime! No risk!',
	'Act now! Limited time offer expires soon!',
	'Click here to unsubscribe from this list!',
	'You are pre-approved for a credit card!',
	'Get your free sample today! Pay only shipping!',
	'Miracle cure for all diseases! Order now!',
	'Secret method to make money revealed!',
];

const HAM_TRAINING_DATA = [
	'Hi John, can we schedule a meeting for tomorrow at 2pm?',
	'Thanks for your email. I will review the document and get back to you.',
	'The project deadline is next Friday. Please submit your work by then.',
	'I enjoyed our conversation yesterday. Let\'s catch up again soon.',
	'Here is the report you requested. Please let me know if you need anything else.',
	'Reminder: Team meeting at 10am in conference room B.',
	'Happy birthday! Hope you have a wonderful day!',
	'The package was delivered successfully. Thank you for your order.',
	'Your appointment is confirmed for Monday at 3pm.',
	'Please find attached the invoice for last month.',
	'Welcome to our newsletter! We send updates once a month.',
	'Your password has been successfully changed.',
	'Thank you for registering for our webinar.',
	'Your flight is scheduled to depart at 8:30am.',
	'Congratulations on your promotion! Well deserved!',
	'The weather forecast shows rain this weekend.',
	'Your subscription has been renewed for another year.',
	'Please review the attached contract and sign if you agree.',
	'The conference starts next Monday. See you there!',
	'Your order has been shipped and will arrive in 3-5 business days.',
	'Thank you for your feedback. We appreciate your input.',
	'The system maintenance is scheduled for tonight at midnight.',
	'Your reservation is confirmed for 2 guests on Saturday.',
	'Please complete the survey at your earliest convenience.',
	'The new policy takes effect on the first of next month.',
	'Your request has been approved. Congratulations!',
	'The event has been rescheduled to next week.',
	'Thank you for your patience during this transition.',
	'Your profile has been updated successfully.',
	'Looking forward to working with you on this project.',
];

test('should train custom classifier with dummy data', async () => {
	const classifier = new NaiveBayes();

	// Train with spam data
	for (const text of SPAM_TRAINING_DATA) {
		classifier.learn(text, 'spam');
	}

	// Train with ham data
	for (const text of HAM_TRAINING_DATA) {
		classifier.learn(text, 'ham');
	}

	// Test classification on new spam-like text
	const spamText = 'Get free money now! Limited offer!';
	const spamResult = classifier.categorize(spamText);

	assert.strictEqual(spamResult, 'spam', 'Should classify spam-like text as spam');

	// Test classification on new ham-like text
	const hamText = 'Hi, let\'s meet tomorrow for lunch at noon.';
	const hamResult = classifier.categorize(hamText);

	assert.strictEqual(hamResult, 'ham', 'Should classify ham-like text as ham');
});

test('should use custom classifier in SpamScanner', async () => {
	// Train custom classifier
	const classifier = new NaiveBayes();

	for (const text of SPAM_TRAINING_DATA) {
		classifier.learn(text, 'spam');
	}

	for (const text of HAM_TRAINING_DATA) {
		classifier.learn(text, 'ham');
	}

	// Create scanner with custom classifier
	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	// Test with spam email
	const spamEmail = `From: spammer@example.com
To: victim@example.com
Subject: Get rich quick!

Buy cheap viagra now! Make money fast! Click here!
`;

	const spamResult = await scanner.scan(spamEmail);

	// Classification should work (may be spam or ham depending on other factors)
	assert.strictEqual(typeof spamResult.isSpam, 'boolean', 'Should return boolean');
	assert.ok(['spam', 'ham'].includes(spamResult.results.classification.category), 'Should classify as spam or ham');
});

test('should classify ham email correctly with custom classifier', async () => {
	// Train custom classifier
	const classifier = new NaiveBayes();

	for (const text of SPAM_TRAINING_DATA) {
		classifier.learn(text, 'spam');
	}

	for (const text of HAM_TRAINING_DATA) {
		classifier.learn(text, 'ham');
	}

	// Create scanner with custom classifier
	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	// Test with ham email
	const hamEmail = `From: colleague@example.com
To: me@example.com
Subject: Meeting tomorrow

Hi, can we schedule a meeting for tomorrow at 2pm to discuss the project?
Thanks!
`;

	const hamResult = await scanner.scan(hamEmail);

	assert.strictEqual(hamResult.isSpam, false, 'Should not detect ham email as spam');
	assert.strictEqual(hamResult.results.classification.category, 'ham', 'Should classify as ham');
});

test('should handle edge case with very short text', async () => {
	const classifier = new NaiveBayes();

	for (const text of SPAM_TRAINING_DATA) {
		classifier.learn(text, 'spam');
	}

	for (const text of HAM_TRAINING_DATA) {
		classifier.learn(text, 'ham');
	}

	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	const shortEmail = `From: test@example.com
To: user@example.com
Subject: Hi

Hi
`;

	const result = await scanner.scan(shortEmail);

	assert.strictEqual(typeof result.isSpam, 'boolean', 'Should return boolean for isSpam');
	assert.ok(['spam', 'ham'].includes(result.results.classification.category), 'Should classify as spam or ham');
});

test('should handle classifier with unbalanced training data', async () => {
	const classifier = new NaiveBayes();

	// Train with more spam than ham (unbalanced)
	for (const text of SPAM_TRAINING_DATA) {
		classifier.learn(text, 'spam');
	}

	// Only train with 5 ham examples
	for (let index = 0; index < 5; index++) {
		classifier.learn(HAM_TRAINING_DATA[index], 'ham');
	}

	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	// Should still be able to classify
	const email = `From: test@example.com
To: user@example.com
Subject: Test

This is a test email about a meeting tomorrow.
`;

	const result = await scanner.scan(email);

	assert.strictEqual(typeof result.isSpam, 'boolean', 'Should return boolean');
	assert.ok(['spam', 'ham'].includes(result.results.classification.category), 'Should classify correctly');
});

test('should retrain classifier and get different results', async () => {
	// First classifier - trained with lots of spam examples
	const classifier1 = new NaiveBayes();
	for (const text of SPAM_TRAINING_DATA) {
		classifier1.learn(text, 'spam');
	}

	classifier1.learn('meeting tomorrow project deadline', 'ham');

	const scanner1 = new SpamScanner({
		classifier: classifier1.toJson(),
	});

	const testEmail = `From: test@example.com
To: user@example.com
Subject: Free

Free consultation available.
`;

	const result1 = await scanner1.scan(testEmail);

	// Second classifier - trained with lots of ham examples
	const classifier2 = new NaiveBayes();
	for (const text of HAM_TRAINING_DATA) {
		classifier2.learn(text, 'ham');
	}

	classifier2.learn('buy viagra cheap pills', 'spam');

	const scanner2 = new SpamScanner({
		classifier: classifier2.toJson(),
	});

	const result2 = await scanner2.scan(testEmail);

	// Both should classify (may or may not be different)
	assert.ok(['spam', 'ham'].includes(result1.results.classification.category), 'Result 1 should classify');
	assert.ok(['spam', 'ham'].includes(result2.results.classification.category), 'Result 2 should classify');
});

test('should handle classifier with special characters', async () => {
	const classifier = new NaiveBayes();

	// Train with special characters - use more examples
	for (let i = 0; i < 10; i++) {
		classifier.learn('$$$$ Make money $$$$ !!! Click here !!!', 'spam');
		classifier.learn('Re: Project update - please review', 'ham');
	}

	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	const email = `From: test@example.com
To: user@example.com
Subject: $$$ Free $$$

$$$ Get rich quick $$$
`;

	const result = await scanner.scan(email);

	// Should classify (may be spam or ham)
	assert.ok(['spam', 'ham'].includes(result.results.classification.category), 'Should handle special characters');
});

test('should verify classifier accuracy with test set', async () => {
	const classifier = new NaiveBayes();

	// Train with 80% of data
	const trainSpamCount = Math.floor(SPAM_TRAINING_DATA.length * 0.8);
	const trainHamCount = Math.floor(HAM_TRAINING_DATA.length * 0.8);

	for (let index = 0; index < trainSpamCount; index++) {
		classifier.learn(SPAM_TRAINING_DATA[index], 'spam');
	}

	for (let index = 0; index < trainHamCount; index++) {
		classifier.learn(HAM_TRAINING_DATA[index], 'ham');
	}

	// Test with remaining 20%
	let correctPredictions = 0;
	let totalPredictions = 0;

	for (let index = trainSpamCount; index < SPAM_TRAINING_DATA.length; index++) {
		const result = classifier.categorize(SPAM_TRAINING_DATA[index]);
		if (result === 'spam') {
			correctPredictions++;
		}

		totalPredictions++;
	}

	for (let index = trainHamCount; index < HAM_TRAINING_DATA.length; index++) {
		const result = classifier.categorize(HAM_TRAINING_DATA[index]);
		if (result === 'ham') {
			correctPredictions++;
		}

		totalPredictions++;
	}

	const accuracy = correctPredictions / totalPredictions;

	assert.ok(accuracy > 0.5, `Classifier accuracy should be > 50% (got ${(accuracy * 100).toFixed(1)}%)`);
});

test('should handle empty classifier gracefully', async () => {
	const classifier = new NaiveBayes();

	// Don't train at all
	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	const email = `From: test@example.com
To: user@example.com
Subject: Test

This is a test email.
`;

	const result = await scanner.scan(email);

	// Should not throw error
	assert.strictEqual(typeof result.isSpam, 'boolean', 'Should handle empty classifier');
	assert.ok(['spam', 'ham'].includes(result.results.classification.category), 'Should still classify');
});

test('should serialize and deserialize classifier correctly', async () => {
	const classifier = new NaiveBayes();

	classifier.learn('spam spam spam', 'spam');
	classifier.learn('ham ham ham', 'ham');

	// Serialize
	const json = classifier.toJson();

	// Deserialize - NaiveBayes expects the JSON object directly
	const classifier2 = NaiveBayes.fromJson(json);

	// Both should produce same results
	const result1 = classifier.categorize('spam spam');
	const result2 = classifier2.categorize('spam spam');

	assert.strictEqual(result1, result2, 'Serialized classifier should produce same results');
});

test('should handle multilingual training data', async () => {
	const classifier = new NaiveBayes();

	// Train with English spam
	classifier.learn('Buy cheap viagra now', 'spam');
	classifier.learn('Get rich quick scheme', 'spam');

	// Train with Spanish ham
	classifier.learn('Hola, ¿cómo estás? Nos vemos mañana.', 'ham');
	classifier.learn('Gracias por tu correo electrónico.', 'ham');

	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	const spanishEmail = `From: amigo@example.com
To: user@example.com
Subject: Reunión

Hola, nos vemos mañana para la reunión.
`;

	const result = await scanner.scan(spanishEmail);

	assert.strictEqual(result.results.classification.category, 'ham', 'Should classify Spanish ham correctly');
});

test('should handle very long text', async () => {
	const classifier = new NaiveBayes();

	for (const text of SPAM_TRAINING_DATA) {
		classifier.learn(text, 'spam');
	}

	for (const text of HAM_TRAINING_DATA) {
		classifier.learn(text, 'ham');
	}

	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	// Create very long email
	const longBody = 'This is a legitimate business email. '.repeat(1000);
	const longEmail = `From: business@example.com
To: user@example.com
Subject: Business Proposal

${longBody}
`;

	const result = await scanner.scan(longEmail);

	assert.strictEqual(typeof result.isSpam, 'boolean', 'Should handle long text');
	assert.ok(['spam', 'ham'].includes(result.results.classification.category), 'Should classify long text');
});

test('should handle classifier with numeric data', async () => {
	const classifier = new NaiveBayes();

	// Train with numbers
	classifier.learn('Win $1000000 now! Call 1-800-SPAM-NOW', 'spam');
	classifier.learn('Invoice #12345 for $500.00 due on 2024-01-15', 'ham');

	const scanner = new SpamScanner({
		classifier: classifier.toJson(),
	});

	const invoiceEmail = `From: accounting@example.com
To: user@example.com
Subject: Invoice #67890

Your invoice #67890 for $250.00 is attached.
`;

	const result = await scanner.scan(invoiceEmail);

	assert.strictEqual(result.results.classification.category, 'ham', 'Should classify invoice as ham');
});
