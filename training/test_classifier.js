#!/usr/bin/env node
/**
 * Test the trained classifier with sample emails
 */

import SpamScanner from '../spamscanner-fresh/src/index.js';

async function testClassifier() {
	console.log('🧪 Testing trained classifier...');

	// Initialize scanner with trained classifier
	const scanner = new SpamScanner({
		classifier: true,
	});

	// Test emails
	const testEmails = [
		{
			name: 'Ham - Business Email',
			text: 'Subject: Meeting tomorrow\n\nHi John, can we reschedule our meeting for tomorrow at 2pm? Thanks, Sarah',
			expected: 'ham',
		},
		{
			name: 'Spam - Typical Spam',
			text: 'Subject: URGENT! You have won $1,000,000!!!\n\nCongratulations! You are our lucky winner! Click here to claim your prize now! Limited time offer!',
			expected: 'spam',
		},
		{
			name: 'Ham - Technical Discussion',
			text: 'Subject: Code review feedback\n\nThe pull request looks good overall. Just a few minor suggestions on the error handling in line 45.',
			expected: 'ham',
		},
		{
			name: 'Spam - Phishing',
			text: 'Subject: Your account will be suspended\n\nDear customer, your account will be suspended unless you verify your credentials immediately. Click here to login.',
			expected: 'spam',
		},
		{
			name: 'Ham - Enron-style Business',
			text: 'Subject: Gas daily report\n\nEnron gas daily report for December 15. Total volume: 120,000 MMBtu. Please review and confirm.',
			expected: 'ham',
		},
	];

	let correct = 0;
	const total = testEmails.length;

	console.log('\n📧 Testing emails:');

	for (const email of testEmails) {
		try {
			const result = await scanner.scan(email.text);
			const predicted = result.isSpam ? 'spam' : 'ham';
			const isCorrect = predicted === email.expected;

			if (isCorrect) {
				correct++;
			}

			console.log(`\n${isCorrect ? '✅' : '❌'} ${email.name}`);
			console.log(`   Expected: ${email.expected}, Predicted: ${predicted}`);
			console.log(`   Confidence: ${(result.score * 100).toFixed(1)}%`);
			console.log(`   Classification: ${result.classification}`);
		} catch (error) {
			console.error(`❌ Error testing ${email.name}:`, error.message);
		}
	}

	const accuracy = (correct / total * 100).toFixed(1);
	console.log('\n📊 Test Results:');
	console.log(`   Accuracy: ${accuracy}% (${correct}/${total})`);

	if (accuracy >= 80) {
		console.log('🎉 Classifier performance is good!');
	} else {
		console.log('⚠️  Classifier may need more training or tuning.');
	}

	return {accuracy: Number.parseFloat(accuracy), correct, total};
}

// Run tests
testClassifier().catch(console.error);

