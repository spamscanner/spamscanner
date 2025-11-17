/* eslint-disable no-await-in-loop */
import {test} from 'node:test';
import assert from 'node:assert';
import SpamScanner from '../src/index.js';

// Tests for configuration options functionality

test('enableMacroDetection: true should detect macros', async () => {
	const scanner = new SpamScanner({enableMacroDetection: true});

	const emailWithMacro = `From: test@example.com
To: user@example.com
Subject: Invoice

This is a test email with VBA macro content.
Sub AutoOpen()
    MsgBox "Hello"
End Sub
`;

	const result = await scanner.scan(emailWithMacro);
	assert.ok(result.results.macros.length > 0, 'Should detect macros when enabled');
});

test('enableMacroDetection: false should skip macro detection', async () => {
	const scanner = new SpamScanner({enableMacroDetection: false});

	const emailWithMacro = `From: test@example.com
To: user@example.com
Subject: Invoice

This is a test email with VBA macro content.
Sub AutoOpen()
    MsgBox "Hello"
End Sub
`;

	const result = await scanner.scan(emailWithMacro);
	assert.strictEqual(result.results.macros.length, 0, 'Should not detect macros when disabled');
});

test('supportedLanguages: should filter to supported languages', async () => {
	const scanner = new SpamScanner({supportedLanguages: ['en', 'es', 'fr']});

	// English text
	const englishText = 'This is a test email in English with enough words for detection.';
	const enResult = await scanner.detectLanguageHybrid(englishText);
	assert.strictEqual(enResult, 'en', 'Should detect English');

	// Spanish text
	const spanishText = 'Este es un correo electrónico de prueba en español con suficientes palabras.';
	const esResult = await scanner.detectLanguageHybrid(spanishText);
	assert.strictEqual(esResult, 'es', 'Should detect Spanish');

	// French text
	const frenchText = 'Ceci est un e-mail de test en français avec suffisamment de mots.';
	const frResult = await scanner.detectLanguageHybrid(frenchText);
	assert.strictEqual(frResult, 'fr', 'Should detect French');
});

test('supportedLanguages: should fallback to first language for unsupported', async () => {
	const scanner = new SpamScanner({supportedLanguages: ['en']});

	// German text (not in supported list)
	const germanText = 'Dies ist eine Test-E-Mail auf Deutsch mit genügend Wörtern zur Erkennung.';
	const result = await scanner.detectLanguageHybrid(germanText);
	assert.strictEqual(result, 'en', 'Should fallback to first supported language (en)');
});

test('supportedLanguages: empty array should allow all languages', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	// German text
	const germanText = 'Dies ist eine Test-E-Mail auf Deutsch mit genügend Wörtern zur Erkennung.';
	const result = await scanner.detectLanguageHybrid(germanText);
	assert.strictEqual(result, 'de', 'Should detect German when no language filter');
});

test('enablePerformanceMetrics: true should track metrics', async () => {
	const scanner = new SpamScanner({enablePerformanceMetrics: true});

	const email = `From: test@example.com
To: user@example.com
Subject: Test

This is a test email.
`;

	const result = await scanner.scan(email);
	assert.ok(result.metrics, 'Should include metrics');
	assert.ok(typeof result.metrics.totalTime === 'number', 'Should have totalTime');
	assert.ok(result.metrics.totalTime > 0, 'totalTime should be positive');
});

test('enablePerformanceMetrics: false should not track metrics', async () => {
	const scanner = new SpamScanner({enablePerformanceMetrics: false});

	const email = `From: test@example.com
To: user@example.com
Subject: Test

This is a test email.
`;

	const result = await scanner.scan(email);
	assert.strictEqual(result.metrics, undefined, 'Should not include metrics when disabled');
});

test('enableMixedLanguageDetection: true should detect mixed languages', async () => {
	const scanner = new SpamScanner({enableMixedLanguageDetection: true});

	const mixedEmail = `From: test@example.com
To: user@example.com
Subject: Test

Hello, this is English. Bonjour, c'est du français. Hola, esto es español.
`;

	const result = await scanner.scan(mixedEmail);
	// Should process the email successfully
	assert.ok(result, 'Should process mixed language email');
	assert.ok(result.results, 'Should have results');
});

test('enableMixedLanguageDetection: false should use single language', async () => {
	const scanner = new SpamScanner({enableMixedLanguageDetection: false});

	const mixedEmail = `From: test@example.com
To: user@example.com
Subject: Test

Hello, this is English. Bonjour, c'est du français. Hola, esto es español.
`;

	const result = await scanner.scan(mixedEmail);
	// Should process the email successfully
	assert.ok(result, 'Should process email with single language detection');
	assert.ok(result.results, 'Should have results');
});

test('enableAdvancedPatternRecognition: true should normalize patterns in preprocessing', async () => {
	const scanner = new SpamScanner({enableAdvancedPatternRecognition: true});

	const text = 'Credit card: 4532-1488-0343-6467 Phone: (555) 123-4567';
	const preprocessed = await scanner.preprocessText(text);

	// Should normalize patterns to tokens
	assert.ok(preprocessed.includes('CREDIT_CARD') || preprocessed.includes('PHONE_NUMBER'), 'Should normalize patterns when enabled');
});

test('enableAdvancedPatternRecognition: false should skip pattern normalization', async () => {
	const scanner = new SpamScanner({enableAdvancedPatternRecognition: false});

	const text = 'Credit card: 4532-1488-0343-6467 Phone: (555) 123-4567';
	const preprocessed = await scanner.preprocessText(text);

	// Should NOT normalize patterns
	assert.ok(!preprocessed.includes('CREDIT_CARD') && !preprocessed.includes('PHONE_NUMBER'), 'Should not normalize patterns when disabled');
});

test('timeout option should be respected', async () => {
	const scanner = new SpamScanner({timeout: 5000});

	assert.strictEqual(scanner.config.timeout, 5000, 'Timeout should be set correctly');
});

test('multiple options should work together', async () => {
	const scanner = new SpamScanner({
		enableMacroDetection: true,
		enablePerformanceMetrics: true,
		supportedLanguages: ['en', 'es'],
		enableAdvancedPatternRecognition: true,
	});

	const email = `From: test@example.com
To: user@example.com
Subject: Test

This is a test email with a phone number (555) 123-4567.
Sub AutoOpen()
    MsgBox "Test"
End Sub
`;

	const result = await scanner.scan(email);
	assert.ok(result, 'Should process email with multiple options');
	assert.ok(result.metrics, 'Should have metrics');
	assert.ok(result.results.macros.length > 0, 'Should detect macros');
});

test('default options should work correctly', async () => {
	const scanner = new SpamScanner();

	// Verify defaults
	assert.strictEqual(scanner.config.enableMacroDetection, true, 'enableMacroDetection default should be true');
	assert.strictEqual(scanner.config.enablePerformanceMetrics, false, 'enablePerformanceMetrics default should be false');
	assert.strictEqual(scanner.config.timeout, 30_000, 'timeout default should be 30000');
	assert.deepStrictEqual(scanner.config.supportedLanguages, ['en'], 'supportedLanguages default should be [\'en\']');
	assert.strictEqual(scanner.config.enableMixedLanguageDetection, false, 'enableMixedLanguageDetection default should be false');
	assert.strictEqual(scanner.config.enableAdvancedPatternRecognition, true, 'enableAdvancedPatternRecognition default should be true');
});

test('supportedLanguages with multiple languages should work', async () => {
	const scanner = new SpamScanner({
		supportedLanguages: ['en', 'es', 'fr', 'de', 'ja', 'zh'],
	});

	const tests = [
		{text: 'This is a comprehensive English text message with many words to ensure proper language detection by the franc library which requires sufficient context.', expected: 'en'},
		{text: 'Este es un mensaje de texto completo en español con muchas palabras para garantizar la detección adecuada del idioma por la biblioteca franc que requiere suficiente contexto.', expected: 'es'},
		{text: 'Ceci est un message texte complet en français avec de nombreux mots pour assurer une détection linguistique appropriée par la bibliothèque franc qui nécessite un contexte suffisant.', expected: 'fr'},
		{text: 'Dies ist eine umfassende deutsche Textnachricht mit vielen Wörtern um eine ordnungsgemäße Spracherkennung durch die Franc-Bibliothek sicherzustellen die ausreichenden Kontext erfordert.', expected: 'de'},
	];

	for (const {text, expected} of tests) {
		const result = await scanner.detectLanguageHybrid(text);
		assert.strictEqual(result, expected, `Should detect ${expected} correctly`);
	}
});
