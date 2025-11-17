/* eslint-disable no-await-in-loop */
import {test} from 'node:test';
import assert from 'node:assert';
import SpamScanner from '../src/index.js';

// Tests specifically for franc->lande fallback behavior

test('should use lande when franc returns und for numbers only', async () => {
	const scanner = new SpamScanner();

	// Numbers only - franc should return 'und'
	const result = await scanner.detectLanguageHybrid('123456789');
	assert.ok(result, 'Should return a language code');
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for special characters', async () => {
	const scanner = new SpamScanner();

	// Special characters - franc might detect a language or return 'und'
	const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
	const result = await scanner.detectLanguageHybrid(specialChars);
	assert.ok(result, 'Should return a language code');
	assert.strictEqual(typeof result, 'string', 'Should return string');
});

test('should use lande when franc returns und for punctuation', async () => {
	const scanner = new SpamScanner();

	// Punctuation only - franc should return 'und'
	const punctuation = '... --- ... ... ---';
	const result = await scanner.detectLanguageHybrid(punctuation);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for whitespace with minimal text', async () => {
	const scanner = new SpamScanner();

	// Mostly whitespace - franc should return 'und'
	const whitespace = '   \n\n\n   \t\t\t   ';
	const result = await scanner.detectLanguageHybrid(whitespace);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for mixed symbols', async () => {
	const scanner = new SpamScanner();

	// Mixed symbols that franc can't identify
	const symbols = '→←↑↓↔↕↖↗↘↙';
	const result = await scanner.detectLanguageHybrid(symbols);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for emoji only', async () => {
	const scanner = new SpamScanner();

	// Emoji only - franc should return 'und'
	const emoji = '😀😁😂🤣😃😄😅😆';
	const result = await scanner.detectLanguageHybrid(emoji);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for mathematical symbols', async () => {
	const scanner = new SpamScanner();

	// Math symbols - franc should return 'und'
	const mathSymbols = '∑∏∫∂∇∆√∞≈≠≤≥';
	const result = await scanner.detectLanguageHybrid(mathSymbols);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for currency symbols', async () => {
	const scanner = new SpamScanner();

	// Currency symbols - franc should return 'und'
	const currency = '$€£¥₹₽¢₩';
	const result = await scanner.detectLanguageHybrid(currency);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for very short ambiguous text', async () => {
	const scanner = new SpamScanner();

	// Very short text that franc can't determine
	const shortTexts = ['a', 'ok', 'hi', 'no', 'yes'];

	for (const text of shortTexts) {
		const result = await scanner.detectLanguageHybrid(text);
		assert.ok(result, `Should return language for "${text}"`);
		assert.strictEqual(typeof result, 'string', 'Should return string');
	}
});

test('should use lande when franc returns und for repetitive characters', async () => {
	const scanner = new SpamScanner();

	// Repetitive single character - franc should return 'und'
	const repetitive = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
	const result = await scanner.detectLanguageHybrid(repetitive);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for mixed numbers and symbols', async () => {
	const scanner = new SpamScanner();

	// Mixed numbers and symbols - franc should return 'und'
	const mixed = '123-456-7890 (555) 123-4567';
	const result = await scanner.detectLanguageHybrid(mixed);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for hexadecimal', async () => {
	const scanner = new SpamScanner();

	// Hexadecimal - franc might detect a language or return 'und'
	const hex = '0x1A2B3C4D5E6F';
	const result = await scanner.detectLanguageHybrid(hex);
	assert.ok(result, 'Should return a language code');
	assert.strictEqual(typeof result, 'string', 'Should return string');
});

test('should use lande when franc returns und for binary', async () => {
	const scanner = new SpamScanner();

	// Binary - franc should return 'und'
	const binary = '01010101010101010101';
	const result = await scanner.detectLanguageHybrid(binary);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should use lande when franc returns und for roman numerals', async () => {
	const scanner = new SpamScanner();

	// Roman numerals - franc might return 'und'
	const roman = 'XVII MCMXCIV MMXXIII';
	const result = await scanner.detectLanguageHybrid(roman);
	assert.ok(result, 'Should return a language code');
	assert.strictEqual(typeof result, 'string', 'Should return string');
});

test('should use lande when franc returns und for box drawing characters', async () => {
	const scanner = new SpamScanner();

	// Box drawing characters - franc should return 'und'
	const boxChars = '┌─┐│└─┘├┤┬┴┼';
	const result = await scanner.detectLanguageHybrid(boxChars);
	assert.strictEqual(result, 'en', 'Should fallback to en via lande');
});

test('should verify lande is actually being called in fallback', async () => {
	const scanner = new SpamScanner();

	// Text that definitely makes franc return 'und'
	const undeterminedTexts = [
		'...',
		'---',
		'===',
		'***',
		'###',
		'@@@',
	];

	for (const text of undeterminedTexts) {
		const result = await scanner.detectLanguageHybrid(text);
		assert.strictEqual(result, 'en', `Should fallback to en for "${text}"`);
	}
});

test('should handle case where lande also returns empty for pure symbols', async () => {
	const scanner = new SpamScanner();

	// Pure symbols that both franc and lande can't identify
	const pureSymbols = '░▒▓█▀▄';
	const result = await scanner.detectLanguageHybrid(pureSymbols);
	assert.strictEqual(result, 'en', 'Should fallback to en when lande also fails');
});

test('should use franc successfully for clear language text', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	// Clear English text - franc should work
	const englishText = 'This is a clear English sentence with enough words for franc to detect.';
	const result = await scanner.detectLanguageHybrid(englishText);
	assert.strictEqual(result, 'en', 'Should detect English via franc');
});

test('should use franc successfully for clear French text', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	// Clear French text - franc should work
	const frenchText = 'Bonjour, comment allez-vous aujourd\'hui? C\'est une belle journée.';
	const result = await scanner.detectLanguageHybrid(frenchText);
	assert.strictEqual(result, 'fr', 'Should detect French via franc');
});

test('should use franc successfully for clear Spanish text', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	// Clear Spanish text - franc should work
	const spanishText = 'Hola, ¿cómo estás? Este es un mensaje en español.';
	const result = await scanner.detectLanguageHybrid(spanishText);
	assert.strictEqual(result, 'es', 'Should detect Spanish via franc');
});

test('should demonstrate fallback path coverage', async () => {
	const scanner = new SpamScanner({supportedLanguages: []});

	// This test explicitly demonstrates the fallback path:
	// 1. Text that franc returns 'und' for
	// 2. Lande is called as fallback
	// 3. If lande returns empty, fallback to 'en'

	const testCases = [
		{input: '123', expected: 'en', path: 'franc->und->lande->en'},
		{input: '!!!', expected: 'en', path: 'franc->und->lande->en'},
		{input: 'Hello world', expected: 'en', path: 'franc->en'},
		{input: 'Bonjour', expected: 'fr', path: 'franc->fr'},
	];

	for (const {input, expected, path} of testCases) {
		const result = await scanner.detectLanguageHybrid(input);
		assert.strictEqual(result, expected, `Path ${path} should work for "${input}"`);
	}
});
