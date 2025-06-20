#!/usr/bin/env node

/**
 * Test script for hybrid franc/lande language detection
 * This tests the detectLanguageHybrid method implementation
 */

import SpamScanner from './src/index.js';

const scanner = new SpamScanner();

// Test cases for hybrid language detection
const testCases = [
	{
		text: 'Hello world',
		expected: 'en',
		description: 'Short English text (should use lande)',
	},
	{
		text: 'Bonjour',
		expected: 'fr',
		description: 'Short French text (should use lande)',
	},
	{
		text: 'This is a longer English text that should be processed by franc instead of lande because it exceeds the 50 character threshold that we have set for the hybrid detection system.',
		expected: 'en',
		description: 'Long English text (should use franc)',
	},
	{
		text: 'Ceci est un texte français plus long qui devrait être traité par franc au lieu de lande car il dépasse le seuil de 50 caractères que nous avons défini pour le système de détection hybride.',
		expected: 'fr',
		description: 'Long French text (should use franc)',
	},
	{
		text: 'Hola mundo',
		expected: 'es',
		description: 'Short Spanish text (should use lande)',
	},
	{
		text: 'Este es un texto en español más largo que debería ser procesado por franc en lugar de lande porque excede el umbral de 50 caracteres que hemos establecido para el sistema de detección híbrida.',
		expected: 'es',
		description: 'Long Spanish text (should use franc)',
	},
	{
		text: 'Hallo Welt',
		expected: 'de',
		description: 'Short German text (should use lande)',
	},
	{
		text: 'Dies ist ein längerer deutscher Text, der von franc anstatt von lande verarbeitet werden sollte, da er die 50-Zeichen-Schwelle überschreitet, die wir für das hybride Erkennungssystem festgelegt haben.',
		expected: 'de',
		description: 'Long German text (should use franc)',
	},
	{
		text: 'Ciao mondo',
		expected: 'it',
		description: 'Short Italian text (should use lande)',
	},
	{
		text: 'Questo è un testo italiano più lungo che dovrebbe essere elaborato da franc invece di lande perché supera la soglia di 50 caratteri che abbiamo impostato per il sistema di rilevamento ibrido.',
		expected: 'it',
		description: 'Long Italian text (should use franc)',
	},
	{
		text: 'Привет мир',
		expected: 'ru',
		description: 'Short Russian text (should use lande)',
	},
	{
		text: 'Это более длинный русский текст, который должен обрабатываться franc вместо lande, потому что он превышает порог в 50 символов, который мы установили для гибридной системы обнаружения.',
		expected: 'ru',
		description: 'Long Russian text (should use franc)',
	},
	{
		text: '你好世界',
		expected: 'zh',
		description: 'Short Chinese text (should use lande)',
	},
	{
		text: '这是一个更长的中文文本，应该由franc而不是lande处理，因为它超过了我们为混合检测系统设置的50个字符的阈值。这个测试确保我们的语言检测系统能够正确处理不同长度的文本。',
		expected: 'zh',
		description: 'Long Chinese text (should use franc)',
	},
	{
		text: 'こんにちは世界',
		expected: 'ja',
		description: 'Short Japanese text (should use lande)',
	},
	{
		text: 'これは、ハイブリッド検出システムに設定した50文字のしきい値を超えるため、landeではなくfrancによって処理される必要があるより長い日本語テキストです。このテストにより、言語検出システムがさまざまな長さのテキストを正しく処理できることが保証されます。',
		expected: 'ja',
		description: 'Long Japanese text (should use franc)',
	},
	{
		text: '',
		expected: 'en',
		description: 'Empty text (should default to English)',
	},
	{
		text: '123 456 789',
		expected: 'en',
		description: 'Numbers only (should default to English)',
	},
	{
		text: '!@#$%^&*()',
		expected: 'en',
		description: 'Special characters only (should default to English)',
	},
	{
		text: 'a',
		expected: 'en',
		description: 'Single character (should default to English)',
	},
	{
		text: 'ab',
		expected: 'en',
		description: 'Two characters (should default to English)',
	},
];

async function runTests() {
	console.log('🧪 Testing Hybrid Franc/Lande Language Detection\n');

	let passed = 0;
	let failed = 0;

	for (const testCase of testCases) {
		try {
			const startTime = Date.now();
			const detected = await scanner.detectLanguageHybrid(testCase.text);
			const endTime = Date.now();
			const duration = endTime - startTime;

			const success = detected === testCase.expected;

			if (success) {
				console.log(`✅ PASS: ${testCase.description}`);
				console.log(`   Text: "${testCase.text.slice(0, 50)}${testCase.text.length > 50 ? '...' : ''}"`);
				console.log(`   Expected: ${testCase.expected}, Got: ${detected} (${duration}ms)\n`);
				passed++;
			} else {
				console.log(`❌ FAIL: ${testCase.description}`);
				console.log(`   Text: "${testCase.text.slice(0, 50)}${testCase.text.length > 50 ? '...' : ''}"`);
				console.log(`   Expected: ${testCase.expected}, Got: ${detected} (${duration}ms)\n`);
				failed++;
			}
		} catch (error) {
			console.log(`💥 ERROR: ${testCase.description}`);
			console.log(`   Error: ${error.message}\n`);
			failed++;
		}
	}

	console.log('\n📊 Test Results:');
	console.log(`   ✅ Passed: ${passed}`);
	console.log(`   ❌ Failed: ${failed}`);
	console.log(`   📈 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);

	if (failed === 0) {
		console.log('\n🎉 All tests passed! Hybrid language detection is working correctly.');
	} else {
		console.log('\n⚠️  Some tests failed. Please review the implementation.');
	}
}

// Run the tests
runTests().catch(console.error);

