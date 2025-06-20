// Franc vs Lande Performance Test
import {franc} from 'franc';
import lande from 'lande';

// Test samples of varying lengths and languages
const testSamples = [
	// Short texts (where lande should excel)
	{text: 'Hello world', expected: 'eng', description: 'Very short English'},
	{text: 'Bonjour', expected: 'fra', description: 'Very short French'},
	{text: 'Hola mundo', expected: 'spa', description: 'Short Spanish'},
	{text: 'Guten Tag', expected: 'deu', description: 'Short German'},
	{text: 'こんにちは', expected: 'jpn', description: 'Short Japanese'},

	// Medium texts
	{text: 'This is a medium length sentence in English.', expected: 'eng', description: 'Medium English'},
	{text: 'Ceci est une phrase de longueur moyenne en français.', expected: 'fra', description: 'Medium French'},
	{text: 'Esta es una oración de longitud media en español.', expected: 'spa', description: 'Medium Spanish'},
	{text: 'Dies ist ein mittellanger Satz auf Deutsch.', expected: 'deu', description: 'Medium German'},

	// Long texts (where franc should excel)
	{
		text: 'This is a much longer text sample that contains multiple sentences and should provide enough context for accurate language detection. The purpose of this extended text is to test how well each library performs when given substantial input data.',
		expected: 'eng',
		description: 'Long English',
	},
	{
		text: 'Ceci est un échantillon de texte beaucoup plus long qui contient plusieurs phrases et devrait fournir suffisamment de contexte pour une détection précise de la langue. Le but de ce texte étendu est de tester la performance de chaque bibliothèque lorsqu\'elle reçoit des données d\'entrée substantielles.',
		expected: 'fra',
		description: 'Long French',
	},

	// Edge cases
	{text: '123 456 789', expected: 'und', description: 'Numbers only'},
	{text: '!!!', expected: 'und', description: 'Punctuation only'},
	{text: '', expected: 'und', description: 'Empty string'},
	{text: 'a', expected: 'und', description: 'Single character'},

	// Mixed/ambiguous cases
	{text: 'café restaurant', expected: 'fra', description: 'Mixed French/English'},
	{text: 'email@example.com', expected: 'und', description: 'Email address'},
	{text: 'https://www.example.com', expected: 'und', description: 'URL'},
];

function testFranc() {
	console.log(String.raw`\n=== FRANC RESULTS ===`);
	const results = [];

	for (const sample of testSamples) {
		const start = performance.now();
		const detected = franc(sample.text);
		const end = performance.now();
		const time = end - start;

		const correct = detected === sample.expected;
		results.push({
			description: sample.description,
			text: sample.text.slice(0, 50) + (sample.text.length > 50 ? '...' : ''),
			expected: sample.expected,
			detected,
			correct,
			time: time.toFixed(3) + 'ms',
		});

		console.log(`${sample.description}: ${detected} (${correct ? '✓' : '✗'}) - ${time.toFixed(3)}ms`);
	}

	return results;
}

function testLande() {
	console.log(String.raw`\n=== LANDE RESULTS ===`);
	const results = [];

	for (const sample of testSamples) {
		const start = performance.now();
		const landeResults = lande(sample.text);
		const detected = landeResults.length > 0 ? landeResults[0][0] : 'und';
		const confidence = landeResults.length > 0 ? landeResults[0][1] : 0;
		const end = performance.now();
		const time = end - start;

		const correct = detected === sample.expected;
		results.push({
			description: sample.description,
			text: sample.text.slice(0, 50) + (sample.text.length > 50 ? '...' : ''),
			expected: sample.expected,
			detected,
			confidence: confidence.toFixed(4),
			correct,
			time: time.toFixed(3) + 'ms',
		});

		console.log(`${sample.description}: ${detected} (${confidence.toFixed(4)}) (${correct ? '✓' : '✗'}) - ${time.toFixed(3)}ms`);
	}

	return results;
}

function compareResults(francResults, landeResults) {
	console.log(String.raw`\n=== COMPARISON SUMMARY ===`);

	const francCorrect = francResults.filter(r => r.correct).length;
	const landeCorrect = landeResults.filter(r => r.correct).length;
	const total = testSamples.length;

	console.log(`Franc accuracy: ${francCorrect}/${total} (${(francCorrect / total * 100).toFixed(1)}%)`);
	console.log(`Lande accuracy: ${landeCorrect}/${total} (${(landeCorrect / total * 100).toFixed(1)}%)`);

	// Performance comparison
	const francAvgTime = francResults.reduce((sum, r) => sum + Number.parseFloat(r.time), 0) / francResults.length;
	const landeAvgTime = landeResults.reduce((sum, r) => sum + Number.parseFloat(r.time), 0) / landeResults.length;

	console.log(String.raw`\nAverage processing time:`);
	console.log(`Franc: ${francAvgTime.toFixed(3)}ms`);
	console.log(`Lande: ${landeAvgTime.toFixed(3)}ms`);

	// Detailed comparison by text length
	console.log(String.raw`\n=== DETAILED COMPARISON ===`);
	for (const [i, sample] of testSamples.entries()) {
		const francResult = francResults[i];
		const landeResult = landeResults[i];

		console.log(`\\n${sample.description}:`);
		console.log(`  Text: "${sample.text.slice(0, 30)}${sample.text.length > 30 ? '...' : ''}"`);
		console.log(`  Expected: ${sample.expected}`);
		console.log(`  Franc: ${francResult.detected} (${francResult.correct ? '✓' : '✗'}) - ${francResult.time}`);
		console.log(`  Lande: ${landeResult.detected} (conf: ${landeResult.confidence}) (${landeResult.correct ? '✓' : '✗'}) - ${landeResult.time}`);
	}
}

// Run the tests
async function runTests() {
	console.log('Starting Franc vs Lande Performance Comparison...');

	const francResults = testFranc();
	const landeResults = testLande();

	compareResults(francResults, landeResults);
}

// Run the tests
runTests().catch(console.error);

