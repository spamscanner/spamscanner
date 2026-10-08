/**
 * Points each test adds to a message's score. Negative points count toward
 * ham. A message is spam at `threshold` points (default 5) and rejected by
 * the milter at `rejectThreshold` (default 15).
 */
// Log-odds at which the classifier's points reach 80% of bayesSpam: 99%
// spam probability, which then scores exactly 5.
const BAYES_SCALE = Math.log10(99) / 0.8;

export const DEFAULT_SCORES = {
	// The classifier adds up to bayesSpam points as its spam probability goes
	// from 0.5 to 1, and takes away up to bayesHam points from 0.5 down to 0.
	bayesSpam: 6.25,
	bayesHam: 2.5,

	// Links
	homograph: 5,
	mixedScriptDomain: 3,
	brandInDomain: 1.5,
	typoDomain: 1,
	deceptiveLink: 3,
	maliciousDomain: 6,
	adultDomain: 2,
	uriblListed: 5,

	// Sender
	rblListed: 4,
	denylisted: 100,
	allowlisted: -20,
	truthSource: -5,

	// Attachments
	executable: 10,
	disguisedExecutable: 12,
	doubleExtension: 6,
	rtlOverride: 6,
	executableInArchive: 8,
	encryptedArchive: 2,
	macro: 4,
	pdfActive: 3,
	rtfObject: 4,
	htmlAttachment: 1,
	activeHtmlAttachment: 3,
	virus: 100,

	// Text
	invisibleCharacters: 2,
	mixedScriptWords: 2.5,
	styledLetters: 1.5,
	languageNotAllowed: 3,
	toxicity: 3,
	nsfw: 3,

	// Second opinion from a language model: confidence times these points.
	llmSpam: 6,
	llmHam: 3,
};

const ATTACHMENT_TESTS = Object.fromEntries([
	['executable', ['EXECUTABLE_ATTACHMENT', 'executable']],
	['disguised_executable', ['DISGUISED_EXECUTABLE', 'disguisedExecutable']],
	['double_extension', ['DOUBLE_EXTENSION', 'doubleExtension']],
	['rtl_override', ['RTL_OVERRIDE_FILENAME', 'rtlOverride']],
	['executable_in_archive', ['EXECUTABLE_IN_ARCHIVE', 'executableInArchive']],
	['encrypted_archive', ['ENCRYPTED_ARCHIVE', 'encryptedArchive']],
	['macro', ['MACRO_ATTACHMENT', 'macro']],
	['pdf_active', ['PDF_ACTIVE_CONTENT', 'pdfActive']],
	['rtf_object', ['RTF_EMBEDDED_OBJECT', 'rtfObject']],
	['html_attachment', ['HTML_ATTACHMENT', 'htmlAttachment']],
]);

/**
 * The SpamAssassin-style name of a classifier probability: BAYES_99 for 0.99
 * and up, BAYES_00 below 0.01.
 * @param {number} probability
 * @returns {string}
 */
export function bayesTestName(probability) {
	const steps = [[0.999, '999'], [0.99, '99'], [0.95, '95'], [0.8, '80'], [0.6, '60'], [0.4, '50'], [0.2, '40'], [0.05, '20'], [0.01, '05']];
	const found = steps.find(([floor]) => probability >= floor);
	return `BAYES_${found ? found[1] : '00'}`;
}

function round(value) {
	return Math.round(value * 100) / 100;
}

/**
 * Turn detection results into a score, the list of tests that fired, and a
 * decision.
 *
 * @param {object} results - classification, phishing, attachments, viruses,
 *   arbitrary, obfuscation, authentication, reputation, dnsbl, language,
 *   toxicity, nsfw and llm results from a scan
 * @param {object} [options]
 * @param {object} [options.scores] - overrides for DEFAULT_SCORES
 * @param {number} [options.threshold]
 * @param {number} [options.rejectThreshold]
 * @param {object} [options.authScores] - see calculateAuthScore
 * @returns {{score: number, threshold: number, rejectThreshold: number, isSpam: boolean, action: 'accept'|'tag'|'reject', tests: Array<{name: string, score: number, description: string}>}}
 */
export function scoreResults(results = {}, options = {}) {
	const scores = {...DEFAULT_SCORES, ...options.scores};
	const threshold = options.threshold ?? 5;
	const rejectThreshold = options.rejectThreshold ?? 15;
	const tests = [];
	const seen = new Set();
	// A test name as a key (scores: {FROM_NAME_BRAND: 4}) sets that test's points.
	const add = (name, score, description) => {
		const points = Object.hasOwn(scores, name) ? scores[name] : score;
		if (seen.has(name) || !Number.isFinite(points)) {
			return;
		}

		seen.add(name);
		tests.push({name, score: round(points), description});
	};

	const {classification} = results;
	if (classification && typeof classification.probability === 'number' && classification.category !== 'disabled') {
		// Points follow the classifier's log-odds: 2.4 points at 90%, 5 (the spam
		// threshold) at 99% and the full bayesSpam at 99.9%, so a classifier that
		// is only fairly sure needs a second signal to mark a message as spam.
		const p = classification.probability;
		const name = bayesTestName(p);
		const strength = Math.min(Math.abs(Math.log10(p / (1 - p))) / BAYES_SCALE, 1);
		const points = p > 0.5 ? scores.bayesSpam * strength : -scores.bayesHam * strength;
		add(name, Math.abs(points) < 0.005 ? 0 : points, `Classifier spam probability ${(p * 100).toFixed(1)}%`);
	}

	for (const item of results.phishing || []) {
		switch (item.type) {
			case 'homograph': {
				if (item.riskScore >= 0.85) {
					add('PHISHING_LOOKALIKE_DOMAIN', scores.homograph, item.message);
				} else if (item.riskScore >= 0.6) {
					add(item.mixedScripts ? 'MIXED_SCRIPT_DOMAIN' : 'BRAND_IN_DOMAIN', item.mixedScripts ? scores.mixedScriptDomain : scores.brandInDomain, item.message);
				} else {
					add('TYPO_DOMAIN', scores.typoDomain, item.message);
				}

				break;
			}

			case 'deceptive_link': {
				add('DECEPTIVE_LINK', scores.deceptiveLink, item.message);
				break;
			}

			case 'malicious_domain': {
				add('MALICIOUS_DOMAIN', scores.maliciousDomain, item.message);
				break;
			}

			case 'adult_domain': {
				add('ADULT_DOMAIN', scores.adultDomain, item.message);
				break;
			}

			case 'uribl': {
				add(`URIBL_${item.zone.split('.')[0].toUpperCase()}`, scores.uriblListed, item.message);
				break;
			}

			default: {
				break;
			}
		}
	}

	for (const item of results.attachments || []) {
		const [name, key] = ATTACHMENT_TESTS[item.type] || [];
		if (name) {
			const points = item.type === 'html_attachment' && item.active ? scores.activeHtmlAttachment : scores[key];
			add(name, points, item.message);
		}
	}

	if ((results.viruses || []).length > 0) {
		add('VIRUS', scores.virus, results.viruses.map(virus => virus.message).join('; '));
	}

	for (const rule of results.arbitrary?.rules || []) {
		add(rule.name, rule.score, rule.message);
	}

	const obfuscation = results.obfuscation || {};
	if (obfuscation.invisible >= 3) {
		add('INVISIBLE_CHARACTERS', scores.invisibleCharacters, `${obfuscation.invisible} invisible characters inside the text`);
	}

	if (obfuscation.mixed >= 2) {
		add('MIXED_SCRIPT_WORDS', scores.mixedScriptWords, `${obfuscation.mixed} words mix letters from different alphabets`);
	}

	if (obfuscation.styled) {
		add('STYLED_LETTERS', scores.styledLetters, 'Uses mathematical or enclosed letters to look like plain text');
	}

	for (const test of results.authentication?.score?.tests || []) {
		add(test.name, test.score, `Authentication: ${test.name.toLowerCase().replace('_', '=')}`);
	}

	const {reputation} = results;
	if (reputation?.isDenylisted) {
		add('DENYLISTED', scores.denylisted, `Sender is on the denylist (${reputation.denylistValue})`);
	} else if (reputation?.isAllowlisted) {
		add('ALLOWLISTED', scores.allowlisted, `Sender is on the allowlist (${reputation.allowlistValue})`);
	} else if (reputation?.isTruthSource) {
		add('TRUTH_SOURCE', scores.truthSource, `Sender is a known truth source (${reputation.truthSourceValue})`);
	}

	for (const listing of results.dnsbl || []) {
		add(`RBL_${listing.zone.split('.')[0].toUpperCase()}`, scores.rblListed, `Sending IP ${listing.value} is listed in ${listing.zone}`);
	}

	if (results.language?.notAllowed) {
		add('LANGUAGE_NOT_ALLOWED', scores.languageNotAllowed, `Written in ${results.language.language}, which is not an accepted language`);
	}

	if ((results.toxicity || []).length > 0) {
		add('TOXIC_CONTENT', scores.toxicity, results.toxicity.map(item => item.message).join('; '));
	}

	if ((results.nsfw || []).length > 0) {
		add('NSFW_IMAGE', scores.nsfw, results.nsfw.map(item => item.message).join('; '));
	}

	const {llm} = results;
	// A message that addresses AI filters may have talked the model into
	// calling it ham, so it earns no ham credit from the model.
	const injected = (results.arbitrary?.rules || []).some(rule => rule.name === 'PROMPT_INJECTION');
	if (llm?.verdict && !(injected && llm.verdict === 'ham')) {
		if (llm.verdict === 'ham') {
			add('LLM_HAM', -scores.llmHam * llm.confidence, `${llm.model || llm.provider} says ham (${Math.round(llm.confidence * 100)}%)`);
		} else {
			add(`LLM_${llm.verdict.toUpperCase()}`, scores.llmSpam * llm.confidence, `${llm.model || llm.provider} says ${llm.verdict} (${Math.round(llm.confidence * 100)}%)${llm.reasons?.length ? `: ${llm.reasons.slice(0, 2).join('; ')}` : ''}`);
		}
	}

	const score = round(tests.reduce((sum, test) => sum + test.score, 0));
	let action = 'accept';
	if (score >= rejectThreshold) {
		action = 'reject';
	} else if (score >= threshold) {
		action = 'tag';
	}

	return {
		score, threshold, rejectThreshold, isSpam: score >= threshold, action, tests: tests.filter(test => test.score !== 0 || test.name.startsWith('BAYES_')),
	};
}
