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
	// A QR code that goes elsewhere than the sender's own domains
	qrCodeLink: 1.5,
	// A link that runs a script or opens a page held in the link
	scriptLink: 3,
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
	// A shell, Python or Perl script, or a text file that starts with "#!"
	scriptAttachment: 3,
	disguisedExecutable: 12,
	doubleExtension: 6,
	rtlOverride: 6,
	executableInArchive: 8,
	scriptInArchive: 3,
	riskyAttachment: 2,
	encryptedArchive: 2,
	macro: 4,
	pdfActive: 3,
	rtfObject: 4,
	htmlAttachment: 1,
	activeHtmlAttachment: 3,
	virus: 100,
	// A message beyond the MIME parser's limits (more than 1000 MIME parts, or
	// a part's header over 1 MB), or with an attached message it fails on, not
	// read whole; no credit but the allowlist's and a truth source's offsets
	// it.
	mimeTooComplex: 6,

	// Text
	invisibleCharacters: 2,
	mixedScriptWords: 2.5,
	styledLetters: 1.5,
	// A QR code drawn with HTML cells or block characters, not an image
	drawnQrCode: 3,
	languageNotAllowed: 3,
	toxicity: 3,
	nsfw: 3,

	// Second opinion from a language model: confidence times these points.
	llmSpam: 6,
	llmHam: 3,
};

// The tests of link findings by their type, and their keys in scores
const PHISHING_TESTS = Object.fromEntries([
	['deceptive_link', ['DECEPTIVE_LINK', 'deceptiveLink']],
	['qr_code_link', ['QR_CODE_LINK', 'qrCodeLink']],
	['script_link', ['SCRIPT_LINK', 'scriptLink']],
	['malicious_domain', ['MALICIOUS_DOMAIN', 'maliciousDomain']],
	['adult_domain', ['ADULT_DOMAIN', 'adultDomain']],
]);

const ATTACHMENT_TESTS = Object.fromEntries([
	['executable', ['EXECUTABLE_ATTACHMENT', 'executable']],
	['disguised_executable', ['DISGUISED_EXECUTABLE', 'disguisedExecutable']],
	['double_extension', ['DOUBLE_EXTENSION', 'doubleExtension']],
	['rtl_override', ['RTL_OVERRIDE_FILENAME', 'rtlOverride']],
	['executable_in_archive', ['EXECUTABLE_IN_ARCHIVE', 'executableInArchive']],
	['script_in_archive', ['SCRIPT_IN_ARCHIVE', 'scriptInArchive']],
	['risky_attachment', ['RISKY_ATTACHMENT_TYPE', 'riskyAttachment']],
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

/**
 * The results that count toward the score. A sender that passes DMARC is who
 * it says it is, so what marks a message as hiding its sender says nothing
 * of it: the address a newsletter shows over its mailing service's tracking
 * domain, a brand's name in a link's domain
 * (`unlessAuthenticated`, see checkLinks), and the invisible characters,
 * styled letters and words of mixed alphabets that mail from shops and the
 * names of a social network's members are full of. A brand's address shown by another sender still counts,
 * and so does everything else. (Not a pass that earns no DMARC_PASS, nor in
 * a message not read whole.)
 * @param {object} results
 * @returns {object}
 */
function counted(results) {
	const authenticated = !results.parseError && (results.authentication?.score?.tests || []).some(test => test.name === 'DMARC_PASS');
	return authenticated
		? {
			...results,
			phishing: (results.phishing || []).filter(item => !item.unlessAuthenticated),
			obfuscation: {
				...results.obfuscation, invisible: 0, mixed: 0, styled: false,
			},
		}
		: results;
}

// The points of an attachment finding: its type's, but an HTML file with
// scripts or forms, and a script developers send as it is (see
// inspectAttachments), have their own.
function attachmentPoints(item, scores, key) {
	if (item.type === 'html_attachment' && item.active) {
		return scores.activeHtmlAttachment;
	}

	return item.type === 'executable' && item.script ? scores.scriptAttachment : scores[key];
}

// Why a message earns no credit (see scoreResults), or null
function noCreditReason(results, tests) {
	const fired = name => tests.some(test => test.name === name && test.score > 0);
	if (results.parseError) {
		return 'the message was not read whole';
	}

	if (fired('MALICIOUS_DOMAIN') && results.phishing.some(item => item.type === 'malicious_domain' && !item.quoted)) {
		return 'it links to a site blocked as phishing or malware';
	}

	if (fired('FROM_NAME_BRAND') && results.arbitrary.rules.some(rule => rule.name === 'FROM_NAME_BRAND' && rule.subject)) {
		return 'its display name and its subject claim a brand it is not from';
	}

	if (fired('FROM_NAME_LOOKALIKE')) {
		return 'its display name writes a brand it is not from with lookalike letters';
	}

	if (fired('FROM_UNKNOWN_TLD')) {
		return 'its From address is under no top-level domain, so what passes is another domain\'s';
	}

	return fired('CLOUD_SERVER') ? 'it was sent straight from a rented cloud server without authenticating' : null;
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
export function scoreResults(results, options) {
	results = counted(results ?? {});
	options ??= {};
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

			default: {
				const [name, key] = PHISHING_TESTS[item.type] || [];
				if (name) {
					add(name, scores[key], item.message);
				} else if (item.type === 'uribl') {
					add(`URIBL_${item.zone.split('.')[0].toUpperCase()}`, scores.uriblListed, item.message);
				}
			}
		}
	}

	for (const item of results.attachments || []) {
		const [name, key] = ATTACHMENT_TESTS[item.type] || [];
		if (name) {
			add(name, attachmentPoints(item, scores, key), item.message);
		}
	}

	if (results.parseError) {
		add('MIME_TOO_COMPLEX', scores.mimeTooComplex, `Message, or a message attached to it, is beyond the MIME parser (${results.parseError}), so it was not read whole`);
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

	// (also of a sender that passes DMARC: no one but phishing draws one so)
	if (obfuscation.qrCode) {
		add('DRAWN_QR_CODE', scores.drawnQrCode, 'A QR code drawn with HTML cells or block characters rather than an image, which hides its link from scanners');
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

	// (a message not read whole earns no credit, as the
	//  sender's own authentication, but what the receiver trusts: what was
	//  not read cannot be vouched for; nor does one with a link to a site
	//  blocked as phishing or malware: a sender that passes DMARC with words
	//  the classifier finds ordinary is how a hacked account or a
	//  throwaway domain sends it, but not for a link only in a message it
	//  carries, as a mailing list's notice of a post held for approval or a
	//  bounce quotes one; nor does one sent straight from a rented cloud
	//  server without authenticating, whose words are the spammer's to
	//  choose; nor one whose display name and subject both name a brand it
	//  is not from: its authentication shows only that it is not the brand,
	//  and its words are the brand's own, copied; nor one whose display name
	//  writes such a brand with lookalike letters, which no sender does but
	//  to be taken for it; nor one a domain signed from an address under no
	//  top-level domain there is: no domain can be such a sender's, so what
	//  passes is another's)
	const noCredit = noCreditReason(results, tests);
	if (noCredit) {
		for (const test of tests.filter(test => test.score < 0 && !['ALLOWLISTED', 'TRUTH_SOURCE'].includes(test.name))) {
			test.score = 0;
			test.description += ` (no credit: ${noCredit})`;
		}
	}

	const score = round(tests.reduce((sum, test) => sum + test.score, 0));
	let action = 'accept';
	// (a reject threshold below the spam threshold rejects spam only)
	if (score >= Math.max(threshold, rejectThreshold)) {
		action = 'reject';
	} else if (score >= threshold) {
		action = 'tag';
	}

	return {
		score, threshold, rejectThreshold, isSpam: score >= threshold, action, tests: tests.filter(test => test.score !== 0 || test.name.startsWith('BAYES_')),
	};
}
