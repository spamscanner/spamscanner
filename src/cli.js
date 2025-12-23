/***
 * SpamScanner CLI
 *
 * Command-line interface for scanning emails for spam, phishing, and malware.
 * Can be used standalone or integrated with mail servers like Postfix and Dovecot.
 *
 * Exit codes:
 *   0 - Clean (not spam)
 *   1 - Spam detected
 *   2 - Error occurred
 */

import {Buffer} from 'node:buffer';
import {
	createReadStream, readFileSync, writeFileSync, existsSync, mkdirSync,
} from 'node:fs';
import {createServer} from 'node:net';
import {homedir} from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';
import SpamScanner from './index.js';

// Get version from package.json
// Handle both ESM (import.meta.url) and CJS/bundled contexts
let __filename;
let __dirname;
try {
	__filename = fileURLToPath(import.meta.url);
	__dirname = path.dirname(__filename);
} catch {
	// In bundled CJS context, use process.cwd() as fallback
	__filename = '';
	__dirname = process.cwd();
}

/**
 * Supported languages with their ISO 639-1 codes
 */
const SUPPORTED_LANGUAGES = {
	en: 'English',
	fr: 'French',
	es: 'Spanish',
	de: 'German',
	it: 'Italian',
	pt: 'Portuguese',
	ru: 'Russian',
	ja: 'Japanese',
	ko: 'Korean',
	zh: 'Chinese',
	ar: 'Arabic',
	hi: 'Hindi',
	bn: 'Bengali',
	ur: 'Urdu',
	tr: 'Turkish',
	pl: 'Polish',
	nl: 'Dutch',
	sv: 'Swedish',
	no: 'Norwegian',
	da: 'Danish',
	fi: 'Finnish',
	hu: 'Hungarian',
	cs: 'Czech',
	sk: 'Slovak',
	sl: 'Slovenian',
	hr: 'Croatian',
	sr: 'Serbian',
	bg: 'Bulgarian',
	ro: 'Romanian',
	el: 'Greek',
	he: 'Hebrew',
	th: 'Thai',
	vi: 'Vietnamese',
	id: 'Indonesian',
	ms: 'Malay',
	tl: 'Tagalog',
	uk: 'Ukrainian',
	be: 'Belarusian',
	lt: 'Lithuanian',
	lv: 'Latvian',
	et: 'Estonian',
	ca: 'Catalan',
	eu: 'Basque',
	gl: 'Galician',
	ga: 'Irish',
	gd: 'Scottish Gaelic',
	cy: 'Welsh',
	is: 'Icelandic',
	mt: 'Maltese',
	af: 'Afrikaans',
	sw: 'Swahili',
	am: 'Amharic',
	ha: 'Hausa',
	yo: 'Yoruba',
	ig: 'Igbo',
	so: 'Somali',
	om: 'Oromo',
	ti: 'Tigrinya',
	mg: 'Malagasy',
	ny: 'Chichewa',
	sn: 'Shona',
	xh: 'Xhosa',
	zu: 'Zulu',
	st: 'Southern Sotho',
	tn: 'Tswana',
};

/**
 * Default score weights for different detection types
 */
const DEFAULT_SCORES = {
	classifier: 5, // Base score when classifier says spam
	phishing: 5, // Per phishing issue detected
	executable: 10, // Per dangerous executable detected
	macro: 5, // Per macro detected
	virus: 100, // Per virus detected
	nsfw: 3, // Per NSFW content detected
	toxicity: 3, // Per toxic content detected
};

/**
 * Update check cache file location
 */
const UPDATE_CACHE_DIR = path.join(homedir(), '.spamscanner');
const UPDATE_CACHE_FILE = path.join(UPDATE_CACHE_DIR, 'update-check.json');
const UPDATE_CHECK_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Find the package.json by traversing up from current directory
 * @returns {string} Version string
 */
function getVersion() {
	// For bundled binaries, use build-time version
	// This is replaced during build by esbuild define
	const BUNDLED_VERSION = process.env.SPAMSCANNER_VERSION || null;
	if (BUNDLED_VERSION) {
		return BUNDLED_VERSION;
	}

	// Try multiple possible locations
	const possiblePaths = [
		path.join(__dirname, '..', 'package.json'),
		path.join(__dirname, '..', '..', 'package.json'),
		path.join(__dirname, '..', '..', '..', 'package.json'),
		path.join(process.cwd(), 'package.json'),
	];

	for (const pkgPath of possiblePaths) {
		try {
			const content = readFileSync(pkgPath, 'utf8');
			const pkg = JSON.parse(content);
			if (pkg.name === 'spamscanner' && pkg.version) {
				return pkg.version;
			}
		} catch {
			// Continue to next path
		}
	}

	return 'unknown';
}

const VERSION = getVersion();

/**
 * Compare two semver versions
 * @param {string} v1 - First version
 * @param {string} v2 - Second version
 * @returns {number} -1 if v1 < v2, 0 if equal, 1 if v1 > v2
 */
function compareVersions(v1, v2) {
	const parts1 = v1.replace(/^v/, '').split('.').map(Number);
	const parts2 = v2.replace(/^v/, '').split('.').map(Number);

	for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
		const p1 = parts1[i] || 0;
		const p2 = parts2[i] || 0;
		if (p1 < p2) {
			return -1;
		}

		if (p1 > p2) {
			return 1;
		}
	}

	return 0;
}

/**
 * Get the platform-specific binary name
 * @returns {string} Binary name for current platform
 */
function getBinaryName() {
	const {platform} = process;
	const {arch} = process;

	if (platform === 'win32') {
		return 'spamscanner-win-x64.exe';
	}

	if (platform === 'darwin') {
		return arch === 'arm64' ? 'spamscanner-darwin-arm64' : 'spamscanner-darwin-x64';
	}

	return 'spamscanner-linux-x64';
}

/**
 * Check for updates from GitHub releases
 * @param {boolean} force - Force check even if recently checked
 * @returns {Promise<object|null>} Update info or null if up to date
 */
async function checkForUpdates(force = false) {
	try {
		// Check cache first (unless forced)
		if (!force && existsSync(UPDATE_CACHE_FILE)) {
			const cache = JSON.parse(readFileSync(UPDATE_CACHE_FILE, 'utf8'));
			const age = Date.now() - cache.timestamp;
			if (age < UPDATE_CHECK_INTERVAL) {
				// Return cached result
				if (cache.latestVersion && compareVersions(cache.latestVersion, VERSION) > 0) {
					return {
						currentVersion: VERSION,
						latestVersion: cache.latestVersion,
						releaseUrl: cache.releaseUrl,
						downloadUrl: cache.downloadUrl,
						cached: true,
					};
				}

				return null;
			}
		}

		// Fetch latest release from GitHub API
		const response = await fetch('https://api.github.com/repos/spamscanner/spamscanner/releases/latest', {
			headers: {
				Accept: 'application/vnd.github.v3+json',
				'User-Agent': `spamscanner-cli/${VERSION}`,
			},
		});

		if (!response.ok) {
			return null;
		}

		const release = await response.json();
		const latestVersion = release.tag_name.replace(/^v/, '');

		// Find the download URL for current platform
		const binaryName = getBinaryName();
		const asset = release.assets.find(a => a.name === binaryName);
		const downloadUrl = asset?.browser_download_url;

		// Cache the result
		const cacheData = {
			timestamp: Date.now(),
			latestVersion,
			releaseUrl: release.html_url,
			downloadUrl,
		};

		try {
			if (!existsSync(UPDATE_CACHE_DIR)) {
				mkdirSync(UPDATE_CACHE_DIR, {recursive: true});
			}

			writeFileSync(UPDATE_CACHE_FILE, JSON.stringify(cacheData, null, 2));
		} catch {
			// Ignore cache write errors
		}

		// Check if update is available
		if (compareVersions(latestVersion, VERSION) > 0) {
			return {
				currentVersion: VERSION,
				latestVersion,
				releaseUrl: release.html_url,
				downloadUrl,
				cached: false,
			};
		}

		return null;
	} catch {
		return null;
	}
}

/**
 * Print update notification if available
 * @param {boolean} force - Force check even if recently checked
 */
async function printUpdateNotification(force = false) {
	const update = await checkForUpdates(force);
	if (update) {
		const {platform} = process;
		console.error('');
		console.error('╭─────────────────────────────────────────────────────────────╮');
		console.error(`│  Update available: ${update.currentVersion} → ${update.latestVersion.padEnd(37)}│`);
		console.error('│                                                             │');
		if (update.downloadUrl) {
			console.error('│  To update, run one of:                                     │');
			if (platform === 'darwin') {
				console.error('│    curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash │');
			} else if (platform === 'win32') {
				console.error('│    irm https://github.com/spamscanner/spamscanner/releases/latest/download/install.ps1 | iex │');
			} else {
				console.error('│    curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash │');
			}

			console.error('│                                                             │');
			console.error('│  Or download manually from:                                 │');
		} else {
			console.error('│  Download from:                                             │');
		}

		console.error('│    https://github.com/spamscanner/spamscanner/releases      │');
		console.error('╰─────────────────────────────────────────────────────────────╯');
		console.error('');
	}
}

/**
 * Format the list of supported languages for help text
 * @returns {string} Formatted language list
 */
function formatLanguageList() {
	const entries = Object.entries(SUPPORTED_LANGUAGES);
	const lines = [];
	for (let i = 0; i < entries.length; i += 4) {
		const chunk = entries.slice(i, i + 4);
		const formatted = chunk.map(([code, name]) => `${code} (${name})`).join(', ');
		lines.push(`    ${formatted}`);
	}

	return lines.join('\n');
}

const HELP_TEXT = `
SpamScanner CLI v${VERSION}

Usage:
  spamscanner <command> [options]

Commands:
  scan <file>     Scan an email file for spam
  scan -          Scan email from stdin
  server          Start TCP server mode
  update          Check for updates
  help            Show this help message
  version         Show version number

General Options:
  -h, --help      Show help
  -v, --version   Show version
  -j, --json      Output results as JSON
  --verbose       Show detailed output
  --debug         Enable debug mode
  --timeout <ms>  Scan timeout in milliseconds (default: 30000)
  --no-update-check  Disable automatic update check

Spam Detection Options:
  --threshold <score>     Spam score threshold (default: 5.0)
  --check-classifier      Include Bayesian classifier in scoring (default: true)
  --check-phishing        Include phishing detection in scoring (default: true)
  --check-executables     Include executable detection in scoring (default: true)
  --check-macros          Include macro detection in scoring (default: true)
  --check-virus           Include virus detection in scoring (default: true)
  --check-nsfw            Include NSFW detection in scoring (default: false)
  --check-toxicity        Include toxicity detection in scoring (default: false)
  --no-classifier         Disable Bayesian classifier scoring
  --no-phishing           Disable phishing scoring
  --no-executables        Disable executable scoring
  --no-macros             Disable macro scoring
  --no-virus              Disable virus scoring

Score Weights (customize scoring):
  --score-classifier <n>  Classifier spam score weight (default: 5.0)
  --score-phishing <n>    Phishing score per issue (default: 5.0)
  --score-executable <n>  Executable score per file (default: 10.0)
  --score-macro <n>       Macro score per detection (default: 5.0)
  --score-virus <n>       Virus score per detection (default: 100.0)
  --score-nsfw <n>        NSFW score per detection (default: 3.0)
  --score-toxicity <n>    Toxicity score per detection (default: 3.0)

Scanner Configuration Options:
  --languages <list>      Comma-separated list of supported language codes (default: all)
                          Use empty string or 'all' for all languages
  --mixed-language        Enable mixed language detection in emails
  --no-macro-detection    Disable macro detection in attachments
  --no-pattern-recognition  Disable advanced pattern recognition
  --strict-idn            Enable strict IDN/homograph detection
  --nsfw-threshold <n>    NSFW detection threshold 0.0-1.0 (default: 0.6)
  --toxicity-threshold <n>  Toxicity detection threshold 0.0-1.0 (default: 0.7)
  --clamscan-path <path>  Path to clamscan binary (default: /usr/bin/clamscan)
  --clamdscan-path <path> Path to clamdscan binary (default: /usr/bin/clamdscan)

Authentication Options (mailauth):
  --enable-auth           Enable DKIM/SPF/ARC/DMARC/BIMI authentication
  --sender-ip <ip>        Remote IP address of the sender (required for auth)
  --sender-hostname <host>  Resolved hostname of the sender (from reverse DNS)
  --helo <hostname>       HELO/EHLO hostname
  --sender <email>        Envelope sender (MAIL FROM)
  --mta <hostname>        MTA hostname for auth headers (default: spamscanner)
  --auth-timeout <ms>     DNS lookup timeout for auth (default: 10000)

Reputation Options (Forward Email API):
  --enable-reputation     Enable Forward Email reputation checking
  --reputation-url <url>  Custom reputation API URL
  --reputation-timeout <ms>  Reputation API timeout (default: 10000)
  --only-aligned          Only check aligned/authenticated attributes for reputation (default: true)
  --no-only-aligned       Check all attributes regardless of alignment

Header Options:
  --add-headers           Add X-Spam-* headers to output (for mail server integration)
  --add-auth-headers      Add Authentication-Results header to output
  --prepend-subject       Prepend [SPAM] to subject if spam detected
  --subject-tag <tag>     Custom subject tag (default: [SPAM])

Server Options:
  --port <port>   TCP server port (default: 7830)
  --host <host>   TCP server host (default: 127.0.0.1)

Supported Languages (use ISO 639-1 codes with --languages):
${formatLanguageList()}

Examples:
  # Scan a file
  spamscanner scan email.eml

  # Scan from stdin (for Postfix integration)
  cat email.eml | spamscanner scan -

  # Scan with JSON output
  spamscanner scan email.eml --json

  # Scan with custom threshold
  spamscanner scan email.eml --threshold 3.0

  # Scan with only classifier and phishing checks
  spamscanner scan email.eml --no-executables --no-macros --no-virus

  # Scan and add spam headers (for mail server integration)
  spamscanner scan email.eml --add-headers --prepend-subject

  # Scan with specific language support
  spamscanner scan email.eml --languages en,es,fr

  # Scan with mixed language detection
  spamscanner scan email.eml --mixed-language

  # Start TCP server
  spamscanner server --port 7830

  # Scan with authentication (DKIM/SPF/DMARC)
  spamscanner scan email.eml --enable-auth --sender-ip 192.168.1.1 --sender user@example.com

  # Scan with reputation checking
  spamscanner scan email.eml --enable-reputation

  # Full mail server integration
  spamscanner scan email.eml --enable-auth --enable-reputation --sender-ip 192.168.1.1 --add-headers --add-auth-headers

  # Check for updates
  spamscanner update

Exit Codes:
  0 - Clean (not spam)
  1 - Spam detected
  2 - Error occurred

X-Spam Headers (when --add-headers is used):
  X-Spam-Status: Yes/No, score=X.X required=Y.Y tests=TEST1,TEST2,...
  X-Spam-Score: X.X
  X-Spam-Flag: YES/NO
  X-Spam-Tests: Comma-separated list of triggered tests
`;

/**
 * Parse command line arguments
 * @param {string[]} args - Command line arguments
 * @returns {object} Parsed arguments
 */
function parseArgs(args) {
	const result = {
		command: null,
		file: null,
		json: false,
		verbose: false,
		debug: false,
		port: 7830,
		host: '127.0.0.1',
		timeout: 30_000,
		help: false,
		version: false,
		noUpdateCheck: false,
		// Spam detection options
		threshold: 5,
		checkClassifier: true,
		checkPhishing: true,
		checkExecutables: true,
		checkMacros: true,
		checkVirus: true,
		checkNsfw: false,
		checkToxicity: false,
		// Score weights
		scores: {...DEFAULT_SCORES},
		// Header options
		addHeaders: false,
		prependSubject: false,
		subjectTag: '[SPAM]',
		// Scanner configuration options
		supportedLanguages: [], // Empty = all languages
		enableMixedLanguageDetection: false,
		enableMacroDetection: true,
		enableAdvancedPatternRecognition: true,
		strictIdnDetection: false,
		nsfwThreshold: 0.6,
		toxicityThreshold: 0.7,
		clamscanPath: '/usr/bin/clamscan',
		clamdscanPath: '/usr/bin/clamdscan',
		// Authentication options
		enableAuth: false,
		senderIp: null,
		senderHostname: null,
		helo: null,
		sender: null,
		mta: 'spamscanner',
		authTimeout: 10_000,
		// Reputation options
		enableReputation: false,
		reputationUrl: 'https://api.forwardemail.net/v1/reputation',
		reputationTimeout: 10_000,
		onlyAligned: true,
		// Additional header options
		addAuthHeaders: false,
	};

	for (let index = 0; index < args.length; index++) {
		const arg = args[index];

		switch (arg) {
			case 'scan':
			case 'server':
			case 'help':
			case 'version':
			case 'update': {
				result.command = arg;
				break;
			}

			case '-h':
			case '--help': {
				result.help = true;
				break;
			}

			case '-v':
			case '--version': {
				result.version = true;
				break;
			}

			case '-j':
			case '--json': {
				result.json = true;
				break;
			}

			case '--verbose': {
				result.verbose = true;
				break;
			}

			case '--debug': {
				result.debug = true;
				break;
			}

			case '--no-update-check': {
				result.noUpdateCheck = true;
				break;
			}

			case '--port': {
				result.port = Number.parseInt(args[++index], 10);
				break;
			}

			case '--host': {
				result.host = args[++index];
				break;
			}

			case '--timeout': {
				result.timeout = Number.parseInt(args[++index], 10);
				break;
			}

			// Spam detection options
			case '--threshold': {
				result.threshold = Number.parseFloat(args[++index]);
				break;
			}

			case '--check-classifier': {
				result.checkClassifier = true;
				break;
			}

			case '--check-phishing': {
				result.checkPhishing = true;
				break;
			}

			case '--check-executables': {
				result.checkExecutables = true;
				break;
			}

			case '--check-macros': {
				result.checkMacros = true;
				break;
			}

			case '--check-virus': {
				result.checkVirus = true;
				break;
			}

			case '--check-nsfw': {
				result.checkNsfw = true;
				break;
			}

			case '--check-toxicity': {
				result.checkToxicity = true;
				break;
			}

			case '--no-classifier': {
				result.checkClassifier = false;
				break;
			}

			case '--no-phishing': {
				result.checkPhishing = false;
				break;
			}

			case '--no-executables': {
				result.checkExecutables = false;
				break;
			}

			case '--no-macros': {
				result.checkMacros = false;
				break;
			}

			case '--no-virus': {
				result.checkVirus = false;
				break;
			}

			// Score weights
			case '--score-classifier': {
				result.scores.classifier = Number.parseFloat(args[++index]);
				break;
			}

			case '--score-phishing': {
				result.scores.phishing = Number.parseFloat(args[++index]);
				break;
			}

			case '--score-executable': {
				result.scores.executable = Number.parseFloat(args[++index]);
				break;
			}

			case '--score-macro': {
				result.scores.macro = Number.parseFloat(args[++index]);
				break;
			}

			case '--score-virus': {
				result.scores.virus = Number.parseFloat(args[++index]);
				break;
			}

			case '--score-nsfw': {
				result.scores.nsfw = Number.parseFloat(args[++index]);
				break;
			}

			case '--score-toxicity': {
				result.scores.toxicity = Number.parseFloat(args[++index]);
				break;
			}

			// Header options
			case '--add-headers': {
				result.addHeaders = true;
				break;
			}

			case '--prepend-subject': {
				result.prependSubject = true;
				break;
			}

			case '--subject-tag': {
				result.subjectTag = args[++index];
				break;
			}

			// Scanner configuration options
			case '--languages': {
				const langArg = args[++index];
				result.supportedLanguages = langArg && langArg !== 'all' && langArg !== '' ? langArg.split(',').map(l => l.trim().toLowerCase()) : [];

				break;
			}

			case '--mixed-language': {
				result.enableMixedLanguageDetection = true;
				break;
			}

			case '--no-macro-detection': {
				result.enableMacroDetection = false;
				break;
			}

			case '--no-pattern-recognition': {
				result.enableAdvancedPatternRecognition = false;
				break;
			}

			case '--strict-idn': {
				result.strictIdnDetection = true;
				break;
			}

			case '--nsfw-threshold': {
				result.nsfwThreshold = Number.parseFloat(args[++index]);
				break;
			}

			case '--toxicity-threshold': {
				result.toxicityThreshold = Number.parseFloat(args[++index]);
				break;
			}

			case '--clamscan-path': {
				result.clamscanPath = args[++index];
				break;
			}

			case '--clamdscan-path': {
				result.clamdscanPath = args[++index];
				break;
			}

			// Authentication options
			case '--enable-auth': {
				result.enableAuth = true;
				break;
			}

			case '--sender-ip': {
				result.senderIp = args[++index];
				break;
			}

			case '--sender-hostname': {
				result.senderHostname = args[++index];
				break;
			}

			case '--helo': {
				result.helo = args[++index];
				break;
			}

			case '--sender': {
				result.sender = args[++index];
				break;
			}

			case '--mta': {
				result.mta = args[++index];
				break;
			}

			case '--auth-timeout': {
				result.authTimeout = Number.parseInt(args[++index], 10);
				break;
			}

			// Reputation options
			case '--enable-reputation': {
				result.enableReputation = true;
				break;
			}

			case '--reputation-url': {
				result.reputationUrl = args[++index];
				break;
			}

			case '--reputation-timeout': {
				result.reputationTimeout = Number.parseInt(args[++index], 10);
				break;
			}

			case '--only-aligned': {
				result.onlyAligned = true;
				break;
			}

			case '--no-only-aligned': {
				result.onlyAligned = false;
				break;
			}

			// Additional header options
			case '--add-auth-headers': {
				result.addAuthHeaders = true;
				break;
			}

			default: {
				if (!result.file && result.command === 'scan'
					&& (arg === '-' || !arg.startsWith('-'))) {
					result.file = arg;
				}
			}
		}
	}

	return result;
}

/**
 * Read email content from file or stdin
 * @param {string} file - File path or '-' for stdin
 * @returns {Promise<Buffer>} Email content
 */
async function readEmail(file) {
	if (file === '-') {
		// Read from stdin
		const chunks = [];
		for await (const chunk of process.stdin) {
			chunks.push(chunk);
		}

		return Buffer.concat(chunks);
	}

	// Read from file
	const chunks = [];
	const stream = createReadStream(file);
	for await (const chunk of stream) {
		chunks.push(chunk);
	}

	return Buffer.concat(chunks);
}

/**
 * Calculate spam score based on scan results and options
 * @param {object} result - Scan result from SpamScanner
 * @param {object} options - CLI options
 * @returns {object} Score details
 */
function calculateScore(result, options) {
	const {scores} = options;
	const tests = [];
	let totalScore = 0;

	// Classifier score
	if (options.checkClassifier && result.results?.classification) {
		const {category, probability} = result.results.classification;
		if (category === 'spam') {
			// Scale score by probability (0.5-1.0 maps to 0-full score)
			const scaledScore = scores.classifier * Math.max(0, (probability - 0.5) * 2);
			totalScore += scaledScore;
			tests.push(`BAYES_SPAM(${scaledScore.toFixed(1)})`);
		} else if (category === 'ham' && probability > 0.8) {
			// Give negative score for confident ham
			const hamBonus = -1 * (probability - 0.8) * 5;
			totalScore += hamBonus;
			tests.push(`BAYES_HAM(${hamBonus.toFixed(1)})`);
		}
	}

	// Phishing score
	if (options.checkPhishing && result.results?.phishing?.length > 0) {
		const phishingScore = result.results.phishing.length * scores.phishing;
		totalScore += phishingScore;
		tests.push(`PHISHING_DETECTED(${phishingScore.toFixed(1)})`);
	}

	// Executable score
	if (options.checkExecutables && result.results?.executables?.length > 0) {
		const execScore = result.results.executables.length * scores.executable;
		totalScore += execScore;
		tests.push(`EXECUTABLE_ATTACHMENT(${execScore.toFixed(1)})`);
	}

	// Macro score
	if (options.checkMacros && result.results?.macros?.length > 0) {
		const macroScore = result.results.macros.length * scores.macro;
		totalScore += macroScore;
		tests.push(`MACRO_DETECTED(${macroScore.toFixed(1)})`);
	}

	// Virus score
	if (options.checkVirus && result.results?.viruses?.length > 0) {
		const virusScore = result.results.viruses.length * scores.virus;
		totalScore += virusScore;
		tests.push(`VIRUS_DETECTED(${virusScore.toFixed(1)})`);
	}

	// NSFW score
	if (options.checkNsfw && result.results?.nsfw?.length > 0) {
		const nsfwScore = result.results.nsfw.length * scores.nsfw;
		totalScore += nsfwScore;
		tests.push(`NSFW_CONTENT(${nsfwScore.toFixed(1)})`);
	}

	// Toxicity score
	if (options.checkToxicity && result.results?.toxicity?.length > 0) {
		const toxicScore = result.results.toxicity.length * scores.toxicity;
		totalScore += toxicScore;
		tests.push(`TOXIC_CONTENT(${toxicScore.toFixed(1)})`);
	}

	// Authentication score (from mailauth)
	if (result.results?.authentication?.score) {
		const authScore = result.results.authentication.score;
		totalScore += authScore.score;
		tests.push(...authScore.tests);
	}

	// Reputation score
	if (result.results?.reputation) {
		const rep = result.results.reputation;
		if (rep.isDenylisted) {
			totalScore += 10;
			tests.push('DENYLISTED(10.0)');
		}

		if (rep.isTruthSource) {
			totalScore -= 5;
			tests.push('TRUTH_SOURCE(-5.0)');
		} else if (rep.isAllowlisted) {
			totalScore -= 3;
			tests.push('ALLOWLISTED(-3.0)');
		}
	}

	let isSpam = totalScore >= options.threshold;

	// Override spam status based on reputation
	if (result.results?.reputation) {
		const rep = result.results.reputation;
		if (rep.isDenylisted) {
			isSpam = true;
		} else if ((rep.isTruthSource || rep.isAllowlisted) && !result.results?.viruses?.length && !result.results?.executables?.length) {
			isSpam = false;
		}
	}

	return {
		score: totalScore,
		threshold: options.threshold,
		isSpam,
		tests,
	};
}

/**
 * Generate X-Spam headers based on scan results
 * @param {object} scoreDetails - Score calculation details
 * @returns {object} Headers object
 */
function generateSpamHeaders(scoreDetails) {
	const {score, threshold, isSpam, tests} = scoreDetails;
	const status = isSpam ? 'Yes' : 'No';
	const flag = isSpam ? 'YES' : 'NO';

	return {
		'X-Spam-Status': `${status}, score=${score.toFixed(1)} required=${threshold.toFixed(1)} tests=${tests.join(',')} version=${VERSION}`,
		'X-Spam-Score': score.toFixed(1),
		'X-Spam-Flag': flag,
		'X-Spam-Tests': tests.join(', '),
	};
}

/**
 * Modify email content with spam headers and subject tag
 * @param {Buffer} emailContent - Original email content
 * @param {object} options - CLI options
 * @param {object} scoreDetails - Score calculation details
 * @returns {string} Modified email content
 */
function modifyEmail(emailContent, options, scoreDetails, authResultsHeader = null) {
	const emailString = emailContent.toString('utf8');
	const headers = generateSpamHeaders(scoreDetails);

	// Add Authentication-Results header if available
	if (options.addAuthHeaders && authResultsHeader) {
		headers['Authentication-Results'] = authResultsHeader;
	}

	// Find the header/body boundary
	const headerEndMatch = emailString.match(/\r?\n\r?\n/);
	if (!headerEndMatch) {
		// No body, just append headers
		return emailString + '\r\n' + Object.entries(headers)
			.map(([key, value]) => `${key}: ${value}`)
			.join('\r\n');
	}

	const headerEndIndex = headerEndMatch.index;
	const lineEnding = headerEndMatch[0].startsWith('\r\n') ? '\r\n' : '\n';
	const headerPart = emailString.slice(0, headerEndIndex);
	const bodyPart = emailString.slice(headerEndIndex);

	// Add X-Spam headers
	let newHeaders = headerPart;
	if (options.addHeaders) {
		const headerLines = Object.entries(headers)
			.map(([key, value]) => `${key}: ${value}`)
			.join(lineEnding);
		newHeaders = headerPart + lineEnding + headerLines;
	}

	// Prepend subject tag if spam
	if (options.prependSubject && scoreDetails.isSpam) {
		const subjectMatch = newHeaders.match(/^(subject:\s*)(.*)$/im);
		if (subjectMatch) {
			const [fullMatch, prefix, subject] = subjectMatch;
			// Only prepend if not already tagged
			if (!subject.startsWith(options.subjectTag)) {
				const newSubject = `${prefix}${options.subjectTag} ${subject}`;
				newHeaders = newHeaders.replace(fullMatch, newSubject);
			}
		}
	}

	return newHeaders + bodyPart;
}

/**
 * Format scan results for human-readable output
 * @param {object} result - Scan result
 * @param {object} scoreDetails - Score calculation details
 * @param {boolean} verbose - Show verbose output
 * @returns {string} Formatted output
 */
function formatResult(result, scoreDetails, verbose) {
	const lines = [];
	const {score, threshold, isSpam, tests} = scoreDetails;

	if (isSpam) {
		lines.push(`SPAM DETECTED (score: ${score.toFixed(1)}, threshold: ${threshold.toFixed(1)})`);
	} else {
		lines.push(`Clean (score: ${score.toFixed(1)}, threshold: ${threshold.toFixed(1)})`);
	}

	if (tests.length > 0) {
		lines.push(`Tests: ${tests.join(', ')}`);
	}

	if (verbose) {
		lines.push('', 'Details:');

		if (result.results?.classification) {
			const prob = (result.results.classification.probability * 100).toFixed(1);
			lines.push(`  Classification: ${result.results.classification.category} (${prob}%)`);
		}

		if (result.results?.phishing?.length > 0) {
			lines.push(`  Phishing: ${result.results.phishing.length} issue(s) detected`);
			for (const issue of result.results.phishing) {
				lines.push(`    - ${issue.type}: ${issue.description || issue.message || 'N/A'}`);
			}
		}

		if (result.results?.executables?.length > 0) {
			lines.push(`  Executables: ${result.results.executables.length} dangerous file(s) detected`);
			for (const exec of result.results.executables) {
				lines.push(`    - ${exec.filename || exec.extension || 'Unknown'}`);
			}
		}

		if (result.results?.viruses?.length > 0) {
			lines.push(`  Viruses: ${result.results.viruses.length} virus(es) detected`);
			for (const virus of result.results.viruses) {
				lines.push(`    - ${virus.name || virus.message || 'Unknown'}`);
			}
		}

		if (result.results?.macros?.length > 0) {
			lines.push(`  Macros: ${result.results.macros.length} macro(s) detected`);
		}

		if (result.results?.toxicity?.length > 0) {
			lines.push(`  Toxicity: ${result.results.toxicity.length} toxic content detected`);
		}

		if (result.results?.nsfw?.length > 0) {
			lines.push(`  NSFW: ${result.results.nsfw.length} NSFW content detected`);
		}

		// Authentication results
		if (result.results?.authentication) {
			const auth = result.results.authentication;
			lines.push('', '  Authentication:');
			if (auth.dkim?.status?.result) {
				lines.push(`    DKIM: ${auth.dkim.status.result}`);
			}

			if (auth.spf?.status?.result) {
				lines.push(`    SPF: ${auth.spf.status.result}`);
			}

			if (auth.dmarc?.status?.result) {
				lines.push(`    DMARC: ${auth.dmarc.status.result}`);
			}

			if (auth.arc?.status?.result) {
				lines.push(`    ARC: ${auth.arc.status.result}`);
			}
		}

		// Reputation results
		if (result.results?.reputation) {
			const rep = result.results.reputation;
			lines.push('', '  Reputation:');
			if (rep.isTruthSource) {
				lines.push('    Status: Truth Source');
			} else if (rep.isAllowlisted) {
				lines.push(`    Status: Allowlisted (${rep.allowlistValue || 'N/A'})`);
			} else if (rep.isDenylisted) {
				lines.push(`    Status: DENYLISTED (${rep.denylistValue || 'N/A'})`);
			} else {
				lines.push('    Status: Unknown');
			}

			if (rep.checkedValues?.length > 0) {
				lines.push(`    Checked: ${rep.checkedValues.join(', ')}`);
			}
		}
	}

	return lines.join('\n');
}

/**
 * Build SpamScanner configuration from CLI options
 * @param {object} options - CLI options
 * @returns {object} SpamScanner configuration
 */
function buildScannerConfig(options) {
	return {
		debug: options.debug,
		timeout: options.timeout,
		supportedLanguages: options.supportedLanguages,
		enableMixedLanguageDetection: options.enableMixedLanguageDetection,
		enableMacroDetection: options.enableMacroDetection,
		enableAdvancedPatternRecognition: options.enableAdvancedPatternRecognition,
		strictIDNDetection: options.strictIdnDetection,
		nsfwThreshold: options.nsfwThreshold,
		toxicityThreshold: options.toxicityThreshold,
		clamscan: {
			clamscanPath: options.clamscanPath,
			clamdscanPath: options.clamdscanPath,
		},
		// Authentication options
		enableAuthentication: options.enableAuth,
		authOptions: {
			ip: options.senderIp,
			hostname: options.senderHostname,
			helo: options.helo,
			mta: options.mta,
			sender: options.sender,
			timeout: options.authTimeout,
		},
		// Reputation options
		enableReputation: options.enableReputation,
		reputationOptions: {
			apiUrl: options.reputationUrl,
			timeout: options.reputationTimeout,
			onlyAligned: options.onlyAligned,
		},
	};
}

/**
 * Scan an email and output results
 * @param {object} options - Scan options
 */
async function scanCommand(options) {
	const {file, json, verbose, addHeaders, prependSubject} = options;

	if (!file) {
		console.error('Error: No file specified. Use "spamscanner scan <file>" or "spamscanner scan -" for stdin.');
		process.exit(2);
	}

	try {
		// Check if file exists (unless reading from stdin)
		if (file !== '-') {
			try {
				readFileSync(file);
			} catch {
				console.error(`Error: File not found: ${file}`);
				process.exit(2);
			}
		}

		const scannerConfig = buildScannerConfig(options);
		const scanner = new SpamScanner(scannerConfig);

		const emailContent = await readEmail(file);
		const result = await scanner.scan(emailContent);

		// Calculate score based on options
		const scoreDetails = calculateScore(result, options);

		// Generate output
		const output = {
			isSpam: scoreDetails.isSpam,
			score: scoreDetails.score,
			threshold: scoreDetails.threshold,
			tests: scoreDetails.tests,
			message: result.message,
			results: result.results,
			links: result.links,
			tokens: result.tokens,
			mail: result.mail,
		};

		// Add headers if requested
		if (addHeaders || prependSubject || options.addAuthHeaders) {
			output.headers = generateSpamHeaders(scoreDetails);
			const authResultsHeader = result.results?.authentication?.authResultsHeader || null;
			output.modifiedEmail = modifyEmail(emailContent, options, scoreDetails, authResultsHeader);
		}

		if (json) {
			console.log(JSON.stringify(output, null, 2));
		} else if (addHeaders || prependSubject || options.addAuthHeaders) {
			// Output modified email for piping to mail server
			console.log(output.modifiedEmail);
		} else {
			console.log(formatResult(result, scoreDetails, verbose));
		}

		process.exit(scoreDetails.isSpam ? 1 : 0);
	} catch (error) {
		console.error(`Error scanning email: ${error.message}`);
		if (options.debug) {
			console.error(error.stack);
		}

		process.exit(2);
	}
}

/**
 * Start TCP server for high-volume scanning
 * @param {object} options - Server options
 */
async function serverCommand(options) {
	const {port, host, json, verbose, debug} = options;

	const scannerConfig = buildScannerConfig(options);
	const scanner = new SpamScanner(scannerConfig);

	const server = createServer(socket => {
		const chunks = [];

		socket.on('data', chunk => {
			chunks.push(chunk);
		});

		socket.on('end', async () => {
			try {
				const emailContent = Buffer.concat(chunks);
				const result = await scanner.scan(emailContent);
				const scoreDetails = calculateScore(result, options);

				const output = {
					isSpam: scoreDetails.isSpam,
					score: scoreDetails.score,
					threshold: scoreDetails.threshold,
					tests: scoreDetails.tests,
					message: result.message,
				};

				if (options.addHeaders) {
					output.headers = generateSpamHeaders(scoreDetails);
				}

				if (json) {
					socket.write(JSON.stringify(output));
				} else {
					socket.write(formatResult(result, scoreDetails, verbose));
				}
			} catch (error) {
				const errorResponse = json
					? JSON.stringify({error: error.message})
					: `Error: ${error.message}`;
				socket.write(errorResponse);
				if (debug) {
					console.error(error.stack);
				}
			}

			socket.end();
		});

		socket.on('error', error => {
			console.error(`Socket error: ${error.message}`);
		});
	});

	server.listen(port, host, () => {
		console.log(`SpamScanner TCP server listening on ${host}:${port}`);
		console.log('Send email content to scan, close connection to receive results.');
		console.log('Press Ctrl+C to stop.');
	});

	server.on('error', error => {
		console.error(`Server error: ${error.message}`);
		process.exit(2);
	});
}

/**
 * Main entry point
 */
async function main() {
	const args = process.argv.slice(2);
	const options = parseArgs(args);

	// Handle help and version flags first
	if (options.help) {
		console.log(HELP_TEXT);
		process.exit(0);
	}

	if (options.version) {
		console.log(`SpamScanner v${VERSION}`);
		process.exit(0);
	}

	// Check for updates (unless disabled)
	if (!options.noUpdateCheck && options.command !== 'update') {
		// Run update check in background, don't block
		// eslint-disable-next-line promise/prefer-await-to-then, no-void
		void printUpdateNotification().catch(() => {
			// Ignore errors
		});
	}

	// Handle commands
	switch (options.command) {
		case 'scan': {
			await scanCommand(options);
			break;
		}

		case 'server': {
			await serverCommand(options);
			break;
		}

		case 'update': {
			console.log(`SpamScanner v${VERSION}`);
			console.log('Checking for updates...');
			const update = await checkForUpdates(true);
			if (update) {
				console.log(`New version available: ${update.latestVersion}`);
				console.log(`Download from: ${update.releaseUrl}`);
				if (update.downloadUrl) {
					console.log(`Direct download: ${update.downloadUrl}`);
				}
			} else {
				console.log('You are running the latest version.');
			}

			process.exit(0);
			break;
		}

		case 'help': {
			console.log(HELP_TEXT);
			process.exit(0);
			break;
		}

		case 'version': {
			console.log(`SpamScanner v${VERSION}`);
			process.exit(0);
			break;
		}

		default: {
			console.error('Unknown command. Use "spamscanner help" for usage information.');
			process.exit(2);
		}
	}
}

main().catch(error => {
	console.error(`Fatal error: ${error.message}`);
	process.exit(2);
});
