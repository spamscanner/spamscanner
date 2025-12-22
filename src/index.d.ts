import type {ParsedMail, Attachment} from 'mailparser';
import type {AuthResult, AuthOptions, AuthScoreWeights, AuthScoreResult} from './auth.d.ts';
import type {ReputationResult, ReputationOptions} from './reputation.d.ts';
import type {SessionInfo, GetAttributesOptions, ExtractAttributesResult} from './get-attributes.d.ts';
import type {ArbitraryResult, ArbitraryOptions} from './is-arbitrary.d.ts';

// Re-export auth and reputation types
export type {AuthResult, AuthOptions, AuthScoreWeights, AuthScoreResult} from './auth.d.ts';
export type {ReputationResult, ReputationOptions} from './reputation.d.ts';
export type {SessionInfo, GetAttributesOptions, ExtractAttributesResult} from './get-attributes.d.ts';
export type {ArbitraryResult, ArbitraryOptions} from './is-arbitrary.d.ts';

/**
 * ClamScan configuration options
 */
export type ClamScanConfig = {
	/** Remove infected files automatically */
	removeInfected?: boolean;
	/** Quarantine infected files */
	quarantineInfected?: boolean;
	/** Path to scan log file */
	scanLog?: string | undefined;
	/** Enable debug mode for ClamScan */
	debugMode?: boolean;
	/** File list to scan */
	fileList?: string | undefined;
	/** Scan directories recursively */
	scanRecursively?: boolean;
	/** Path to clamscan binary */
	clamscanPath?: string;
	/** Path to clamdscan binary */
	clamdscanPath?: string;
	/** Preferred scanner to use */
	preference?: 'clamscan' | 'clamdscan';
};

/**
 * SpamScanner configuration options
 */
export type SpamScannerConfig = {
	/** Enable macro detection in documents */
	enableMacroDetection?: boolean;
	/** Enable performance metrics collection */
	enablePerformanceMetrics?: boolean;
	/** Timeout for operations in milliseconds */
	timeout?: number;
	/** List of supported languages for detection */
	supportedLanguages?: string[];
	/** Enable mixed language detection */
	enableMixedLanguageDetection?: boolean;
	/** Enable advanced pattern recognition */
	enableAdvancedPatternRecognition?: boolean;
	/** Enable debug mode */
	debug?: boolean;
	/** Logger instance */
	logger?: Console | {
		log: (...args: unknown[]) => void;
		error: (...args: unknown[]) => void;
		warn: (...args: unknown[]) => void;
		info: (...args: unknown[]) => void;
		debug: (...args: unknown[]) => void;
	};
	/** ClamScan configuration */
	clamscan?: ClamScanConfig;
	/** Pre-trained classifier data */
	classifier?: Record<string, unknown> | undefined;
	/** Replacement word mappings */
	replacements?: Map<string, string> | Record<string, string> | undefined;
	/** Enable NSFW detection */
	enableNsfwDetection?: boolean;
	/** Enable toxicity detection */
	enableToxicityDetection?: boolean;
	/** Toxicity detection threshold (0-1) */
	toxicityThreshold?: number;
	/** NSFW detection threshold (0-1) */
	nsfwThreshold?: number;
	/** Enable strict IDN detection */
	strictIdnDetection?: boolean;
	/** Enable token hashing */
	hashTokens?: boolean;
	/** Enable email authentication (DKIM/SPF/ARC/DMARC/BIMI) */
	enableAuthentication?: boolean;
	/** Authentication options */
	authOptions?: AuthOptions;
	/** Authentication score weights */
	authScoreWeights?: AuthScoreWeights;
	/** Enable Forward Email reputation checking */
	enableReputation?: boolean;
	/** Reputation API options */
	reputationOptions?: ReputationOptions;
	/** Enable arbitrary spam detection */
	enableArbitraryDetection?: boolean;
	/** Arbitrary spam score threshold */
	arbitraryThreshold?: number;
};

/**
 * Classification result
 */
export type ClassificationResult = {
	/** Classification category */
	category: 'spam' | 'ham';
	/** Classification probability */
	probability: number;
};

/**
 * Phishing detection result
 */
export type PhishingResult = {
	/** Type of detection */
	type: 'phishing' | 'suspicious';
	/** The URL that was flagged */
	url: string;
	/** Description of the issue */
	description: string;
	/** Additional details */
	details?: {
		riskFactors?: string[];
		recommendations?: string[];
		confidence?: number;
	};
};

/**
 * Executable detection result
 */
export type ExecutableResult = {
	/** Type of detection */
	type: 'executable' | 'archive';
	/** Filename of the attachment */
	filename: string;
	/** File extension */
	extension?: string;
	/** Detected file type */
	detectedType?: string;
	/** Description of the issue */
	description: string;
	/** Risk level */
	risk?: 'low' | 'medium' | 'high';
	/** Warning message */
	warning?: string;
};

/**
 * Macro detection result
 */
export type MacroResult = {
	/** Type of detection */
	type: 'macro';
	/** Subtype of macro */
	subtype: 'vba' | 'powershell' | 'javascript' | 'batch' | 'script' | 'office_document' | 'legacy_office' | 'pdf_javascript';
	/** Filename if from attachment */
	filename?: string;
	/** Description of the issue */
	description: string;
	/** Risk level */
	risk?: 'low' | 'medium' | 'high';
};

/**
 * Arbitrary detection result (e.g., GTUBE, spam patterns)
 */
export type ArbitraryResult = {
	/** Type of detection */
	type: 'arbitrary';
	/** Subtype of arbitrary detection */
	subtype?: 'gtube' | 'pattern';
	/** Description of the issue */
	description: string;
	/** Arbitrary spam score */
	score?: number;
	/** List of reasons why the message was flagged */
	reasons?: string[];
};

/**
 * Virus detection result
 */
export type VirusResult = {
	/** Filename of the infected attachment */
	filename: string;
	/** Detected virus names */
	virus: string[];
	/** Type of detection */
	type: 'virus';
};

/**
 * Pattern detection result
 */
export type PatternResult = {
	/** Type of detection */
	type: 'pattern' | 'file_path';
	/** Subtype of pattern */
	subtype?: string;
	/** Count of matches */
	count?: number;
	/** Detected path */
	path?: string;
	/** Description of the issue */
	description: string;
};

/**
 * IDN Homograph attack detection result
 */
export type IdnHomographResult = {
	/** Whether an attack was detected */
	detected: boolean;
	/** List of suspicious domains */
	domains: IdnDomainAnalysis[];
	/** Overall risk score (0-1) */
	riskScore: number;
	/** Additional details */
	details: string[];
};

/**
 * IDN domain analysis
 */
export type IdnDomainAnalysis = {
	/** The domain analyzed */
	domain: string;
	/** Original URL */
	originalUrl: string;
	/** Normalized URL */
	normalizedUrl: string;
	/** Risk score (0-1) */
	riskScore: number;
	/** Risk factors identified */
	riskFactors: string[];
	/** Recommendations */
	recommendations: string[];
	/** Confidence level */
	confidence: number;
};

/**
 * Toxicity detection result
 */
export type ToxicityResult = {
	/** Type of detection */
	type: 'toxicity';
	/** Toxicity category */
	category: string;
	/** Probability of toxicity */
	probability: number;
	/** Description of the issue */
	description: string;
};

/**
 * NSFW detection result
 */
export type NsfwResult = {
	/** Type of detection */
	type: 'nsfw';
	/** Filename of the image */
	filename: string;
	/** NSFW category */
	category: 'Porn' | 'Hentai' | 'Sexy' | 'Drawing' | 'Neutral';
	/** Probability of NSFW content */
	probability: number;
	/** Description of the issue */
	description: string;
};

/**
 * All scan results
 */
/**
 * Extended authentication result with score
 */
export type AuthenticationResult = AuthResult & {
	/** Authentication score */
	score: AuthScoreResult;
	/** Formatted Authentication-Results header */
	authResultsHeader: string;
};

/**
 * Extended reputation result with details
 */
export type ExtendedReputationResult = ReputationResult & {
	/** Values that were checked */
	checkedValues: string[];
	/** Detailed results per value */
	details: Record<string, ReputationResult>;
};

/**
 * All scan results
 */
export type ScanResults = {
	/** Classification result */
	classification: ClassificationResult;
	/** Phishing detection results */
	phishing: PhishingResult[];
	/** Executable detection results */
	executables: ExecutableResult[];
	/** Macro detection results */
	macros: MacroResult[];
	/** Arbitrary pattern results */
	arbitrary: ArbitraryResult[];
	/** Virus detection results */
	viruses: VirusResult[];
	/** Pattern detection results */
	patterns: PatternResult[];
	/** IDN homograph attack results */
	idnHomographAttack: IdnHomographResult;
	/** Toxicity detection results */
	toxicity: ToxicityResult[];
	/** NSFW detection results */
	nsfw: NsfwResult[];
	/** Authentication results (if enabled) */
	authentication?: AuthenticationResult | null;
	/** Reputation results (if enabled) */
	reputation?: ExtendedReputationResult | null;
};

/**
 * Performance metrics
 */
export type PerformanceMetrics = {
	/** Total processing time in ms */
	totalTime: number;
	/** Classification time in ms */
	classificationTime: number;
	/** Phishing detection time in ms */
	phishingTime: number;
	/** Executable detection time in ms */
	executableTime: number;
	/** Macro detection time in ms */
	macroTime: number;
	/** Virus scan time in ms */
	virusTime: number;
	/** Pattern detection time in ms */
	patternTime: number;
	/** IDN detection time in ms */
	idnTime: number;
	/** Memory usage statistics */
	memoryUsage: NodeJS.MemoryUsage;
};

/**
 * Scanner metrics
 */
export type ScannerMetrics = {
	/** Total number of scans performed */
	totalScans: number;
	/** Average scan time in ms */
	averageTime: number;
	/** Last scan time in ms */
	lastScanTime: number;
};

/**
 * Scan result
 */
export type ScanResult = {
	/** Whether the email is spam */
	isSpam: boolean;
	/** Human-readable message */
	message: string;
	/** Detailed results from all detectors */
	results: ScanResults;
	/** Extracted URLs from the email */
	links: string[];
	/** Extracted tokens from the email */
	tokens: string[];
	/** Parsed mail object */
	mail: ParsedMail;
	/** Performance metrics (if enabled) */
	metrics?: PerformanceMetrics;
};

/**
 * Tokens and mail result from source parsing
 */
export type TokensAndMailResult = {
	/** Extracted tokens */
	tokens: string[];
	/** Parsed mail object */
	mail: ParsedMail;
};

/**
 * Parsed URL result using tldts
 */
export type ParsedUrl = {
	/** Full domain */
	domain: string | undefined;
	/** Domain without suffix */
	domainWithoutSuffix: string | undefined;
	/** Full hostname */
	hostname: string | undefined;
	/** Public suffix */
	publicSuffix: string | undefined;
	/** Subdomain */
	subdomain: string | undefined;
	/** Whether the hostname is an IP address */
	isIp: boolean;
	/** Whether the domain is ICANN registered */
	isIcann: boolean;
	/** Whether the domain is private */
	isPrivate: boolean;
};

/**
 * Mail object for internal processing
 */
export type MailObject = {
	/** Plain text content */
	text?: string;
	/** HTML content */
	html?: string;
	/** Email subject */
	subject?: string;
	/** From address */
	from?: Record<string, unknown>;
	/** To addresses */
	to?: unknown[];
	/** Attachments */
	attachments?: Attachment[];
	/** Header lines */
	headerLines?: Array<{line?: string}>;
	/** Headers map */
	headers?: Map<string, unknown> | Record<string, unknown>;
};

/**
 * Source input type for scanning
 */
export type ScanSource = string | Uint8Array;

/**
 * SpamScanner class for email spam detection
 */
declare class SpamScanner {
	/** Scanner configuration */
	config: SpamScannerConfig & {
		enableMacroDetection: boolean;
		enablePerformanceMetrics: boolean;
		timeout: number;
		supportedLanguages: string[];
		enableMixedLanguageDetection: boolean;
		enableAdvancedPatternRecognition: boolean;
		debug: boolean;
		logger: Console;
		clamscan: ClamScanConfig;
		classifier: Record<string, unknown> | undefined;
		replacements: Map<string, string> | Record<string, string> | undefined;
	};

	/** Naive Bayes classifier instance */
	classifier: unknown | undefined;

	/** ClamScan instance */
	clamscan: unknown | undefined;

	/** Whether the scanner is initialized */
	isInitialized: boolean;

	/** Replacement word mappings */
	replacements: Map<string, string>;

	/** Scanner metrics */
	metrics: ScannerMetrics;

	/**
	 * Create a new SpamScanner instance
	 * @param options - Configuration options
	 */
	constructor(options?: SpamScannerConfig);

	/**
	 * Initialize the classifier
	 */
	initializeClassifier(): Promise<void>;

	/**
	 * Initialize replacements
	 */
	initializeReplacements(): Promise<void>;

	/**
	 * Initialize regex helpers
	 */
	initializeRegex(): void;

	/**
	 * Scan options for per-scan configuration
	 */
	scanOptions?: {
		/** Enable authentication for this scan */
		enableAuthentication?: boolean;
		/** Authentication options for this scan */
		authOptions?: AuthOptions;
		/** Enable reputation checking for this scan */
		enableReputation?: boolean;
		/** Reputation options for this scan */
		reputationOptions?: ReputationOptions;
	};

	/**
	 * Scan an email for spam
	 * @param source - Email source (string, Uint8Array, or file path)
	 * @param scanOptions - Optional per-scan configuration
	 * @returns Scan result
	 */
	scan(source: ScanSource, scanOptions?: {
		enableAuthentication?: boolean;
		authOptions?: AuthOptions;
		enableReputation?: boolean;
		reputationOptions?: ReputationOptions;
	}): Promise<ScanResult>;

	/**
	 * Get tokens and parsed mail from source
	 * @param source - Email source
	 * @returns Tokens and mail object
	 */
	getTokensAndMailFromSource(source: ScanSource): Promise<TokensAndMailResult>;

	/**
	 * Get classification result for tokens
	 * @param tokens - Array of tokens
	 * @returns Classification result
	 */
	getClassification(tokens: string[]): Promise<ClassificationResult>;

	/**
	 * Get phishing detection results
	 * @param mail - Parsed mail object
	 * @returns Array of phishing results
	 */
	getPhishingResults(mail: MailObject): Promise<PhishingResult[]>;

	/**
	 * Get executable detection results
	 * @param mail - Parsed mail object
	 * @returns Array of executable results
	 */
	getExecutableResults(mail: MailObject): Promise<ExecutableResult[]>;

	/**
	 * Get macro detection results
	 * @param mail - Parsed mail object
	 * @returns Array of macro results
	 */
	getMacroResults(mail: MailObject): Promise<MacroResult[]>;

	/**
	 * Get arbitrary pattern results (e.g., GTUBE)
	 * @param mail - Parsed mail object
	 * @returns Array of arbitrary results
	 */
	getArbitraryResults(mail: MailObject): Promise<ArbitraryResult[]>;

	/**
	 * Get virus scan results
	 * @param mail - Parsed mail object
	 * @returns Array of virus results
	 */
	getVirusResults(mail: MailObject): Promise<VirusResult[]>;

	/**
	 * Get pattern detection results
	 * @param mail - Parsed mail object
	 * @returns Array of pattern results
	 */
	getPatternResults(mail: MailObject): Promise<PatternResult[]>;

	/**
	 * Get file path detection results
	 * @param mail - Parsed mail object
	 * @returns Array of pattern results
	 */
	getFilePathResults(mail: MailObject): Promise<PatternResult[]>;

	/**
	 * Get IDN homograph attack results
	 * @param mail - Parsed mail object
	 * @returns IDN homograph result
	 */
	getIdnHomographResults(mail: MailObject): Promise<IdnHomographResult>;

	/**
	 * Get toxicity detection results
	 * @param mail - Parsed mail object
	 * @returns Array of toxicity results
	 */
	getToxicityResults(mail: MailObject): Promise<ToxicityResult[]>;

	/**
	 * Get NSFW detection results
	 * @param mail - Parsed mail object
	 * @returns Array of NSFW results
	 */
	getNsfwResults(mail: MailObject): Promise<NsfwResult[]>;

	/**
	 * Get tokens from text
	 * @param text - Text to tokenize
	 * @param locale - Locale code (default: 'en')
	 * @param isHtml - Whether the text is HTML
	 * @returns Array of tokens
	 */
	getTokens(text: string, locale?: string, isHtml?: boolean): Promise<string[]>;

	/**
	 * Preprocess text for analysis
	 * @param text - Text to preprocess
	 * @returns Preprocessed text
	 */
	preprocessText(text: string): Promise<string>;

	/**
	 * Extract URLs from text
	 * @param text - Text to extract URLs from
	 * @returns Array of URLs
	 */
	getUrls(text: string): string[];

	/**
	 * Extract all URLs from mail and source
	 * @param mail - Parsed mail object
	 * @param originalSource - Original email source
	 * @returns Array of URLs
	 */
	extractAllUrls(mail: MailObject, originalSource: ScanSource): string[];

	/**
	 * Optimize URL parsing with timeout protection
	 * @param url - URL to parse
	 * @returns Normalized URL
	 */
	optimizeUrlParsing(url: string): Promise<string>;

	/**
	 * Parse URL using tldts
	 * @param url - URL to parse
	 * @returns Parsed URL result or null
	 */
	parseUrlWithTldts(url: string): ParsedUrl | undefined;

	/**
	 * Check if a domain is blocked by Cloudflare
	 * @param hostname - Hostname to check
	 * @returns Whether the domain is blocked
	 */
	isCloudflareBlocked(hostname: string): Promise<boolean>;

	/**
	 * Detect language using hybrid approach
	 * @param text - Text to analyze
	 * @returns Detected language code
	 */
	detectLanguageHybrid(text: string): Promise<string>;

	/**
	 * Parse and normalize locale code
	 * @param locale - Locale code to parse
	 * @returns Normalized locale code
	 */
	parseLocale(locale: string): string;

	/**
	 * Normalize language code from 3-letter to 2-letter format
	 * @param code - Language code to normalize
	 * @returns Normalized 2-letter language code
	 */
	normalizeLanguageCode(code: string): string;

	/**
	 * Validate short text language detection
	 * @param text - Text that was analyzed
	 * @param detectedLang - Detected language code
	 * @returns Whether the detection is valid
	 */
	isValidShortTextDetection(text: string, detectedLang: string): boolean;

	/**
	 * Check if a path is a valid file path
	 * @param path - Path to validate
	 * @returns Whether the path is valid
	 */
	isValidFilePath(path: string): boolean;

	/**
	 * Get IDN detector instance
	 * @returns IDN detector or null
	 */
	getIdnDetector(): Promise<EnhancedIdnDetector | undefined>;

	/**
	 * Get authentication results using mailauth
	 * @param source - Email source
	 * @param mail - Parsed mail object
	 * @param options - Authentication options
	 * @returns Authentication result or null
	 */
	getAuthenticationResults(
		source: ScanSource,
		mail: MailObject,
		options?: AuthOptions
	): Promise<AuthenticationResult | null>;

	/**
	 * Get reputation results from Forward Email API
	 * @param mail - Parsed mail object
	 * @param authOptions - Authentication options (for IP/sender)
	 * @param reputationOptions - Reputation API options
	 * @returns Reputation result or null
	 */
	getReputationResults(
		mail: MailObject,
		authOptions?: AuthOptions,
		reputationOptions?: ReputationOptions
	): Promise<ExtendedReputationResult | null>;
}

/**
 * Enhanced IDN Detector options
 */
export type EnhancedIdnDetectorOptions = {
	/** Enable strict mode */
	strictMode?: boolean;
	/** Enable domain whitelist */
	enableWhitelist?: boolean;
	/** Enable brand protection */
	enableBrandProtection?: boolean;
	/** Enable context analysis */
	enableContextAnalysis?: boolean;
	/** Maximum similarity threshold (0-1) */
	maxSimilarityThreshold?: number;
	/** Minimum domain age in days */
	minDomainAge?: number;
};

/**
 * Context for IDN analysis
 */
export type IdnAnalysisContext = {
	/** Email content */
	emailContent?: string;
	/** Display text (if different from domain) */
	displayText?: string | undefined;
	/** Sender reputation (0-1) */
	senderReputation?: number;
	/** Email headers */
	emailHeaders?: Map<string, unknown> | Record<string, unknown>;
};

/**
 * IDN analysis result
 */
export type IdnAnalysisResult = {
	/** The domain analyzed */
	domain: string;
	/** Whether the domain is an IDN */
	isIdn: boolean;
	/** Risk score (0-1) */
	riskScore: number;
	/** Risk factors identified */
	riskFactors: string[];
	/** Recommendations */
	recommendations: string[];
	/** Confidence level (0-1) */
	confidence: number;
};

/**
 * Confusable character analysis result
 */
export type ConfusableAnalysis = {
	/** Risk score contribution */
	score: number;
	/** Risk factors identified */
	factors: string[];
};

/**
 * Brand similarity analysis result
 */
export type BrandAnalysis = {
	/** Risk score contribution */
	score: number;
	/** Risk factors identified */
	factors: string[];
};

/**
 * Script mixing analysis result
 */
export type ScriptAnalysis = {
	/** Risk score contribution */
	score: number;
	/** Risk factors identified */
	factors: string[];
};

/**
 * Context analysis result
 */
export type ContextAnalysis = {
	/** Risk score contribution */
	score: number;
	/** Risk factors identified */
	factors: string[];
};

/**
 * Punycode analysis result
 */
export type PunycodeAnalysis = {
	/** Risk score contribution */
	score: number;
	/** Risk factors identified */
	factors: string[];
};

/**
 * Enhanced IDN Homograph Attack Detector
 */
declare class EnhancedIdnDetector {
	/** Detector options */
	options: EnhancedIdnDetectorOptions & {
		strictMode: boolean;
		enableWhitelist: boolean;
		enableBrandProtection: boolean;
		enableContextAnalysis: boolean;
		maxSimilarityThreshold: number;
		minDomainAge: number;
	};

	/** Analysis cache */
	cache: Map<string, IdnAnalysisResult>;

	/**
	 * Create a new EnhancedIdnDetector instance
	 * @param options - Configuration options
	 */
	constructor(options?: EnhancedIdnDetectorOptions);

	/**
	 * Detect homograph attack in a domain
	 * @param domain - Domain to analyze
	 * @param context - Analysis context
	 * @returns Analysis result
	 */
	detectHomographAttack(domain: string, context?: IdnAnalysisContext): IdnAnalysisResult;

	/**
	 * Comprehensive analysis of a domain
	 * @param domain - Domain to analyze
	 * @param context - Analysis context
	 * @returns Analysis result
	 */
	analyzeComprehensive(domain: string, context: IdnAnalysisContext): IdnAnalysisResult;

	/**
	 * Check if domain contains IDN characters
	 * @param domain - Domain to check
	 * @returns Whether the domain is an IDN
	 */
	isIdnDomain(domain: string): boolean;

	/**
	 * Check if domain is whitelisted
	 * @param domain - Domain to check
	 * @returns Whether the domain is whitelisted
	 */
	isWhitelisted(domain: string): boolean;

	/**
	 * Analyze confusable characters in domain
	 * @param domain - Domain to analyze
	 * @returns Confusable analysis result
	 */
	analyzeConfusableCharacters(domain: string): ConfusableAnalysis;

	/**
	 * Analyze brand similarity
	 * @param domain - Domain to analyze
	 * @returns Brand analysis result
	 */
	analyzeBrandSimilarity(domain: string): BrandAnalysis;

	/**
	 * Analyze script mixing patterns
	 * @param domain - Domain to analyze
	 * @returns Script analysis result
	 */
	analyzeScriptMixing(domain: string): ScriptAnalysis;

	/**
	 * Analyze context for additional risk factors
	 * @param domain - Domain to analyze
	 * @param context - Analysis context
	 * @returns Context analysis result
	 */
	analyzeContext(domain: string, context: IdnAnalysisContext): ContextAnalysis;

	/**
	 * Analyze punycode domain
	 * @param domain - Domain to analyze
	 * @returns Punycode analysis result
	 */
	analyzePunycode(domain: string): PunycodeAnalysis;

	/**
	 * Normalize domain for comparison
	 * @param domain - Domain to normalize
	 * @returns Normalized domain
	 */
	normalizeDomain(domain: string): string;

	/**
	 * Calculate string similarity using Levenshtein distance
	 * @param string1 - First string
	 * @param string2 - Second string
	 * @returns Similarity score (0-1)
	 */
	calculateSimilarity(string1: string, string2: string): number;

	/**
	 * Detect scripts used in domain
	 * @param domain - Domain to analyze
	 * @returns Set of detected scripts
	 */
	detectScripts(domain: string): Set<string>;

	/**
	 * Decode punycode domain
	 * @param domain - Domain to decode
	 * @returns Decoded domain
	 */
	decodePunycode(domain: string): string;

	/**
	 * Generate recommendations based on analysis
	 * @param analysis - Analysis result
	 * @returns Array of recommendations
	 */
	generateRecommendations(analysis: IdnAnalysisResult): string[];

	/**
	 * Get cache key for analysis
	 * @param domain - Domain
	 * @param context - Analysis context
	 * @returns Cache key
	 */
	getCacheKey(domain: string, context: IdnAnalysisContext): string;
}

export default SpamScanner;
export {SpamScanner, EnhancedIdnDetector};
