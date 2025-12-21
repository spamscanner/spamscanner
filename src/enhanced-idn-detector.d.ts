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

export default EnhancedIdnDetector;
export {EnhancedIdnDetector};
