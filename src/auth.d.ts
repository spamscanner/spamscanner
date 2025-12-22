/**
 * Email Authentication Module Type Definitions
 */

export interface DkimResult {
	results: DkimSignatureResult[];
	status: AuthStatus;
}

export interface DkimSignatureResult {
	signingDomain?: string;
	selector?: string;
	algo?: string;
	format?: string;
	signature?: string;
	bodyHash?: string;
	status: AuthStatus;
}

export interface SpfResult {
	status: AuthStatus;
	domain: string | null;
	explanation?: string | null;
}

export interface DmarcResult {
	status: AuthStatus;
	policy: string | null;
	domain: string | null;
	p?: string | null;
	sp?: string | null;
	pct?: number | null;
}

export interface ArcResult {
	status: AuthStatus;
	chain: ArcChainEntry[];
	i?: number | null;
}

export interface ArcChainEntry {
	i: number;
	cv: string;
	status: AuthStatus;
}

export interface BimiResult {
	status: AuthStatus;
	location: string | null;
	authority: string | null;
	selector?: string | null;
}

export interface AuthStatus {
	result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
	comment?: string;
}

export interface AuthResult {
	dkim: DkimResult;
	spf: SpfResult;
	dmarc: DmarcResult;
	arc: ArcResult;
	bimi: BimiResult;
	receivedChain: ReceivedChainEntry[];
	headers: Record<string, string>;
}

export interface ReceivedChainEntry {
	from?: string;
	by?: string;
	with?: string;
	id?: string;
	for?: string;
	date?: string;
}

export interface AuthOptions {
	ip: string;
	helo?: string;
	mta?: string;
	sender?: string;
	resolver?: (name: string, type: string) => Promise<string[]>;
	timeout?: number;
}

export interface AuthScoreWeights {
	dkimPass?: number;
	dkimFail?: number;
	spfPass?: number;
	spfFail?: number;
	spfSoftfail?: number;
	dmarcPass?: number;
	dmarcFail?: number;
	arcPass?: number;
	arcFail?: number;
}

export interface AuthScoreResult {
	score: number;
	tests: string[];
	details: {
		dkim: string;
		spf: string;
		dmarc: string;
		arc: string;
	};
}

/**
 * Authenticate an email message
 */
export function authenticate(
	message: Buffer | string,
	options?: AuthOptions
): Promise<AuthResult>;

/**
 * Perform SPF check only
 */
export function checkSpf(
	ip: string,
	sender: string,
	helo?: string,
	options?: Partial<AuthOptions>
): Promise<SpfResult>;

/**
 * Verify DKIM signature
 */
export function verifyDkim(
	message: Buffer | string,
	options?: Partial<AuthOptions>
): Promise<DkimResult>;

/**
 * Calculate authentication score based on results
 */
export function calculateAuthScore(
	authResult: AuthResult,
	weights?: AuthScoreWeights
): AuthScoreResult;

/**
 * Format authentication results as Authentication-Results header
 */
export function formatAuthResultsHeader(
	authResult: AuthResult,
	hostname?: string
): string;

/**
 * Create a DNS resolver with timeout support
 */
export function createResolver(
	timeout?: number
): (name: string, type: string) => Promise<string[]>;
