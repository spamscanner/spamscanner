// Options of earlier versions, still read and mapped to the current ones (a
// declaration file, as only TypeScript can mark a property deprecated).
export type LegacyOptions = {
	/** @deprecated Use `clamav`. */
	clamscan?: boolean | {socket?: string; host?: string; port?: number; clamdscan?: {socket?: string; host?: string; port?: number}};
	/** @deprecated Use `macros`. */
	enableMacroDetection?: boolean;
	/** @deprecated Use `arbitrary`. */
	enableArbitraryDetection?: boolean;
	/** @deprecated Use `authentication`. */
	enableAuthentication?: boolean;
	/** @deprecated Use `authentication` and `session`. */
	authOptions?: {ip?: string; helo?: string; sender?: string; hostname?: string; [option: string]: unknown};
	/** @deprecated Use `reputation`. */
	enableReputation?: boolean;
	/** @deprecated Use `reputation`. */
	reputationOptions?: {apiUrl?: string; timeout?: number};
	/** @deprecated Use `phishing.homograph.strictMode`. */
	strictIDNDetection?: boolean;
	/** @deprecated Ignored. */
	logger?: unknown;
	/** @deprecated Ignored. */
	memoize?: unknown;
};
