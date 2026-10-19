import dns from 'node:dns';
import {isIP} from 'node:net';

// Whether a name can be looked up: not an address (also "[2001:db8::1]"),
// at most 253 characters, in labels of 1 to 63
export function isLookupName(name) {
	if (typeof name !== 'string') {
		return false;
	}

	const host = name.replaceAll(/^\[|]$/g, '').replace(/\.$/, '');
	return host !== '' && isIP(host) === 0 && host.length <= 253 && host.split('.').every(label => label.length > 0 && label.length <= 63);
}

/**
 * Blocklists that answer DNS queries. None is enabled by default: each has its
 * own terms (Spamhaus, for example, is free only for low-volume
 * non-commercial use and refuses queries sent through public resolvers).
 */
export const KNOWN_LISTS = {
	ip: {
		'zen.spamhaus.org': 'Spamhaus ZEN (SBL, XBL, PBL, CSS)',
		'b.barracudacentral.org': 'Barracuda Reputation Block List',
		'bl.spamcop.net': 'SpamCop Blocking List',
		'psbl.surriel.com': 'Passive Spam Block List',
		'bl.mailspike.net': 'Mailspike Blacklist',
		'dnsbl.dronebl.org': 'DroneBL',
	},
	domain: {
		'dbl.spamhaus.org': 'Spamhaus Domain Block List',
		'multi.surbl.org': 'SURBL multi',
		'multi.uribl.com': 'URIBL multi',
		'dbl.nordspam.com': 'NordSpam DBL',
	},
};

// Cloudflare's resolvers for families: 1.1.1.2 blocks malware, 1.1.1.3 blocks
// malware and adult content. Blocked names resolve to 0.0.0.0.
export const CLOUDFLARE_MALWARE = ['1.1.1.2', '1.0.0.2'];
export const CLOUDFLARE_FAMILY = ['1.1.1.3', '1.0.0.3'];

// The eight 16-bit groups of an IPv6 address (an IPv4 address at its end,
// as in "::ffff:192.0.2.1", is two groups).
function ipv6Groups(address) {
	const expanded = address.replace(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/, (...match) => {
		const [a, b, c, d] = match.slice(1, 5).map(Number);
		return `${((a * 256) + b).toString(16)}:${((c * 256) + d).toString(16)}`;
	});
	const [head, tail = ''] = expanded.split('::');
	const left = head ? head.split(':') : [];
	const right = tail ? tail.split(':') : [];
	return [...left, ...Array.from({length: 8 - left.length - right.length}).fill('0'), ...right].map(group => Number.parseInt(group, 16));
}

/**
 * An IP address as blocklists and allowlists know it: without an IPv6 zone
 * ("fe80::1%eth0"), and an IPv4 address mapped into IPv6 ("::ffff:192.0.2.1",
 * as a dual-stack server reports IPv4 clients) as the IPv4 address, and any
 * other IPv6 address in its canonical form (RFC 5952: "2001:db8::1", and an
 * IPv4 address translated into IPv6 or under the NAT64 prefix in dotted form:
 * "::ffff:0:192.0.2.1", "64:ff9b::192.0.2.1"). Anything
 * that is not an IP address is returned as it is.
 * @param {string} ip
 * @returns {string}
 */
export function normalizeIp(ip) {
	const address = String(ip).replace(/%.*$/, '');
	const version = isIP(address);
	if (version === 4) {
		return address;
	}

	if (version !== 6) {
		return String(ip);
	}

	const groups = ipv6Groups(address);
	const ipv4 = [Math.floor(groups[6] / 256), groups[6] % 256, Math.floor(groups[7] / 256), groups[7] % 256].join('.');
	if (groups.slice(0, 5).every(group => group === 0) && groups[5] === 0xFF_FF) {
		return ipv4;
	}

	// (an IPv4 address translated into IPv6, "::ffff:0:192.0.2.1", or under
	//  the NAT64 prefix, "64:ff9b::192.0.2.1", keeps it in dotted form, as
	//  RFC 5952 (section 5) asks)
	const embedded = (groups.slice(0, 4).every(group => group === 0) && groups[4] === 0xFF_FF && groups[5] === 0)
		|| (groups[0] === 0x64 && groups[1] === 0xFF_9B && groups.slice(2, 6).every(group => group === 0));
	const count = embedded ? 6 : 8;

	// (in the one form of RFC 5952, so "2001:0DB8:0:0::0001" is
	//  "2001:db8::1": lowercase, without leading zeros, the longest run of two
	//  or more zero groups, the first of equals, as "::")
	let run = {start: -1, length: 1};
	for (let i = 0; i < count; i++) {
		let length = 0;
		while (i + length < count && groups[i + length] === 0) {
			length++;
		}

		if (length > run.length) {
			run = {start: i, length};
		}

		i += length;
	}

	const hex = groups.slice(0, count).map(group => group.toString(16));
	const written = run.start === -1 ? hex.join(':') : `${hex.slice(0, run.start).join(':')}::${hex.slice(run.start + run.length).join(':')}`;
	if (!embedded) {
		return written;
	}

	return `${written}${written.endsWith(':') ? '' : ':'}${ipv4}`;
}

/**
 * The DNS name to query for an IP address in a blocklist zone: reversed
 * octets for IPv4 ("4.3.2.1.zen.spamhaus.org"), reversed nibbles for IPv6.
 * An IPv4 address mapped into IPv6 is looked up as IPv4.
 * @param {string} ip
 * @param {string} zone
 * @returns {string|null}
 */
export function reverseName(ip, zone) {
	const address = normalizeIp(ip);
	const version = isIP(address);
	if (version === 4) {
		return `${address.split('.').reverse().join('.')}.${zone}`;
	}

	if (version === 6) {
		const nibbles = ipv6Groups(address).map(group => group.toString(16).padStart(4, '0')).join('');
		return `${[...nibbles].reverse().join('.')}.${zone}`;
	}

	return null;
}

// A zone of a list, or of a mirror of it ("multi.surbl.org", or
// "key.dq.spamhaus.net" for Spamhaus's own service)
function inZone(zone, domain) {
	const name = String(zone).toLowerCase().replace(/\.$/, '');
	return name === domain || name.endsWith(`.${domain}`);
}

/**
 * Whether an answer means "listed": an address in 127.0.0.0/8 that is not one
 * of the error codes lists return when queries are refused or wrong: at
 * Spamhaus, 127.255.255.x (127.255.255.252 for a misspelled zone,
 * .254 for queries through a public resolver, .255 for too many queries) and
 * 127.0.1.255 (an address looked up in the DBL), 127.0.0.255 anywhere, and
 * 127.0.0.1 at SURBL and URIBL, which answer it to resolvers they block
 * (SpamAssassin's SURBL_BLOCKED and URIBL_BLOCKED).
 * @param {string} address
 * @param {string} zone
 * @returns {boolean}
 */
export function isListedAnswer(address, zone) {
	if (!/^127(?:\.\d+){3}$/.test(address)) {
		return false;
	}

	if (address.startsWith('127.255.255.') || address === '127.0.0.255') {
		return false;
	}

	if (address === '127.0.1.255' && (inZone(zone, 'spamhaus.org') || inZone(zone, 'spamhaus.net'))) {
		return false;
	}

	if (address === '127.0.0.1' && (inZone(zone, 'uribl.com') || inZone(zone, 'surbl.org'))) {
		return false;
	}

	return true;
}

/**
 * Looks names and addresses up in DNS blocklists and Cloudflare's filtering
 * resolvers, with a cache and a timeout.
 */
export class DnsChecker {
	/**
	 * @param {object} [options]
	 * @param {string[]} [options.servers] - name servers for blocklist queries (default: system)
	 * @param {number} [options.timeout] - per lookup, in milliseconds
	 * @param {number} [options.cacheSize]
	 * @param {number} [options.cacheTtl] - milliseconds
	 * @param {Function} [options.resolve4] - custom (name, servers) => Promise<string[]>, for tests
	 */
	constructor(options = {}) {
		this.timeout = options.timeout ?? 3000;
		this.servers = options.servers || null;
		this.cacheSize = options.cacheSize ?? 10_000;
		this.cacheTtl = options.cacheTtl ?? 600_000;
		this.cache = new Map();
		this.resolvers = new Map();
		this.customResolve4 = options.resolve4 || null;
	}

	resolver(servers) {
		const key = servers ? servers.join(',') : '';
		if (!this.resolvers.has(key)) {
			const resolver = new dns.promises.Resolver({timeout: this.timeout, tries: 1});
			if (servers) {
				resolver.setServers(servers);
			}

			this.resolvers.set(key, resolver);
		}

		return this.resolvers.get(key);
	}

	/**
	 * A records for a name; an empty list when it does not exist or the lookup
	 * fails or times out.
	 * @param {string} name
	 * @param {string[]|null} [servers]
	 * @returns {Promise<string[]>}
	 */
	async resolve4(name, servers = this.servers) {
		return (await this.answer(name, servers)) ?? [];
	}

	/**
	 * A records for a name, an empty list when the name does not exist or has
	 * no A records, and null when no answer came: the lookup timed out or
	 * failed (SERVFAIL, refused, unreachable). Only answers are cached, so a
	 * failed lookup is tried again for the next message.
	 * @param {string} name
	 * @param {string[]|null} [servers]
	 * @returns {Promise<string[]|null>}
	 */
	async answer(name, servers = this.servers) {
		const key = `${servers ? servers.join(',') : ''}|${name}`;
		const hit = this.cache.get(key);
		if (hit && hit.expires > Date.now()) {
			return hit.value;
		}

		let value;
		let timer;
		try {
			const lookup = this.customResolve4 ? this.customResolve4(name, servers) : this.resolver(servers).resolve4(name);
			value = await Promise.race([
				lookup,
				new Promise(resolve => {
					timer = setTimeout(() => resolve(null), this.timeout);
				}),
			]);
		} catch (error) {
			value = ['ENOTFOUND', 'ENODATA'].includes(error?.code) ? [] : null;
		} finally {
			clearTimeout(timer);
		}

		if (value === null) {
			return null;
		}

		this.cache.set(key, {value, expires: Date.now() + this.cacheTtl});
		if (this.cache.size > this.cacheSize) {
			this.cache.delete(this.cache.keys().next().value);
		}

		return value;
	}

	/**
	 * Look an IP address up in IP blocklists.
	 * @param {string} ip
	 * @param {string[]} zones
	 * @returns {Promise<Array<{zone: string, value: string, answers: string[]}>>}
	 */
	async checkIp(ip, zones = []) {
		const results = await Promise.all(zones.map(async zone => {
			const name = reverseName(ip, zone);
			if (!name) {
				return null;
			}

			const addresses = await this.resolve4(name);
			const answers = addresses.filter(address => isListedAnswer(address, zone));
			return answers.length > 0 ? {zone, value: ip, answers} : null;
		}));
		return results.filter(Boolean);
	}

	/**
	 * Look domains up in domain blocklists (Spamhaus DBL, SURBL, URIBL).
	 * @param {string[]} domains - registrable domains
	 * @param {string[]} zones
	 * @returns {Promise<Array<{zone: string, value: string, answers: string[]}>>}
	 */
	async checkDomains(domains = [], zones = []) {
		const queries = [];
		for (const domain of domains) {
			if (isIP(domain)) {
				continue;
			}

			for (const zone of zones) {
				queries.push((async () => {
					const addresses = await this.resolve4(`${domain}.${zone}`);
					const answers = addresses.filter(address => isListedAnswer(address, zone));
					return answers.length > 0 ? {zone, value: domain, answers} : null;
				})());
			}
		}

		const results = await Promise.all(queries);
		return results.filter(Boolean);
	}

	/**
	 * Ask Cloudflare's filtering resolvers about host names. A name blocked by
	 * the malware resolver is "malware"; one blocked only by the family
	 * resolver is "adult". The hosts that got no answer (from the malware
	 * resolver, or from the family resolver when asked) are listed in the
	 * result's (non-enumerable) `unanswered` property.
	 * @param {string[]} hosts
	 * @param {object} [options]
	 * @param {boolean} [options.adult] - also ask the family resolver
	 * @param {string[]} [options.malwareServers]
	 * @param {string[]} [options.familyServers]
	 * @returns {Promise<Array<{host: string, category: 'malware'|'adult'}> & {unanswered: string[]}>}
	 */
	async checkCloudflare(hosts = [], options = {}) {
		const {adult = true, malwareServers = CLOUDFLARE_MALWARE, familyServers = CLOUDFLARE_FAMILY} = options;
		const unanswered = [];
		const results = await Promise.all(hosts.map(async host => {
			// (an address, or a name no lookup could answer: not asked)
			if (!isLookupName(host)) {
				return null;
			}

			const malware = await this.answer(host, malwareServers);
			if (malware?.includes('0.0.0.0')) {
				return {host, category: 'malware'};
			}

			const family = malware && adult ? await this.answer(host, familyServers) : [];
			if (family?.includes('0.0.0.0')) {
				return {host, category: 'adult'};
			}

			if (!malware || !family) {
				unanswered.push(host);
			}

			return null;
		}));
		// (not enumerable: the result is still a plain list of findings)
		return Object.defineProperty(results.filter(Boolean), 'unanswered', {value: unanswered});
	}
}
