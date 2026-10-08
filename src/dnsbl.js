import dns from 'node:dns';
import {isIP} from 'node:net';

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

/**
 * The DNS name to query for an IP address in a blocklist zone: reversed
 * octets for IPv4 ("4.3.2.1.zen.spamhaus.org"), reversed nibbles for IPv6.
 * @param {string} ip
 * @param {string} zone
 * @returns {string|null}
 */
export function reverseName(ip, zone) {
	const version = isIP(ip);
	if (version === 4) {
		return `${ip.split('.').reverse().join('.')}.${zone}`;
	}

	if (version === 6) {
		const [head, tail = ''] = ip.split('::');
		const left = head ? head.split(':') : [];
		const right = tail ? tail.split(':') : [];
		const groups = [...left, ...Array.from({length: 8 - left.length - right.length}).fill('0'), ...right];
		const nibbles = groups.map(group => group.padStart(4, '0')).join('');
		return `${[...nibbles].reverse().join('.')}.${zone}`;
	}

	return null;
}

/**
 * Whether an answer means "listed": an address in 127.0.0.0/8 that is not one
 * of the error codes lists return when queries are refused (127.255.255.x at
 * Spamhaus, 127.0.0.255 at SURBL, 127.0.0.1 at URIBL for blocked resolvers).
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

	if (zone.endsWith('uribl.com') && address === '127.0.0.1') {
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
		} catch {
			value = [];
		} finally {
			clearTimeout(timer);
		}

		if (value === null) {
			// Timed out: not cached, so the next message tries again.
			return [];
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
	 * resolver is "adult".
	 * @param {string[]} hosts
	 * @param {object} [options]
	 * @param {boolean} [options.adult] - also ask the family resolver
	 * @param {string[]} [options.malwareServers]
	 * @param {string[]} [options.familyServers]
	 * @returns {Promise<Array<{host: string, category: 'malware'|'adult'}>>}
	 */
	async checkCloudflare(hosts = [], options = {}) {
		const {adult = true, malwareServers = CLOUDFLARE_MALWARE, familyServers = CLOUDFLARE_FAMILY} = options;
		const results = await Promise.all(hosts.map(async host => {
			if (isIP(host)) {
				return null;
			}

			const malware = await this.resolve4(host, malwareServers);
			if (malware.includes('0.0.0.0')) {
				return {host, category: 'malware'};
			}

			const family = adult ? await this.resolve4(host, familyServers) : [];
			if (family.includes('0.0.0.0')) {
				return {host, category: 'adult'};
			}

			return null;
		}));
		return results.filter(Boolean);
	}
}
