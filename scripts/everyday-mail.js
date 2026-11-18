// Everyday mail and spam in the languages the public datasets have little
// of, written for this project: in each language the same notices, bills,
// letters between colleagues and family, and the same frauds, as sentences
// (scripts/everyday-mail/*.json) that are put together into messages. The
// ordinary mail says what the frauds say where real mail does (a password
// reset that was asked for, a parcel on its way, a shop's offer), so that a
// word is no sign of spam for being in the frauds alone.
import {readFileSync, readdirSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const DIRECTORY = path.join(path.dirname(fileURLToPath(import.meta.url)), 'everyday-mail');
const CURRENCY = {
	ar: 'دولار', bg: 'лв.', cs: 'Kč', da: 'kr.', el: '€', fi: '€', fr: '€', he: '₪', hi: '₹', hu: 'Ft', ja: '円', ko: '원', nl: '€', no: 'kr', pl: 'zł', pt: '€', ro: 'lei', sv: 'kr', th: 'บาท', tr: 'TL', uk: 'грн', vi: 'đồng', zh: '元',
};

// A generator of the same numbers each time (Lehmer's), so the messages made
// are the same on every run
function random(seed) {
	let state = (seed % 2_147_483_646) + 1;
	return () => {
		state = (state * 48_271) % 2_147_483_647;
		return state / 2_147_483_647;
	};
}

/**
 * The languages written, each as {names, shops, ham: {subjects, sentences}, spam: {subjects, sentences}}.
 * @returns {Record<string, object>}
 */
export function everydayLanguages() {
	const languages = {};
	for (const file of readdirSync(DIRECTORY).filter(name => name.endsWith('.json')).sort()) {
		Object.assign(languages, JSON.parse(readFileSync(path.join(DIRECTORY, file), 'utf8')));
	}

	return languages;
}

/**
 * Messages made of the sentences of each language.
 * @param {object} [options]
 * @param {number} [options.ham] - ordinary messages of each language
 * @param {number} [options.spam] - spam messages of each language
 * @yields {{language: string, subject: string, text: string, label: 'ham'|'spam'}}
 */
export function * everydayMail({ham = 300, spam = 200} = {}) {
	for (const [language, source] of Object.entries(everydayLanguages())) {
		const next = random([...language].reduce((sum, letter) => (sum * 31) + letter.codePointAt(0), 7));
		const pick = list => list[Math.floor(next() * list.length)];
		const fill = text => text
			.replaceAll('{name}', () => pick(source.names))
			.replaceAll('{shop}', () => pick(source.shops))
			.replaceAll('{n}', () => String(10_000 + Math.floor(next() * 89_999)))
			.replaceAll('{amount}', () => `${[25, 40, 120, 250, 480, 1500, 3200, 9000][Math.floor(next() * 8)]} ${CURRENCY[language]}`)
			.replaceAll('{date}', () => `${1 + Math.floor(next() * 28)}.${1 + Math.floor(next() * 12)}.`)
			.replaceAll('{time}', () => `${8 + Math.floor(next() * 11)}:${pick(['00', '15', '30', '45'])}`)
			.replaceAll('{code}', () => String(100_000 + Math.floor(next() * 899_999)));
		const some = (list, count) => {
			const left = [...list];
			const taken = [];
			while (taken.length < count && left.length > 0) {
				taken.push(left.splice(Math.floor(next() * left.length), 1)[0]);
			}

			return taken;
		};

		// (an ordinary message: a greeting, two to four things said, a close)
		const {subjects, sentences} = source.ham;
		const [greeting, ...rest] = sentences;
		const closes = rest.slice(-2);
		const said = rest.slice(0, -2);
		for (let index = 0; index < ham; index++) {
			const body = [greeting, ...some(said, 2 + Math.floor(next() * 3)), pick(closes)];
			yield {
				language, subject: fill(pick(subjects)), text: fill(body.join('\n\n')), label: 'ham',
			};
		}

		for (let index = 0; index < spam; index++) {
			yield {
				language, subject: fill(pick(source.spam.subjects)), text: fill(some(source.spam.sentences, 3 + Math.floor(next() * 3)).join('\n\n')), label: 'spam',
			};
		}
	}
}
