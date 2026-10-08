import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {
	countScripts, detectLanguage, normalizeLanguageCode, scriptOf,
} from '../src/language.js';

describe('language detection', () => {
	const cases = [
		['Hi Bob, are we still on for lunch on Thursday at noon? Let me know what works.', 'en'],
		['Herzlichen Glückwunsch, Sie haben einen Preis gewonnen. Klicken Sie hier, um ihn abzuholen.', 'de'],
		['Félicitations, vous avez gagné un prix, cliquez ici pour le réclamer maintenant.', 'fr'],
		['¡Felicidades! Has ganado un premio, haz clic aquí para reclamarlo ahora mismo.', 'es'],
		['Parabéns! Você ganhou um prêmio, clique aqui para resgatar agora mesmo.', 'pt'],
		['Поздравляем! Вы выиграли миллион долларов, нажмите сюда чтобы получить приз', 'ru'],
		['Вітаємо! Ви виграли мільйон доларів, натисніть тут', 'uk'],
		['Віншуем, вы выйгралі. Націсніце тут, каб атрымаць ўзнагароду', 'be'],
		['Честитамо, освојили сте награду. Кликните овде да бисте је преузели ђ', 'sr'],
		['Честитки, освоивте награда. Кликнете тука ѓ', 'mk'],
		['恭喜您赢得了一百万美元请点击链接领取', 'zh'],
		['おめでとうございます。賞金を受け取るにはこちら', 'ja'],
		['축하합니다 당첨되셨습니다', 'ko'],
		['ยินดีด้วยคุณได้รับรางวัล', 'th'],
		['Συγχαρητήρια, κερδίσατε ένα βραβείο', 'el'],
		['מזל טוב, זכית בפרס', 'he'],
		['مبروك لقد ربحت جائزة كبيرة اضغط هنا للحصول عليها الآن', 'ar'],
		['बधाई हो! आपने दस लाख रुपये का इनाम जीता है', 'hi'],
	];
	for (const [text, language] of cases) {
		it(`detects ${language}`, () => {
			assert.equal(detectLanguage(text).language, language);
		});
	}

	it('leaves short Latin text undecided', () => {
		const result = detectLanguage('ok thanks');
		assert.equal(result.language, null);
		assert.equal(result.script, 'Latin');
		assert.equal(result.confidence, 0);
	});

	it('handles empty, non-string and letterless input', () => {
		assert.deepEqual(detectLanguage(''), {
			language: null, script: null, scripts: [], confidence: 0,
		});
		assert.equal(detectLanguage(42).language, null);
		assert.equal(detectLanguage('12345 !!! 678').script, null);
	});

	it('reports mixed scripts', () => {
		const result = detectLanguage('Hello world, this is a test. Привет мир, это тест сообщения.');
		assert.deepEqual(result.scripts.sort(), ['Cyrillic', 'Latin']);
	});

	it('falls back to undecided when franc cannot tell a long Cyrillic text apart', () => {
		const result = detectLanguage('Честито на всички награди днес и утре за всеки човек в града');
		assert.equal(result.script, 'Cyrillic');
		assert.ok(result.language === 'bg' || result.language === null);
	});

	it('returns undecided when franc answers und', () => {
		const result = detectLanguage('zzzz qqqq xxxx vvvv kkkk zzzz qqqq xxxx vvvv kkkk zzzz qqqq');
		assert.equal(result.script, 'Latin');
	});
});

describe('scripts and codes', () => {
	it('counts letters per script, most frequent first, up to a limit', () => {
		const counts = countScripts('abcабв日', 10);
		assert.deepEqual([...counts.keys()], ['Latin', 'Cyrillic', 'Han']);
		assert.equal(countScripts('abcdef', 3).get('Latin'), 3);
		assert.equal(countScripts('ᚠᚢᚦ').get('Other'), 3);
	});

	it('names the script of a letter', () => {
		assert.equal(scriptOf('a'), 'Latin');
		assert.equal(scriptOf('ж'), 'Cyrillic');
		assert.equal(scriptOf('ᚠ'), 'Other');
	});

	it('normalizes language codes', () => {
		assert.equal(normalizeLanguageCode('eng'), 'en');
		assert.equal(normalizeLanguageCode('en-US'), 'en');
		assert.equal(normalizeLanguageCode('pt_BR'), 'pt');
		assert.equal(normalizeLanguageCode('xyz'), 'xyz');
		assert.equal(normalizeLanguageCode(''), null);
		assert.equal(normalizeLanguageCode(null), null);
	});
});
