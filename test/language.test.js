import assert from 'node:assert/strict';
import {describe, it} from 'node:test';
import {franc} from 'franc';
import {
	countScripts, detectLanguage, normalizeLanguageCode, scriptOf,
} from '../src/language.js';
import {cpuTime} from './helpers/cpu-time.js';

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
		// (letters of a script franc has no languages of: long enough to ask it,
		//  and it answers "und")
		const text = '\u16A0\u16A2\u16A6\u16A8\u16B1\u16B2 \u16B7\u16B9\u16BA\u16BE\u16C1\u16C3 \u16C7\u16C8\u16C9\u16CA\u16CF\u16D2 \u16D6\u16D7\u16DA\u16DC\u16DE\u16DF';
		assert.equal(franc(text, {minLength: 20}), 'und');
		assert.deepEqual(detectLanguage(text), {
			language: null, script: 'Other', scripts: ['Other'], confidence: 0,
		});
	});

	it('leaves Cyrillic text with letters of Turkic, Iranian and Mongolic languages to franc', () => {
		// (Kazakh has "\u0456" as Ukrainian does, Uzbek "\u045E" as Belarusian,
		//  Kyrgyz and Mongolian "\u044B" and "\u044D" as Russian)
		const texts = {
			kk: 'Құрметті клиент, сіздің тапсырысыңыз дайын. Біз оны ертең жеткіземіз. Рақмет, сізге көп рақмет!',
			uz: 'Ҳурматли мижоз, буюртмангиз тайёр. Биз уни эртага етказиб берамиз. Ўзбекистон бўйлаб, катта раҳмат!',
			ky: 'Урматтуу кардар, сиздин буйрутмаңыз даяр. Биз аны эртең жеткиребиз. Рахмат, чоң рахмат сизге!',
			mn: 'Хүн бүр төрөхөөсөө эрх чөлөөтэй, адилхан нэр төртэй, ижил эрхтэй байдаг. Оюун ухаан, нандин чанар заяасан хүн гэдэг утгаараа бие биенийхээ өмнө ахан дүүгийн үзэл санаагаар харьцах учиртай.',
			tg: 'Мизоҷи муҳтарам, фармоиши шумо омода аст. Мо онро пагоҳ мерасонем. Ташаккур, ташаккури зиёд!',
		};
		for (const [language, text] of Object.entries(texts)) {
			assert.equal(detectLanguage(text).language, language, text);
		}
	});

	it('keeps Slavic text that names a Kazakh person or place or has a Kazakh word', () => {
		// (franc reads these as Bulgarian, Serbian or Bosnian; the words without
		//  Kazakh letters decide as in any Slavic text)
		const texts = [
			['Добрый день, Әсем! Напоминаем, что встреча с Ғалымом и Серікбаем перенесена на пятницу. Пожалуйста, подтвердите участие.', 'ru'],
			['Коллеги, отчёт по филиалу подготовил Ерлан Тұрсынұлы. Прошу ознакомиться с ним до среды и прислать замечания.', 'ru'],
			['Вы получили посылку от магазина «Өрнек». Чтобы забрать её, предъявите этот код в пункте выдачи на улице Абылай хана.', 'ru'],
			['Спасибо за заказ! Как говорят у нас в Алматы, үлкен рақмет. Мы отправим вам письмо, когда товар будет в пути.', 'ru'],
			['Здравейте, Әсем! Напомняме ви, че срещата с Ғалым е преместена за петък. Моля, потвърдете участието си до сряда.', 'bg'],
			['Почитувана Әсем, ве известуваме дека средбата со Ғалым е одложена за петок. Ве молиме потврдете го вашето учество.', 'mk'],
			['Поштована Әсем, обавештавамо вас да је састанак са Ғалымом одложен за петак. Молимо вас да потврдите своје учешће.', 'sr'],
			['Шановна Әсем, повідомляємо, що зустріч із Ғалимом перенесено на пʼятницю. Будь ласка, підтвердіть свою участь.', 'uk'],
			['Сіздің шотыңыз уақытша бұғатталды. Қалпына келтіру үшін төмендегі сілтемені басып, деректеріңізді енгізіңіз.', 'kk'],
		];
		for (const [text, language] of texts) {
			assert.equal(detectLanguage(text).language, language, text);
		}
	});

	it('does not let the letters of a name decide the language of a Cyrillic text', () => {
		// (a Bulgarian text that names a Russian or Kazakh person, of whose
		//  letters only the "ы" of a name is not Bulgarian: franc tells)
		for (const text of ['Уважаеми колеги, господин Рыскулов от Қарағанды ще пристигне в София в понеделник. Моля, подгответе залата за срещата и документите.', 'Уважаеми колеги, господин Рыскулов ще пристигне в София в понеделник. Моля, подгответе залата за срещата и документите.', 'Уважаеми колеги,\nгоспожа Сыроежкина ще пристигне в София в понеделник. Моля, подгответе залата и документите.']) {
			assert.equal(detectLanguage(text).language, 'bg', text);
		}

		// (but a word that starts a sentence or a line is no name, and in a text
		//  too short for franc, a name's letters are all there is)
		assert.equal(detectLanguage('Добрый день! Вы получили письмо от компании, ответьте пожалуйста до пятницы.').language, 'ru');
		assert.equal(detectLanguage('Привет, Рыскулов').language, 'ru');
		// (a word in capitals is no name)
		for (const [text, language] of [['ВАША ПОСЫЛКА ЗАДЕРЖАНА НА СКЛАДЕ. ОПЛАТИТЕ ДОСТАВКУ СЕГОДНЯ, ЧТОБЫ ПОЛУЧИТЬ ЗАКАЗ ВОВРЕМЯ И БЕЗ ЛИШНИХ ПРОБЛЕМ', 'ru'], ['УВАГА! ВАШ РАХУНАК ЗАБЛАКАВАНЫ. ПАЦВЯРДЗІЦЕ ДАДЗЕНЫЯ НЕАДКЛАДНА ДЛЯ АДНАЎЛЕННЯ ДОСТУПУ ДА ІНТЭРНЭТ-БАНКІНГУ', 'be'], ['ПАЖЊА! ВАШ РАЧУН ЈЕ БЛОКИРАН. ПОТВРДИТЕ ПОДАТКЕ ОДМАХ ДА БИСТЕ ПОВРАТИЛИ ПРИСТУП ЊЕГОВОЈ ЛОЗИНЦИ ЂАК ЋЕ ДОЋИ', 'sr']]) {
			assert.equal(detectLanguage(text).language, language, text);
		}
	});

	it('tells names from other words in linear time', () => {
		const time = text => {
			const started = cpuTime();
			detectLanguage(text);
			return cpuTime() - started;
		};

		for (const make of [n => 'Ры '.repeat(n), n => 'Ә. ы '.repeat(n), n => 'Ы'.repeat(n * 3)]) {
			const fastest = text => Math.min(time(text), time(text), time(text));
			const small = fastest(make(1500));
			const large = fastest(make(6000));
			assert.ok(large < 8 * Math.max(small, 5), `${Math.round(small)}ms, then ${Math.round(large)}ms`);
		}
	});

	it('names Malagasy with its two-letter code', () => {
		assert.equal(detectLanguage('Ny olombelona rehetra dia teraka afaka sy mitovy zo sy fahamendrehana. Samy manan-tsaina sy fieritreretana izy ary tokony hifampitondra am-pirahalahiana.').language, 'mg');
		assert.equal(normalizeLanguageCode('mlg'), 'mg');
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

	it('normalizes codes of the same language as one detected', () => {
		for (const [code, detected] of [['no', 'nb'], ['nor', 'nb'], ['no-NO', 'nb'], ['fil', 'tl'], ['fil-PH', 'tl'], ['iw', 'he'], ['in', 'id'], ['ji', 'yi'], ['yid', 'yi'], ['nn', 'nn'], ['nob', 'nb']]) {
			assert.equal(normalizeLanguageCode(code), detected, code);
		}
	});

	it('normalizes language codes', () => {
		assert.equal(normalizeLanguageCode('eng'), 'en');
		assert.equal(normalizeLanguageCode('en-US'), 'en');
		assert.equal(normalizeLanguageCode('pt_BR'), 'pt');
		assert.equal(normalizeLanguageCode('xyz'), 'xyz');
		assert.equal(normalizeLanguageCode('ENG'), 'en');
		assert.equal(normalizeLanguageCode('zh-Hant-TW'), 'zh');
		assert.equal(normalizeLanguageCode(''), null);
		assert.equal(normalizeLanguageCode(null), null);
	});
});
