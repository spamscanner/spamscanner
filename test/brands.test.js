import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import process from 'node:process';
import {describe, it} from 'node:test';
import {DISPLAY_BRANDS, brandsIn} from '../src/brands.js';

// The brands a text names, as the names found of them
const named = text => brandsIn(text).brands.map(entry => entry.brand);

describe('brands', () => {
	it('finds each name of each brand as itself, and none twice', () => {
		const seen = new Set();
		for (const {names, capitals} of DISPLAY_BRANDS) {
			for (const {name, words, pattern} of names) {
				const text = capitals ? name.toUpperCase() : name;
				assert.ok(pattern.test(text), name);
				assert.ok(words.some(word => text.includes(word)), name);
				assert.equal(name, name.toLowerCase(), name);
				assert.ok(!seen.has(name), name);
				seen.add(name);
			}
		}

		assert.ok(DISPLAY_BRANDS.length > 500);
	});

	it('lists each brand\'s domains as names, domains or patterns of whole domains', () => {
		for (const {brand, official} of DISPLAY_BRANDS) {
			assert.ok(official.length > 0, brand);
			for (const entry of official) {
				assert.ok(entry instanceof RegExp ? /^\^.*\$$|\$$/.test(entry.source) : /^[a-z\d](?:[a-z\d.-]*[a-z\d])?$/.test(entry), `${brand}: ${entry}`);
			}
		}
	});

	it('reads a name in its own script and in Latin letters, with or without its accents, in capitals or small letters', () => {
		for (const [text, brand] of [
			['Сбербанк Онлайн', 'сбербанк'],
			['SBERBANK ONLINE', 'sberbank'],
			['Госуслуги: новое уведомление', 'госуслуги'],
			['三井住友カードからのお知らせ', '三井住友'],
			['【重要】ヤマト運輸よりお荷物のお届けについて', 'ヤマト運輸'],
			['支付宝安全中心', '支付宝'],
			['카카오뱅크 고객센터', '카카오뱅크'],
			['ไปรษณีย์ไทย แจ้งเตือนพัสดุ', 'ไปรษณีย์ไทย'],
			['بريد الإمارات', 'بريد الإمارات'],
			['بريد الامارات', 'بريد الإمارات'],
			['דואר ישראל', 'דואר ישראל'],
			['Itaú Unibanco', 'itaú'],
			['ITAU UNIBANCO', 'itaú'],
			['Crédit Agricole', 'crédit agricole'],
			['CREDIT AGRICOLE', 'crédit agricole'],
			['Société Générale', 'société générale'],
			['İş Bankası', 'iş bankası'],
			['İŞ BANKASI', 'iş bankası'],
			['Τράπεζα Πειραιώς', 'τράπεζα πειραιώς'],
			['ΤΡΑΠΕΖΑ ΠΕΙΡΑΙΩΣ', 'τράπεζα πειραιώς'],
			['Česká pošta', 'česká pošta'],
			['Ceska posta', 'česká pošta'],
			['Poșta Română', 'poșta română'],
			['Österreichische Post', 'österreichische post'],
			['Caisse d\'Epargne', 'caisse d\'épargne'],
			['Caisse d’Épargne', 'caisse d\'épargne'],
		]) {
			assert.deepEqual(named(text), [brand], text);
		}
	});

	it('reads the words of a name together or apart, and a hyphen in it or not', () => {
		for (const [text, brand] of [
			['Wells Fargo', 'wells fargo'],
			['WellsFargo', 'wells fargo'],
			['Wells-Fargo', 'wells fargo'],
			['wells.fargo', 'wells fargo'],
			['Royal  Mail', 'royal mail'],
			['e-Boks', 'e-boks'],
			['eBoks', 'e-boks'],
			['M-PESA', 'm-pesa'],
			['Booking.com', 'booking.com'],
			['1&1', '1&1'],
			['K&H Bank', 'k&h bank'],
		]) {
			assert.deepEqual(named(text), [brand], text);
		}

		// (not a hyphenated name apart: "M&T Bank" is no T-Bank, "AT&T
		//  Online" no T-Online; nor a name with a dot as any character)
		for (const text of ['M&T Bank Stadium', 'AT&T Online Services', 'Bookingxcom']) {
			assert.deepEqual(named(text), [], text);
		}
	});

	it('reads a name beside the words of a script written without spaces, but not inside a word', () => {
		for (const [text, brand] of [
			['Amazonプライム会員', 'amazon'],
			['【American Express】ご利用確認', 'american express'],
			['こちらはゆうちょ銀行です', 'ゆうちょ銀行'],
			['メルカリ事務局', 'メルカリ'],
			['NTTドコモ', 'ドコモ'],
			['ドコモ光', 'ドコモ'],
		]) {
			assert.deepEqual(named(text), [brand], text);
		}

		// (inside a word: of Latin letters, of Katakana before a name in
		//  Katakana, or after a short one)
		for (const text of ['Shipayments', 'Linkedinning', 'netflixing', 'レビューカードのご案内', 'オリコンランキング', 'Dkbx', 'sign-ups and follow-ups', 'the n26-plan', 'Сбербанковский', 'ПриватБанку123']) {
			assert.deepEqual(named(text), [], text);
		}
	});

	it('reads a name that is also a word or an abbreviation alone, or beside the words of its services', () => {
		for (const [text, brand] of [
			['Orange', 'orange'],
			['Orange Business', 'orange'],
			['Service client Orange', 'orange'],
			['ING', 'ing'],
			['ING-DiBa', 'ing-diba'],
			['Mijn ING', 'ing'],
			['Stripe Support', 'stripe'],
			['Wise', 'wise'],
			['LINE', 'line'],
			['LINE公式アカウント', 'line'],
			['Caixa Econômica Federal', 'caixa'],
			['Correios: sua encomenda aguarda retirada', 'correios'],
			['Meta for Business', 'meta'],
			['Meta Verified', 'meta'],
			['ANZ Internet Banking', 'anz'],
			['Aruba.it', 'aruba'],
			['Ledger Live', 'ledger'],
			['Citi Cards', 'citi'],
			['SARS eFiling', 'sars'],
			['GLS Paket', 'gls'],
			['Hermes Paketshop', 'hermes'],
			['Desjardins', 'desjardins'],
			['AccèsD Desjardins', 'desjardins'],
			['Knab', 'knab'],
			['Knab Bank', 'knab'],
			['SEUR: tu envío está en reparto', 'seur'],
			['ELTA Courier', 'elta'],
			['BROU: aviso de seguridad', 'brou'],
			['Strato Hosting', 'strato'],
			['Ameli', 'ameli'],
			['ameli.fr', 'ameli'],
			['Ameli : votre remboursement', 'ameli'],
			['Votre compte ameli', 'ameli'],
			['Argenta Bank', 'argenta'],
			['Landbank iAccess', 'landbank'],
			['Coppel Pay', 'coppel'],
			['Starken Chile', 'starken'],
		]) {
			assert.deepEqual(named(text), [brand], text);
		}

		for (const text of [
			'Orange County Choppers', 'Orange is the new black', 'ING. JUAN PEREZ', 'ing', 'Stripe pattern shirts', 'Wise Owl Books', 'NEW LINE OF PRODUCTS', 'ON LINE PAYMENT', 'caixa de entrada', 'Tus correos electrónicos', 'Meta analysis of trials', 'Salesforce ANZ Summit', 'Aruba holidays', 'The Public Ledger', 'Citi Field', 'SARS-CoV-2', 'Mercedes GLS 450', 'Hermes Paris', 'Marie Desjardins', 'Peter Knab', 'De seur van mijn broer', 'Elta MD Skincare', 'Brou de noix pour vos meubles', 'Nuovo strato protettivo per il legno', 'Ameli Schmidt', 'Argenta Ceramica', 'Wayne County Landbank', 'Ana Coppel', 'Mit starken Angeboten in den Herbst',
		]) {
			assert.deepEqual(named(text), [], text);
		}
	});

	it('reads a name written with lookalike letters as its reader does, and notes one no keyboard explains', () => {
		const read = text => brandsIn(text).brands.map(entry => [entry.brand, entry.lookalike]);
		// (a Cyrillic or Greek letter inside a word in Latin letters, and a
		//  letter of the phonetic alphabet anywhere in the name)
		for (const [text, brand] of [
			['P\u0430ypal', 'paypal'],
			['Netfl\u0456x', 'netflix'],
			['Wells F\u0430rgo', 'wells fargo'],
			['\u0410m\u0430zon', 'amazon'],
			['P\u0251yp\u0251l', 'paypal'],
			['\u0251mazon', 'amazon'],
			['Goo\u0261le', 'google'],
			['\u03A5\u0251hoo Mail', 'yahoo'],
			['\u0397\u0251lifax', 'halifax'],
			['D\u0397L Express', 'dhl'],
			['U\u0420S', 'ups'],
		]) {
			assert.deepEqual(read(text), [[brand, true]], text);
		}

		// (not a letter of another script at the start or the end of a word,
		//  as a typist who changes keyboards a letter late or early leaves
		//  it, nor Latin letters in a Cyrillic word; nor wide letters or an
		//  invisible character, which are counted on their own)
		for (const [text, brand] of [
			['PayPal', 'paypal'],
			['\u039Detflix', 'netflix'],
			['American \u0415xpress', 'american express'],
			['\u039D\u0395\u03A4flix', 'netflix'],
			['\u0420aypal', 'paypal'],
			['Netfli\u03C7', 'netflix'],
			['\u0395DF', 'edf'],
			['C\u0431\u0435\u0440\u0431\u0430\u043D\u043A', '\u0441\u0431\u0435\u0440\u0431\u0430\u043D\u043A'],
			['\u0421\u0431\u0435\u0440\u0431a\u043D\u043A', '\u0441\u0431\u0435\u0440\u0431\u0430\u043D\u043A'],
			['\u041C\u0422C', '\u043C\u0442\u0441'],
			['\uFF2E\uFF45\uFF54\uFF46\uFF4C\uFF49\uFF58', 'netflix'],
			['Pay\u200BPal', 'paypal'],
		]) {
			assert.deepEqual(read(text), [[brand, false]], text);
		}

		// (a word of one script, a unit and a capital that looks like no
		//  Latin letter are read as they are)
		for (const text of ['\u0399\u039D\u0393', '\u039D\u0395\u0391', 'U\u03A9S', 'I\u041FG', '5 k\u2126']) {
			assert.deepEqual(read(text), [], text);
		}
	});

	it('does not read a word that says something else, or a place named for its sponsor, as the brand', () => {
		for (const text of [
			'Saving the Amazon rainforest', 'アマゾン川の旅', 'Nutritional Outlook', 'Economic Outlook 2027', 'Canada post-secondary education', 'An post-mortem of the launch', 'El mercado libre y la competencia', 'Mercado livre de energia', '楽天的な人', '中国银行业协会', '中国移动互联网大会', 'Paid by standard bank transfer', 'Agencia Tributaria de Andalucía', 'Home Equity Bank', 'Barclays Center', 'Wells Fargo Center', 'Intuit Dome', 'UBS Arena', 'Truist Park', 'PayPal Park', 'Suncorp Stadium', 'Volksbank-Arena', 'Estadio Banorte', 'Estádio Bradesco',
		]) {
			assert.deepEqual(named(text), [], text);
		}

		// (as a magazine or a report is named, not as phishing mail writes it)
		for (const text of ['Outlook', 'Microsoft Outlook', 'Your Outlook storage is full', 'Sign in to Outlook', 'Outlook Web App']) {
			assert.ok(named(text).includes('outlook'), text);
		}

		// (and the brand itself beside one: its second mention is its own)
		assert.deepEqual(named('UBS'), ['ubs']);
		assert.deepEqual(named('Banorte'), ['banorte']);
	});

	it('makes the pattern of a name when a text first holds a word of it, not all of them when loaded', () => {
		// (the processor time a new process takes to load the names, against
		//  the time to load what they are read with: making every pattern
		//  takes ten times as long)
		const loading = file => Number(execFileSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(new URL(file, import.meta.url).href)}); const {user, system} = process.cpuUsage(); console.log(user + system);`], {encoding: 'utf8'}));
		assert.ok(loading('../src/brands.js') < 3 * loading('../src/tokenizer.js'));
	});

	it('reads a text that names no brand without reading it for each', () => {
		assert.deepEqual(named(''), []);
		assert.deepEqual(named('Minutes of the meeting on Tuesday'), []);
		assert.deepEqual(named('Your PayPal and Netflix accounts'), ['paypal', 'netflix']);
	});
});
