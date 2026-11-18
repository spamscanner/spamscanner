import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {
	chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, utimesSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {describe, it} from 'node:test';
import {Classifier} from '../src/classifier.js';
import {
	defaultModelPath, embeddedModel, loadDefaultModel, loadModel, loadSea, moduleDirectory, saveModel,
} from '../src/model.js';
import {CLASSIFIER_MODELS, DECISION_MODELS, RECOMMENDED_MODELS} from '../src/models.js';
import {PROVIDERS} from '../src/llm.js';
import {SpamScanner} from '../src/index.js';
import {VERSION} from '../src/version.js';
import {everydayLanguages, everydayMail} from '../scripts/everyday-mail.js';
import {temporaryDirectory} from './helpers/index.js';

function trained() {
	const classifier = new Classifier();
	classifier.learn(['prize', 'winner'], 'spam');
	classifier.learn(['meeting', 'agenda'], 'ham');
	return classifier;
}

function fakeSea(asset) {
	return {
		isSea: () => asset !== undefined,
		getAsset(name, encoding) {
			assert.equal(name, 'classifier.json');
			assert.equal(encoding, 'utf8');
			if (asset instanceof Error) {
				throw asset;
			}

			return asset;
		},
	};
}

describe('model files', () => {
	it('finds the bundled model next to the package, or the one in SPAMSCANNER_MODEL', () => {
		assert.equal(moduleDirectory(), path.resolve('src'));
		assert.equal(defaultModelPath(), path.resolve('model/classifier.json'));
		assert.equal(defaultModelPath(path.resolve('dist/esm')), path.resolve('model/classifier.json'));
		assert.equal(defaultModelPath(temporaryDirectory()), null);
		process.env.SPAMSCANNER_MODEL = 'custom/model.json';
		try {
			assert.equal(defaultModelPath(), path.resolve('custom/model.json'));
		} finally {
			delete process.env.SPAMSCANNER_MODEL;
		}
	});

	it('loads the bundled model once and gives each caller its own classifier', () => {
		const first = loadDefaultModel();
		const second = loadDefaultModel({spamCutoff: 0.95});
		assert.ok(first.nspam > 1000 && first.nham > 1000);
		assert.equal(first.frozen, second.frozen);
		assert.equal(second.options.spamCutoff, 0.95);
		assert.ok(first.metadata.trainedOn.length > 0);
		first.learn(['only-in-first'], 'spam');
		assert.equal(second.nspam, first.nspam - 1);
	});

	it('saves and reloads models, reading a file again after it is saved', () => {
		const file = path.join(temporaryDirectory(), 'nested', 'model.json');
		saveModel(trained(), file, {metadata: {note: 'test'}});
		assert.ok(existsSync(file));
		const loaded = loadModel(file);
		assert.equal(loaded.metadata.note, 'test');
		assert.equal(loaded.classify(['prize']).probability > 0.5, true);
		const more = trained();
		more.learn(['third'], 'spam');
		saveModel(more, file);
		assert.equal(loadModel(file).nspam, 2);
		assert.equal(JSON.parse(readFileSync(file, 'utf8')).type, 'spamscanner-classifier');
	});

	it('keeps the permissions of the file it replaces', {skip: process.platform === 'win32'}, () => {
		const directory = temporaryDirectory();
		const file = path.join(directory, 'model.json');
		saveModel(trained(), file);
		chmodSync(file, 0o640);
		saveModel(trained(), file);
		assert.equal(statSync(file).mode & 0o777, 0o640);
		chmodSync(file, 0o600);
		saveModel(trained(), file);
		assert.equal(statSync(file).mode & 0o777, 0o600);
		assert.deepEqual(readdirSync(directory), ['model.json']);
	});

	it('leaves no temporary file when a model cannot be saved', () => {
		const directory = temporaryDirectory();
		const file = path.join(directory, 'model.json');
		// (a directory in the way: the rename fails)
		mkdirSync(path.join(file, 'inside'), {recursive: true});
		assert.throws(() => saveModel(trained(), file));
		assert.deepEqual(readdirSync(directory), ['model.json']);
		assert.deepEqual(readdirSync(file), ['inside']);
	});

	it('saves through a temporary file of its own each time', () => {
		const directory = temporaryDirectory();
		const file = path.join(directory, 'model.json');
		// (a file another save of this process is still writing, at the name
		//  every save of a process once used)
		mkdirSync(`${file}.${process.pid}.tmp`);
		saveModel(trained(), file);
		assert.equal(loadModel(file).nspam, 1);
		assert.deepEqual(readdirSync(directory).sort(), ['model.json', `model.json.${process.pid}.tmp`]);
	});

	it('uses the model embedded in a standalone binary', () => {
		const json = JSON.stringify(trained().toJSON());
		assert.equal(embeddedModel(fakeSea(json)), json);
		assert.equal(embeddedModel(fakeSea()), null);
		assert.equal(embeddedModel(fakeSea(new Error('no asset'))), null);
		assert.equal(embeddedModel(null), null);
		assert.equal(embeddedModel(), null);
		const fromBinary = loadDefaultModel({}, {file: null, sea: fakeSea(json)});
		assert.equal(fromBinary.nspam, 1);
		assert.equal(loadDefaultModel({hamCutoff: 0.1}, {file: null, sea: fakeSea(json)}).options.hamCutoff, 0.1);
		const empty = loadDefaultModel({}, {file: null, sea: fakeSea()});
		assert.equal(empty.nspam, 0);
		assert.equal(loadSea(() => {
			throw new Error('No such built-in module: node:sea');
		}), null);
		assert.equal(typeof loadSea(name => ({name})).name, 'string');
	});

	it('writes a model in one step, and reads a file again when it changes', () => {
		const directory = temporaryDirectory();
		const file = path.join(directory, 'model.json');
		saveModel(trained(), file);
		// (written to a temporary file, then renamed: nothing else is left)
		assert.deepEqual(readdirSync(directory), ['model.json']);
		assert.equal(loadModel(file).nspam, 1);
		// (changed by another process)
		const more = trained();
		more.learn(['third'], 'spam');
		writeFileSync(file, JSON.stringify(more.toJSON()));
		utimesSync(file, new Date(), new Date(Date.now() + 5000));
		assert.equal(loadModel(file).nspam, 2);
	});

	it('rejects a broken model file', () => {
		const file = path.join(temporaryDirectory(), 'broken.json');
		writeFileSync(file, '{"type":"something-else"}');
		assert.throws(() => loadModel(file), /Not a Spam Scanner classifier model/);
	});
});

describe('recommended models', () => {
	it('lists open models with an Ollama tag, a Hugging Face repository and a license', () => {
		assert.ok(RECOMMENDED_MODELS.some(model => model.ollama === PROVIDERS.ollama.model), 'the default Ollama model is recommended');
		for (const model of [...RECOMMENDED_MODELS, ...CLASSIFIER_MODELS]) {
			assert.match(model.huggingface, /^[\w.-]+\/[\w.-]+$/);
			assert.match(model.license, /^(?:Apache-2\.0|MIT)$/);
		}

		for (const model of RECOMMENDED_MODELS) {
			assert.match(model.ollama, /^[\w.-]+:[\w.]+$/);
			assert.match(model.size, /^\d+(?:\.\d)? GB$/);
		}

		assert.match(VERSION, /^\d+\.\d+\.\d+/);
	});

	it('lists hosted decision models that have a provider preset', () => {
		for (const model of DECISION_MODELS) {
			assert.equal(PROVIDERS[model.provider].api, 'decision', model.provider);
			assert.equal(PROVIDERS[model.provider].name, model.name);
			assert.ok(model.weights === null || /^[\w.-]+\/[\w.-]+$/.test(model.weights));
			assert.ok(model.notes.length > 20);
		}
	});
});

describe('the bundled model', () => {
	// (a mail server's standard words, not those of the message it returns)
	const bounce = (from, subject, text) => Buffer.from(`Return-Path: <>\r\nFrom: ${from}\r\nTo: sam@customer.example\r\nSubject: ${subject}\r\nDate: Tue, 17 Nov 2026 10:00:05 +0000\r\nMessage-ID: <b1@mx.far.example>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n${text.replaceAll('\n', '\r\n')}\r\n`);
	const returned = 'Return-Path: <sam@customer.example>\nReceived: from mail.customer.example (mail.customer.example [192.0.2.10])\n\tby mx.far.example with ESMTP id ABC123; Tue, 17 Nov 2026 10:00:00 +0000\nFrom: Sam <sam@customer.example>\nTo: dana@far.example\nSubject: Notes from Tuesday\nDate: Tue, 17 Nov 2026 10:00:00 +0000\nMessage-ID: <m1@customer.example>\n';
	const scan = async raw => {
		const result = await new SpamScanner({phishing: {cloudflare: false}}).scan(raw);
		return result.results.classification.probability;
	};

	it('does not take a mail server\'s bounce for spam by its standard words', async () => {
		const bounces = {
			sendmail: bounce('Mail Delivery Subsystem <MAILER-DAEMON@mx.far.example>', 'Returned mail: see transcript for details', `The original message was received at Tue, 17 Nov 2026 10:00:01 GMT\nfrom mail.customer.example [192.0.2.10]\n\n   ----- The following addresses had permanent fatal errors -----\n<dana@far.example>\n    (reason: 550 5.1.1 <dana@far.example>... User unknown)\n\n   ----- Transcript of session follows -----\n... while talking to mail.far.example.:\n>>> DATA\n<<< 550 5.1.1 <dana@far.example>... User unknown\n550 5.1.1 <dana@far.example>... User unknown\n<<< 503 5.0.0 Need RCPT (recipient)\n\n   ----- Original message follows -----\n\n${returned}`),
			exim: bounce('Mail Delivery System <Mailer-Daemon@host7.hosting.example>', 'Mail delivery failed: returning message to sender', `This message was created automatically by mail delivery software.\n\nA message that you sent could not be delivered to one or more of its\nrecipients. This is a permanent error. The following address(es) failed:\n\n  dana@far.example\n    mailbox is full: retry timeout exceeded\n\n------ This is a copy of the message, including all the headers. ------\n------ The body of the message is 4512 characters long; only the first\n------ 106 characters will be returned.\n\n${returned}`),
			qmail: bounce('MAILER-DAEMON@mx.far.example', 'failure notice', `Hi. This is the qmail-send program at mx.far.example.\nI'm afraid I wasn't able to deliver your message to the following addresses.\nThis is a permanent error; I've given up. Sorry it didn't work out.\n\n<dana@far.example>:\nSorry, no mailbox here by that name. (#5.1.1)\n\n--- Below this line is a copy of the message.\n\n${returned}`),
			postfix: bounce('MAILER-DAEMON@mx.far.example (Mail Delivery System)', 'Undelivered Mail Returned to Sender', 'This is the mail system at host mx.far.example.\n\nI\'m sorry to have to inform you that your message could not\nbe delivered to one or more recipients. It\'s attached below.\n\nFor further assistance, please send mail to postmaster.\n\nIf you do so, please include this problem report. You can\ndelete your own text from the attached returned message.\n\n                   The mail system\n\n<dana@far.example>: host mail.far.example[198.51.100.7] said: 550 5.1.1\n    <dana@far.example>: Recipient address rejected: User unknown in virtual\n    mailbox table (in reply to RCPT TO command)'),
		};
		for (const [name, raw] of Object.entries(bounces)) {
			assert.ok(await scan(raw) < 0.5, name);
		}
	});

	it('still takes phishing written as a bounce for spam', async () => {
		assert.ok(await scan(bounce('Mail Delivery System <Mailer-Daemon@customer.example>', 'Mail delivery failed: returning message to sender', 'This message was created automatically by mail delivery software.\n\nA message that you sent could not be delivered to one or more of its recipients. This is a permanent error.\n\nYour mailbox has exceeded its quota and 12 incoming messages are on hold. Verify your account to restore delivery and release held messages:\n\nhttps://mailbox-verify.example/restore?id=sam\n\nThis link expires in 24 hours.')) >= 0.99);
	});

	it('tells ordinary mail from a fraud in the languages it has little real mail of', async () => {
		const mail = (subject, text) => Buffer.from(`From: Robin <robin@family.example>\r\nTo: sam@customer.example\r\nSubject: ${subject}\r\nDate: Tue, 17 Nov 2026 10:00:05 +0000\r\nMessage-ID: <m1@family.example>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${text}\r\n`);
		const ordinary = {
			fr: ['Dîner de jeudi', 'Bonjour Claire, merci pour ton message. Je passerai chercher les enfants à l\'école jeudi, puis nous irons dîner chez mes parents. Peux-tu apporter le dessert ? Dis-moi si cela te convient. Bises, Julien'],
			nl: ['Etentje donderdag', 'Hoi Sanne, bedankt voor je bericht. Ik haal de kinderen donderdag van school en daarna eten we bij mijn ouders. Kun jij het toetje meenemen? Laat maar weten of dat goed uitkomt. Groetjes, Daan'],
			pt: ['Jantar de quinta-feira', 'Olá Marta, obrigado pela tua mensagem. Vou buscar as crianças à escola na quinta-feira e depois jantamos em casa dos meus pais. Podes trazer a sobremesa? Diz-me se te dá jeito. Beijinhos, Tiago'],
			nb: ['Middag på torsdag', 'Hei Ingrid, takk for meldingen. Jeg henter barna på skolen på torsdag, og etterpå spiser vi middag hos foreldrene mine. Kan du ta med dessert? Si fra om det passer for deg. Hilsen Lars'],
			sv: ['Middag på torsdag', 'Hej Karin, tack för ditt meddelande. Jag hämtar barnen i skolan på torsdag och sedan äter vi middag hos mina föräldrar. Kan du ta med efterrätten? Hör av dig om det passar. Hälsningar, Erik'],
			da: ['Middag på torsdag', 'Hej Mette, tak for din besked. Jeg henter børnene i skolen på torsdag, og bagefter spiser vi middag hos mine forældre. Kan du tage desserten med? Sig til, om det passer dig. Hilsen Anders'],
			tr: ['Perşembe yemeği', 'Merhaba Elif, mesajın için teşekkürler. Perşembe günü çocukları okuldan ben alacağım, sonra annemlerde yemek yiyeceğiz. Tatlıyı sen getirebilir misin? Sana uyup uymadığını haber ver. Sevgiler, Can'],
			pl: ['Kolacja w czwartek', 'Cześć Kasiu, dziękuję za wiadomość. W czwartek odbiorę dzieci ze szkoły, a potem zjemy kolację u moich rodziców. Czy możesz przynieść deser? Daj znać, czy ci to pasuje. Pozdrawiam, Tomek'],
			ja: ['木曜日の夕食', '恵子さん、ご連絡ありがとうございます。木曜日は私が子どもたちを学校に迎えに行き、そのあと両親の家で夕食をとります。デザートを持ってきてもらえますか。都合を教えてください。健太'],
			ar: ['عشاء الخميس', 'مرحباً ليلى، شكراً على رسالتك. سآخذ الأطفال من المدرسة يوم الخميس ثم نتناول العشاء في بيت والديّ. هل يمكنك إحضار الحلوى؟ أخبريني إن كان ذلك يناسبك. تحياتي، كريم'],
		};
		const fraud = {
			fr: ['Félicitations, vous avez gagné', 'Félicitations ! Vous avez gagné 500 000 € à notre loterie. Cliquez ici immédiatement pour réclamer votre prix et confirmez vos coordonnées bancaires avant 24 heures, sinon votre gain sera annulé.'],
			pt: ['Parabéns, você ganhou', 'Parabéns! Você ganhou 500 000 € na nossa lotaria. Clique aqui imediatamente para reclamar o seu prémio e confirme os seus dados bancários em 24 horas, caso contrário o prémio será cancelado.'],
			nl: ['Gefeliciteerd, u heeft gewonnen', 'Gefeliciteerd! U heeft 500 000 € gewonnen in onze loterij. Klik hier onmiddellijk om uw prijs op te eisen en bevestig uw bankgegevens binnen 24 uur, anders vervalt uw prijs.'],
			sv: ['Grattis, du har vunnit', 'Grattis! Du har vunnit 500 000 kr i vårt lotteri. Klicka här omedelbart för att hämta din vinst och bekräfta dina bankuppgifter inom 24 timmar, annars förfaller vinsten.'],
			tr: ['Tebrikler, kazandınız', 'Tebrikler! Çekilişimizde 500 000 TL kazandınız. Ödülünüzü almak için hemen buraya tıklayın ve 24 saat içinde banka bilgilerinizi doğrulayın, aksi halde ödülünüz iptal edilecek.'],
			ja: ['おめでとうございます、当選しました', 'おめでとうございます！当社の宝くじで500万円が当選しました。今すぐここをクリックして賞金を受け取り、24時間以内に銀行口座情報を確認してください。確認されない場合、当選は取り消されます。'],
		};
		for (const [language, [subject, text]] of Object.entries(ordinary)) {
			assert.ok(await scan(mail(subject, text)) < 0.2, language);
		}

		for (const [language, [subject, text]] of Object.entries(fraud)) {
			assert.ok(await scan(mail(subject, text)) > 0.9, language);
		}
	});

	it('is trained on written mail that is the same each time', () => {
		const messages = [...everydayMail()];
		assert.deepEqual([...everydayMail()], messages);
		const languages = Object.keys(everydayLanguages());
		assert.equal(languages.length, 23);
		for (const language of languages) {
			const own = messages.filter(message => message.language === language);
			assert.deepEqual([own.filter(message => message.label === 'ham').length, own.filter(message => message.label === 'spam').length], [300, 200], language);
			// (no sentence left with a blank to fill)
			assert.ok(own.every(message => message.subject && message.text && !/[{}]/.test(message.subject + message.text)), language);
			assert.ok(new Set(own.map(message => message.subject + message.text)).size > 490, language);
		}

		assert.equal([...everydayMail({ham: 2, spam: 1})].length, 69);
	});
});
