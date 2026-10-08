// Test helpers: synthetic messages and real local servers (DNS, HTTP, clamd,
// milter client) so tests exercise the actual protocols. No real email data.
import {Buffer} from 'node:buffer';
import {randomBytes} from 'node:crypto';
import dgram from 'node:dgram';
import {once} from 'node:events';
import {mkdtempSync} from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

/**
 * A temporary directory, removed by the OS eventually.
 * @returns {string}
 */
export function temporaryDirectory() {
	return mkdtempSync(path.join(os.tmpdir(), 'spamscanner-test-'));
}

function encodeHeader(value) {
	return /^[ -~]*$/.test(value) ? value : `=?UTF-8?B?${Buffer.from(value).toString('base64')}?=`;
}

/**
 * Build a raw message.
 * @param {object} options
 * @param {string} [options.from]
 * @param {string} [options.to]
 * @param {string} [options.subject]
 * @param {string} [options.text]
 * @param {string} [options.html]
 * @param {Array<{filename: string, content: Buffer|string, contentType?: string}>} [options.attachments]
 * @param {Record<string, string>} [options.headers]
 * @param {boolean} [options.date] - add a Date header (default true)
 * @param {boolean} [options.messageId] - add a Message-ID header (default true)
 * @returns {string}
 */
export function message(options = {}) {
	const {
		from = 'Alice Example <alice@example.org>', to = 'bob@example.net', subject = 'Hello', text, html, attachments = [], headers = {}, date = true, messageId = true,
	} = options;
	const lines = [];
	if (from !== null) {
		lines.push(`From: ${from}`);
	}

	lines.push(`To: ${to}`, `Subject: ${encodeHeader(subject)}`);
	if (date) {
		lines.push('Date: Mon, 05 Oct 2026 09:30:00 +0000');
	}

	if (messageId) {
		lines.push(`Message-ID: <${randomBytes(6).toString('hex')}@example.org>`);
	}

	for (const [name, value] of Object.entries(headers)) {
		lines.push(`${name}: ${value}`);
	}

	lines.push('MIME-Version: 1.0');
	const textPart = text === undefined ? null : ['Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', Buffer.from(text).toString('base64')].join('\r\n');
	const htmlPart = html === undefined ? null : ['Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: base64', '', Buffer.from(html).toString('base64')].join('\r\n');
	const bodyParts = [textPart, htmlPart].filter(Boolean);
	const attachmentParts = attachments.map(attachment => [
		`Content-Type: ${attachment.contentType || 'application/octet-stream'}; name="${attachment.filename}"`,
		`Content-Disposition: attachment; filename="${attachment.filename}"`,
		'Content-Transfer-Encoding: base64',
		'',
		Buffer.from(attachment.content).toString('base64').replaceAll(/.{76}/g, '$&\r\n'),
	].join('\r\n'));

	if (attachmentParts.length === 0 && bodyParts.length <= 1) {
		const part = bodyParts[0] || 'Content-Type: text/plain; charset=utf-8\r\n\r\n';
		return `${lines.join('\r\n')}\r\n${part}\r\n`;
	}

	const boundary = `b${randomBytes(8).toString('hex')}`;
	const parts = [];
	if (bodyParts.length > 1) {
		const inner = `a${randomBytes(8).toString('hex')}`;
		parts.push(`Content-Type: multipart/alternative; boundary="${inner}"\r\n\r\n${bodyParts.map(part => `--${inner}\r\n${part}`).join('\r\n')}\r\n--${inner}--`);
	} else if (bodyParts.length === 1) {
		parts.push(bodyParts[0]);
	}

	parts.push(...attachmentParts);
	return `${lines.join('\r\n')}\r\nContent-Type: multipart/mixed; boundary="${boundary}"\r\n\r\n${parts.map(part => `--${boundary}\r\n${part}`).join('\r\n')}\r\n--${boundary}--\r\n`;
}

// Synthetic examples, in several languages, for training and scanning tests.
export const SPAM = [
	['en', 'You have won a free prize', 'Congratulations winner! You have been selected to receive a free prize of one million dollars. Click here now to claim your reward before it expires. Act now, limited time offer!'],
	['en', 'Cheap pills online', 'Buy cheap pills online without prescription. Discount pharmacy, free shipping, best prices guaranteed. Order now and save ninety percent today!'],
	['en', 'Verify your account now', 'Your account has been suspended due to unusual activity. Verify your password immediately or your account will be closed. Click the link to confirm your identity.'],
	['de', 'Sie haben gewonnen', 'Herzlichen Glückwunsch! Sie haben einen Preis von einer Million Euro gewonnen. Klicken Sie jetzt hier, um Ihren Gewinn abzuholen. Nur für kurze Zeit!'],
	['es', 'Has ganado un premio', 'Felicidades, has ganado un premio de un millón de euros. Haz clic aquí ahora para reclamar tu premio gratis. ¡Oferta por tiempo limitado!'],
	['fr', 'Vous avez gagné', 'Félicitations, vous avez gagné un prix d\'un million d\'euros. Cliquez ici maintenant pour réclamer votre prix gratuit. Offre limitée dans le temps!'],
	['ru', 'Вы выиграли приз', 'Поздравляем! Вы выиграли миллион долларов. Нажмите здесь прямо сейчас, чтобы получить свой бесплатный приз. Предложение ограничено по времени!'],
	['zh', '恭喜您中奖了', '恭喜您获得一百万元大奖！请立即点击链接领取您的免费奖金。限时优惠，机不可失！'],
	['ja', 'おめでとうございます当選しました', 'おめでとうございます！百万円が当選しました。今すぐこちらをクリックして無料の賞金を受け取ってください。期間限定です！'],
	['ar', 'لقد ربحت جائزة', 'تهانينا! لقد ربحت جائزة بقيمة مليون دولار. انقر هنا الآن للحصول على جائزتك المجانية. عرض لفترة محدودة!'],
	['ko', '당첨을 축하합니다', '축하합니다! 백만 달러에 당첨되셨습니다. 지금 여기를 클릭하여 무료 상금을 받으세요. 기간 한정 혜택입니다!'],
	['hi', 'आपने इनाम जीता है', 'बधाई हो! आपने दस लाख रुपये का इनाम जीता है। अपना मुफ्त इनाम पाने के लिए अभी यहां क्लिक करें। सीमित समय का प्रस्ताव!'],
	['th', 'คุณได้รับรางวัล', 'ยินดีด้วย คุณได้รับรางวัลเงินสดหนึ่งล้านบาท คลิกที่นี่ตอนนี้เพื่อรับรางวัลฟรีของคุณ ข้อเสนอมีเวลาจำกัด'],
];

export const HAM = [
	['en', 'Lunch on Thursday', 'Hi Bob, are we still on for lunch on Thursday at noon? I can book a table at the usual place near the office. Let me know what works for you. Thanks, Alice'],
	['en', 'Notes from the planning meeting', 'Hello team, attached are the notes from yesterday\'s planning meeting. Please review the action items before Friday and add your comments to the shared document.'],
	['en', 'Weekend plans', 'Hey, the kids want to go hiking on Saturday morning if the weather is good. Do you want to join us? We could have a picnic by the lake afterwards.'],
	['de', 'Treffen am Freitag', 'Hallo Anna, wir treffen uns am Freitag um zehn Uhr im Büro, um den Projektplan zu besprechen. Bitte bring den Bericht vom letzten Monat mit. Viele Grüße'],
	['es', 'Reunión del lunes', 'Hola María, te escribo para confirmar la reunión del lunes a las diez en la oficina. Por favor trae el informe del proyecto. Un saludo'],
	['fr', 'Réunion de lundi', 'Bonjour Pierre, je te confirme la réunion de lundi à dix heures au bureau pour discuter du projet. Merci d\'apporter le rapport. À bientôt'],
	['ru', 'Встреча в пятницу', 'Привет, Мария! Напоминаю, что встреча перенесена на пятницу в три часа дня. Захвати, пожалуйста, отчёт за квартал и план проекта.'],
	['zh', '周五的会议', '你好，提醒一下我们周五下午三点在办公室开会，讨论项目计划。请带上上个月的报告。谢谢！'],
	['ja', '金曜日の会議', 'こんにちは。金曜日の午後三時に事務所で会議があります。先月の報告書を持ってきてください。よろしくお願いします。'],
	['ar', 'اجتماع يوم الجمعة', 'مرحبا، أذكرك بأن الاجتماع سيكون يوم الجمعة الساعة الثالثة في المكتب لمناقشة خطة المشروع. يرجى إحضار التقرير.'],
	['ko', '금요일 회의', '안녕하세요. 금요일 오후 세 시에 사무실에서 프로젝트 계획을 논의하는 회의가 있습니다. 지난달 보고서를 가져와 주세요.'],
	['hi', 'शुक्रवार की बैठक', 'नमस्ते, याद दिला दूं कि शुक्रवार को तीन बजे कार्यालय में परियोजना योजना पर बैठक है। कृपया पिछले महीने की रिपोर्ट साथ लाएं।'],
	['th', 'ประชุมวันศุกร์', 'สวัสดีครับ ขอแจ้งว่าวันศุกร์นี้จะมีประชุมที่สำนักงานเวลาบ่ายสามโมงเพื่อหารือแผนงานโครงการ กรุณานำรายงานเดือนที่แล้วมาด้วย'],
];

/**
 * A ZIP file written with the "stored" method.
 * @param {Array<{name: string, content: Buffer|string, encrypted?: boolean}>} entries
 * @returns {Buffer}
 */
export function zip(entries) {
	const locals = [];
	const centrals = [];
	let offset = 0;
	for (const entry of entries) {
		const name = Buffer.from(entry.name);
		const data = Buffer.from(entry.content);
		const flags = entry.encrypted ? 1 : 0;
		const local = Buffer.alloc(30);
		local.writeUInt32LE(0x04_03_4B_50, 0);
		local.writeUInt16LE(20, 4);
		local.writeUInt16LE(flags, 6);
		local.writeUInt32LE(data.length, 18);
		local.writeUInt32LE(data.length, 22);
		local.writeUInt16LE(name.length, 26);
		locals.push(local, name, data);
		const central = Buffer.alloc(46);
		central.writeUInt32LE(0x02_01_4B_50, 0);
		central.writeUInt16LE(20, 4);
		central.writeUInt16LE(20, 6);
		central.writeUInt16LE(flags, 8);
		central.writeUInt32LE(data.length, 20);
		central.writeUInt32LE(data.length, 24);
		central.writeUInt16LE(name.length, 28);
		central.writeUInt32LE(offset, 42);
		centrals.push(central, name);
		offset += 30 + name.length + data.length;
	}

	const directory = Buffer.concat(centrals);
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06_05_4B_50, 0);
	end.writeUInt16LE(entries.length, 8);
	end.writeUInt16LE(entries.length, 10);
	end.writeUInt32LE(directory.length, 12);
	end.writeUInt32LE(offset, 16);
	return Buffer.concat([...locals, directory, end]);
}

/**
 * The EICAR antivirus test file, assembled at run time so the repository
 * itself never contains it.
 * @returns {Buffer}
 */
export function eicar() {
	return Buffer.from([String.raw`X5O!P%@AP[4\PZX54(P^)7CC)7}$`, 'EICAR-STANDARD-ANTIVIRUS', '-TEST-FILE!$H+H*'].join(''));
}

function encodeName(name) {
	return Buffer.concat([...name.split('.').filter(Boolean).map(label => Buffer.concat([Buffer.from([Buffer.byteLength(label)]), Buffer.from(label)])), Buffer.from([0])]);
}

/**
 * A DNS server on UDP for tests. `records` maps "name TYPE" (lowercase name,
 * type A or TXT) to answers: IPv4 strings for A, strings for TXT. Names
 * missing from the map get NXDOMAIN; a "name TYPE" mapped to "timeout" gets
 * no answer at all.
 * @param {Record<string, string[]|string>} records
 * @returns {Promise<{address: string, port: number, server: string, queries: string[], close: () => Promise<void>}>}
 */
export async function dnsServer(records = {}) {
	const socket = dgram.createSocket('udp4');
	const queries = [];
	socket.on('message', (query, remote) => {
		const id = query.readUInt16BE(0);
		let offset = 12;
		const labels = [];
		while (query[offset] !== 0) {
			const length = query[offset];
			labels.push(query.subarray(offset + 1, offset + 1 + length).toString());
			offset += length + 1;
		}

		const question = query.subarray(12, offset + 5);
		const type = query.readUInt16BE(offset + 1);
		const name = labels.join('.').toLowerCase();
		const typeName = {1: 'A', 16: 'TXT'}[type] || String(type);
		queries.push(`${name} ${typeName}`);
		const answers = records[`${name} ${typeName}`];
		if (answers === 'timeout') {
			return;
		}

		const header = Buffer.alloc(12);
		header.writeUInt16BE(id, 0);
		header.writeUInt16BE(answers ? 0x81_80 : 0x81_83, 2);
		header.writeUInt16BE(1, 4);
		header.writeUInt16BE(answers ? answers.length : 0, 6);
		const records_ = (answers || []).map(answer => {
			let data;
			if (typeName === 'A') {
				data = Buffer.from(answer.split('.').map(Number));
			} else {
				// TXT records are strings of at most 255 bytes each.
				const text = Buffer.from(answer);
				const strings = [];
				for (let i = 0; i < text.length; i += 255) {
					const piece = text.subarray(i, i + 255);
					strings.push(Buffer.from([piece.length]), piece);
				}

				data = Buffer.concat(strings);
			}

			const fixed = Buffer.alloc(10);
			fixed.writeUInt16BE(type, 0);
			fixed.writeUInt16BE(1, 2);
			fixed.writeUInt32BE(60, 4);
			fixed.writeUInt16BE(data.length, 8);
			return Buffer.concat([encodeName(name), fixed, data]);
		});
		socket.send(Buffer.concat([header, question, ...records_]), remote.port, remote.address);
	});
	socket.bind(0, '127.0.0.1');
	await once(socket, 'listening');
	const {port} = socket.address();
	return {
		address: '127.0.0.1',
		port,
		server: `127.0.0.1:${port}`,
		queries,
		close: () => new Promise(resolve => {
			socket.close(resolve);
		}),
	};
}

/**
 * An HTTP server for tests: `handler(request, body)` returns {status, body,
 * headers} or a value sent as JSON with status 200.
 * @param {(request: http.IncomingMessage, body: any) => any} handler
 * @returns {Promise<{url: string, port: number, requests: Array, close: () => Promise<void>}>}
 */
export async function httpServer(handler) {
	const requests = [];
	const server = http.createServer(async (request, response) => {
		const chunks = [];
		for await (const chunk of request) {
			chunks.push(chunk);
		}

		const raw = Buffer.concat(chunks).toString('utf8');
		let body = raw;
		try {
			body = raw ? JSON.parse(raw) : null;
		} catch {}

		requests.push({
			method: request.method, url: request.url, headers: request.headers, body,
		});
		const result = await handler(request, body);
		if (result === 'hang') {
			return;
		}

		if (result && typeof result === 'object' && 'status' in result) {
			response.writeHead(result.status, result.headers || {'content-type': 'application/json'});
			response.end(typeof result.body === 'string' ? result.body : JSON.stringify(result.body));
			return;
		}

		response.writeHead(200, {'content-type': 'application/json'});
		response.end(JSON.stringify(result));
	});
	server.listen(0, '127.0.0.1');
	await once(server, 'listening');
	const {port} = server.address();
	return {
		url: `http://127.0.0.1:${port}`,
		port,
		requests,
		close: () => new Promise(resolve => {
			server.closeAllConnections?.();
			server.close(() => resolve());
		}),
	};
}

/**
 * A stand-in for clamd that speaks the INSTREAM protocol: data containing
 * "EICAR" is reported infected; `reply` overrides the answer.
 * @param {object} [options]
 * @param {string} [options.path] - listen on a Unix socket instead of TCP
 * @param {string} [options.reply]
 * @returns {Promise<{port?: number, path?: string, close: () => Promise<void>}>}
 */
export async function fakeClamd(options = {}) {
	const server = net.createServer(socket => {
		let buffer = Buffer.alloc(0);
		socket.on('data', chunk => {
			buffer = Buffer.concat([buffer, chunk]);
			const text = buffer.toString('latin1');
			if (text.startsWith('zPING\0')) {
				socket.end('PONG\0');
				return;
			}

			if (text.startsWith('zINSTREAM\0')) {
				let offset = 10;
				const parts = [];
				while (offset + 4 <= buffer.length) {
					const size = buffer.readUInt32BE(offset);
					if (size === 0) {
						const data = Buffer.concat(parts).toString('latin1');
						socket.end(options.reply ?? (data.includes('EICAR') ? 'stream: Eicar-Test-Signature FOUND\0' : 'stream: OK\0'));
						return;
					}

					if (offset + 4 + size > buffer.length) {
						return;
					}

					parts.push(buffer.subarray(offset + 4, offset + 4 + size));
					offset += 4 + size;
				}
			}
		});
	});
	if (options.path) {
		server.listen(options.path);
	} else {
		server.listen(0, '127.0.0.1');
	}

	await once(server, 'listening');
	return {
		port: options.path ? undefined : server.address().port,
		path: options.path,
		close: () => new Promise(resolve => {
			server.close(() => resolve());
		}),
	};
}

/**
 * A milter client that talks to a milter server the way Postfix does.
 * @param {number|string} port - TCP port or Unix socket path
 * @returns {Promise<object>}
 */
export async function milterClient(port) {
	const socket = typeof port === 'string' ? net.createConnection(port) : net.createConnection(port, '127.0.0.1');
	await once(socket, 'connect');
	let buffer = Buffer.alloc(0);
	const waiting = [];
	const received = [];
	socket.on('data', chunk => {
		buffer = Buffer.concat([buffer, chunk]);
		while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32BE(0)) {
			const length = buffer.readUInt32BE(0);
			const packet = {command: String.fromCodePoint(buffer[4]), data: buffer.subarray(5, 4 + length)};
			buffer = buffer.subarray(4 + length);
			received.push(packet);
			const next = waiting.shift();
			if (next) {
				next(received.shift());
			}
		}
	});

	const send = (command, data = Buffer.alloc(0)) => {
		const payload = Buffer.isBuffer(data) ? data : Buffer.from(data, 'latin1');
		const header = Buffer.alloc(5);
		header.writeUInt32BE(payload.length + 1);
		header.write(command, 4, 'latin1');
		socket.write(Buffer.concat([header, payload]));
	};

	const read = () => (received.length > 0
		? Promise.resolve(received.shift())
		: new Promise(resolve => {
			waiting.push(resolve);
		}));

	// Read packets until a final answer (accept, continue, reject, ...).
	const readUntilFinal = async () => {
		const packets = [];
		for (;;) {
			const packet = await read();
			packets.push(packet);
			if (!['h', 'm', 'i', 'q'].includes(packet.command)) {
				return packets;
			}
		}
	};

	return {
		socket, send, read, readUntilFinal,
		close() {
			socket.destroy();
		},
	};
}

/**
 * A NUL-terminated string buffer.
 * @param {...string} values
 * @returns {Buffer}
 */
export function cstr(...values) {
	return Buffer.from(values.map(value => `${value}\0`).join(''), 'latin1');
}

/**
 * Collect a writable stream's output, for CLI tests.
 * @returns {{write: (chunk: any) => boolean, text: () => string, buffer: () => Buffer}}
 */
export function sink() {
	const chunks = [];
	return {
		write(chunk) {
			chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
			return true;
		},
		text: () => Buffer.concat(chunks).toString('utf8'),
		buffer: () => Buffer.concat(chunks),
	};
}
